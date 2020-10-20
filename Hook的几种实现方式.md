## Hook简介
微软的MSDN中，对Hook的解释为：
> A hook is a point in the system message-handling mechanism where an application can install a subroutine to monitor the message traffic in the system and process certain types of messages before they reach the target window procedure.

> 微软只是简单的将Hook解释为一种过滤（或叫挂钩）消息的技术。
我们这里讲解的Hook，简单解释为：挂钩，挂钩一切事物。包含微软的解释。
挂钩的事物通常指的是函数。

## Hook 目的
过滤一些关键函数调用，在函数执行前，先执行自己的挂钩函数。达到监控函数调用，改变函数功能的目的。

## Hook 分类
### 系统消息Hook（微软官方提供的方法 Ring3）
- SetWindowsHookEx
- UnhookWindowsHookEx
- CallNextHookEx

### API Hook（非官方方法 Ring0/Ring3）
- 使用汇编代码编替换函数开始的汇编代码，使其跳转到我们的Hook函数中，非官方叫法：Inline hook
- 使用Hook函数地址替换调用函数地址（IAT hook/SSDT hook … …）

## 系统消息 Hook
类型：
- WH_GETMESSAGE    当系统调用GetMessage和PeekMessage时，调用Hook函数
- WH_KEYBOARD_LL     当系统发送键盘消息到线程输入队列前，先调用Hook函数
- WH_MOUSE_LL         当系统发送鼠标消息到线程输入队列前，先调用Hook函数
- … …


```c++
HHOOK WINAPI SetWindowsHookEx(
    int idHook,            // 类型
    HOOKPROC lpfn,        // 回调函数
    HINSTANCE hMod,    // 回调函数所在的DLL的Handle（可能在调用进程也可能不在）
    DWORD dwThreadId    // 针对哪儿个线程做Hook
);
```


> 此Hook可以以线程为单位进行筛选。每个GUI线程有一个消息队列，用来接受消息，既然是消息Hook，那就应该是针对某个线程的接收到的消息做Hook。

> 例如：实现的防键盘勾取，可以使用这种技术。安装了一个WH_KEYBOARD_LL钩子，在键盘按下，发往任意的线程消息队列前，会先调用我们的键盘钩子，钩子里面判断是不是我们的输入框的窗口消息，如果不是，忽略。如果是，做加密处理并保存，改变发送的字符（如改为"* "），发送至窗口过程中。如果第三方调用GetWindowText，由于文本框中的都是"*"，所以无法获取出真实字符。

> 但这种钩子谁也可以安装，Windows将所有程序安装的钩子组成了一个钩子链。如果第三方也安装了一个钩子，还是在我们安装完之后安装的，那么它将会截获到真实字符。所以，所以可以进一步加强处理，增加一个定时器，不停的安装卸载多个钩子。这样，即便第三方也在不停的安装钩子，想截取到完整的PIN，可能性变的很小。但如果这个恶意程序驻留在用户系统中很多天，通过每次的统计，可能能得到完整的PIN。

## API Hook - Inline Hook
**工作方式如下：**
1. 调用GetProcAddress对内存中要拦截的函数进行定位（如Kernel32.dll的ExitProcess），得到它的内存地址。
2. 把这个函数起始的几个字节保存到我们的内存中。
3. 用CPU的JUMP汇编指令来覆盖这个函数的起始几个字节，这条JUMP指令用来跳转到我们的替换函数的内存地址。我们替换的函数需要和原函数具有完全相同的声明：参数相同，返回值相同，调用约定相同。
4. 当线程调用被拦截的函数时，跳转指令实际上会跳转到我们的替代函数，这是，我们可以执行相应的功能代码。
5. 为了撤销对函数的拦截，我们必须把步骤2中保存的字节恢复回被拦截的函数中。
6. 我们调用被拦截函数（现在已经不再拦截），让函数执行它的正常处理。
7. 当原来函数返回时，我们再次执行第2，第3步，这样我们的替代函数将来还会被调用到。

**注意事项：**
- JUMP指令对CPU（AMD，Intel）有依赖，在X86，X64下，更会有不同的表现。
- 由于替换汇编代码的过程，不是原子操作的，很有可能在其它线程运行到此函数的入口的时候进行了替换，导致指令异常，程序崩溃。

解决多线程的办法（分析来自Mhook库）：  
- 替换的过程首先上互斥锁（如EnterCriticalSection），这把锁只对替换的过程互斥，并无法避免其它线程正在调用要替换的函数。
- 第二步做的就是挂起除本线程外的其它线程，并同时确保其它线程的执行点（IP）不在我们将以替换的区域中。（参加Mhook的： SuspendOtherThreads函数）

下面是摘自Mhook的一段代码，它会挂起除了Hook线程以外的其它线程，并且确保其他线程的执行点（IP）不在要Hook的区域内。
```c++
//=========================================================================
// Internal function:
//
// Suspend all threads in this process while trying to make sure that their
// instruction pointer is not in the given range.
//=========================================================================
static BOOL SuspendOtherThreads(PBYTE pbCode, DWORD cbBytes) {
    BOOL bRet = FALSE;
    // make sure we're the most important thread in the process
    INT nOriginalPriority = GetThreadPriority(GetCurrentThread());
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    // get a view of the threads in the system
    HANDLE hSnap = fnCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
    if (GOOD_HANDLE(hSnap)) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        // count threads in this process (except for ourselves)
        DWORD nThreadsInProcess = 0;
        if (fnThread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId()) {
                    if (te.th32ThreadID != GetCurrentThreadId()) {
                        nThreadsInProcess++;
                    }
                }
                te.dwSize = sizeof(te);
            } while(fnThread32Next(hSnap, &te));
        }
        ODPRINTF((L"mhooks: SuspendOtherThreads: counted %d other threads", nThreadsInProcess));
        if (nThreadsInProcess) {
            // alloc buffer for the handles we really suspended
            g_hThreadHandles = (HANDLE*)malloc(nThreadsInProcess*sizeof(HANDLE));
            if (g_hThreadHandles) {
                ZeroMemory(g_hThreadHandles, nThreadsInProcess*sizeof(HANDLE));
                DWORD nCurrentThread = 0;
                BOOL bFailed = FALSE;
                te.dwSize = sizeof(te);
                // Go through every thread
                if (fnThread32First(hSnap, &te)) {
                    do {
                        if (te.th32OwnerProcessID == GetCurrentProcessId()) {
                            if (te.th32ThreadID != GetCurrentThreadId()) {
                                // attempt to suspend it
                                g_hThreadHandles[nCurrentThread] = SuspendOneThread(te.th32ThreadID, pbCode, cbBytes);
                                if (GOOD_HANDLE(g_hThreadHandles[nCurrentThread])) {
                                    ODPRINTF((L"mhooks: SuspendOtherThreads: successfully suspended %d", te.th32ThreadID));
                                    nCurrentThread++;
                                } else {
                                    ODPRINTF((L"mhooks: SuspendOtherThreads: error while suspending thread %d: %d", te.th32ThreadID, gle()));
                                    // TODO: this might not be the wisest choice
                                    // but we can choose to ignore failures on
                                    // thread suspension. It's pretty unlikely that
                                    // we'll fail - and even if we do, the chances
                                    // of a thread's IP being in the wrong place
                                    // is pretty small.
                                    // bFailed = TRUE;
                                }
                            }
                        }
                        te.dwSize = sizeof(te);
                    } while(fnThread32Next(hSnap, &te) && !bFailed);
                }
                g_nThreadHandles = nCurrentThread;
                bRet = !bFailed;
            }
        }
        CloseHandle(hSnap);
        //TODO: we might want to have another pass to make sure all threads
        // in the current process (including those that might have been
        // created since we took the original snapshot) have been
        // suspended.
    } else {
        ODPRINTF((L"mhooks: SuspendOtherThreads: can't CreateToolhelp32Snapshot: %d", gle()));
    }
    SetThreadPriority(GetCurrentThread(), nOriginalPriority);
    if (!bRet) {
        ODPRINTF((L"mhooks: SuspendOtherThreads: Had a problem (or not running multithreaded), resuming all threads."));
        ResumeOtherThreads();
    }
    return bRet;
}

//=========================================================================
// Internal function:
//
// Suspend a given thread and try to make sure that its instruction
// pointer is not in the given range.
//=========================================================================
static HANDLE SuspendOneThread(DWORD dwThreadId, PBYTE pbCode, DWORD cbBytes) {
    // open the thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
    if (GOOD_HANDLE(hThread)) {
        // attempt suspension
        DWORD dwSuspendCount = SuspendThread(hThread);
        if (dwSuspendCount != -1) {
            // see where the IP is
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_CONTROL;
            int nTries = 0;
            while (GetThreadContext(hThread, &ctx)) {
#ifdef _M_IX86
                PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
                PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
                if (pIp >= pbCode && pIp < (pbCode + cbBytes)) {
                    if (nTries < 3) {
                        // oops - we should try to get the instruction pointer out of here.
                        ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE", dwThreadId, pIp));
                        ResumeThread(hThread);
                        Sleep(100);
                        SuspendThread(hThread);
                        nTries++;
                    } else {
                        // we gave it all we could. (this will probably never
                        // happen - unless the thread has already been suspended
                        // to begin with)
                        ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", dwThreadId, pIp));
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                        hThread = NULL;
                        break;
                    }
                } else {
                    // success, the IP is not conflicting
                    ODPRINTF((L"mhooks: SuspendOneThread: Successfully suspended thread %d - IP is at %p", dwThreadId, pIp));
                    break;
                }
            }
        } else {
            // couldn't suspend
            CloseHandle(hThread);
            hThread = NULL;
        }
    }
    return hThread;
}
```

Inline Hook技术复杂，对CPU有依赖，需要编写汇编代码，在抢占式，多线程系统中，很容易出现问题。但目前有比较稳定的Hook库可以使用，也是不错的选择之一。

### API Hook – SEH Hook
这里简单介绍一下，SEH是windows的结构化异常处理，通过安装一个结构化异常处理函数，当在保护的执行区域内发生异常时，会跳转到此异常函数。SEH Hook属于比较另类的Hook方式，它在函数开头插入异常代码，如（INT 3），当执行到此函数时，由于触发异常，则会跳到我们的处理函数中。

### API Hook - IAT Hook

**IAT - Import Address Table （输入地址表）**  
> 简单的说，此表格由一连串的函数地址组成，这些函数地址从其它模块中导入的函数地址。当Windows加载器加载一个PE可执行文件时，会将真正需要的函数的虚拟地址填入此表格。

**输入函数是如何被调用的**  
> 通常，我们编写一个程序（调用者），调用一个输入函数时，此函数并不在当前程序中。我们只需要包含相应的头文件，然后链接正确的lib库（静态lib 和 动态DLL对应的lib），这些函数的实际代码存在于外部的一个DLL中。调用者只保留函数的相关信息（函数名，DLL文件名等）。由于一个PE文件没有被加载到内存中，编译完成的PE文件是无法确定输入函数的具体地址的。  

**下面通过一个例子来说明输入函数的地址是如何确定的**  
现在，我调用一个Windows API函数：Sleep，原型如下：
```c++
extern "C" __declspec(dllimport) void __stdcall Sleep(
    unsigned long dwMilliseconds
);
```

代码中调用如下：
```c++
Sleep(200);
```

VC编译器会将此函数汇编如下：
```asm
push     0C8h
call dword ptr [00407000]
```


由于在编译阶段，编译器是无法确定Sleep在真正运行时候的地址的。所以，编译器在PE文件中分配一块导入地址表，call 的只是导入地址的地址，而不是真正的地址。此示例中， 00407000是地址，它指向导入地址表的某个区域，指向的内容在PE被Windows加载器加载的时候，根据DLL实际加载的地址，找到真正的Sleep地址，将其替换为Sleep的真实地址。此方法类似于C++的多态。(父类的指针在运行时可以指向不同类型的子类）。这样，call dword ptr [00407000]，从00407000取出来的地址就是Sleep的地址。如下图所示。



IAT Hook就是去替换取出来的这个Sleep地址，将00407000地址指向的内存替换为我们的MySleep。当再次执行到call dword ptr [00407000]，此00407000指向的内存保存的已经是MySleep地址了。

IAT Hook的优点在于不依赖CPU，容易实现。很难出现程序崩溃的问题。



如何找到IAT并定位正确的地址？

需要掌握PE文件的结构。（可以参考看雪论坛出版的加密与解密（第三版））

下面的代码片段，引自《Windows核心编程（第5版）》 示例代码 22-LastMsgBoxInfo ：



void CAPIHook::ReplaceIATEntryInOneMod(PCSTR pszCalleeModName,
PROC pfnCurrent, PROC pfnNew, HMODULE hmodCaller) {

// Get the address of the module's import section
ULONG ulSize;

// An exception was triggered by Explorer (when browsing the content of
// a folder) into imagehlp.dll. It looks like one module was unloaded...
// Maybe some threading problem: the list of modules from Toolhelp might
// not be accurate if FreeLibrary is called during the enumeration.
PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
__try {
pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToData(
hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
}
__except (InvalidReadExceptionFilter(GetExceptionInformation())) {
// Nothing to do in here, thread continues to run normally
// with NULL for pImportDesc
}

if (pImportDesc == NULL)
return; // This module has no import section or is no longer loaded


// Find the import descriptor containing references to callee's functions
for (; pImportDesc->Name; pImportDesc++) {
PSTR pszModName = (PSTR) ((PBYTE) hmodCaller + pImportDesc->Name);
if (lstrcmpiA(pszModName, pszCalleeModName) == 0) {

// Get caller's import address table (IAT) for the callee's functions
PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
((PBYTE) hmodCaller + pImportDesc->FirstThunk);

// Replace current function address with new function address
for (; pThunk->u1.Function; pThunk++) {

// Get the address of the function address
PROC* ppfn = (PROC*) &pThunk->u1.Function;

// Is this the function we're looking for?
BOOL bFound = (*ppfn == pfnCurrent);
if (bFound) {
if (!WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError())) {
DWORD dwOldProtect;
if (VirtualProtect(ppfn, sizeof(pfnNew), PAGE_WRITECOPY,
&dwOldProtect)) {

WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
sizeof(pfnNew), NULL);
VirtualProtect(ppfn, sizeof(pfnNew), dwOldProtect,
&dwOldProtect);
}
}
return; // We did it, get out
}
}
} // Each import section is parsed until the right entry is found and patched
}
}

API Hook - SSDT Hook (Ring0)
SSDT （System Service Dispatch Table) 系统服务调度表

此表保存了系统中所有的系统服务函数地址，通过改变此表中的地址，达到Hook某个系统函数的目的

为何替换SSDT表中的地址，首先需要了解，Windows内核是如何为应用程序服务的？

为了保证每个进程的安全， Windows为不同的进程分配了独立的进程空间，即虚拟内存空间。一个进程的虚拟地址是无法指到另一个进程中的数据的。对应32位x86系统，每个进程的空间是4G，0x00000000-0xFFFFFFFF。为了高效的调用系统服务，Windows把操作系统的代码和数据映射到所有进程的空间中，因此4G划分为低2G的用户层和高2G的内核层空间。如图所示：



Windows定义了两种访问模式（access mode）

用户模式（user mode）    （ring3）
内核模式（kernel mode）（ring0）
    应用程序运行在用户模式下，操作系统运行在内核模式下。内核模式对应CPU的高权限级别，内核模式下可以访问系统的所有资源，拥有执行所有指令的权限，用户模式对应CPU较低的权限，只可以访问系统允许的其访问的内存空间和资源，并且没有权限运行一些特殊指令。

    用户模式下的代码不可以直接访问内核模式下的代码和数据，不能直接通过call指令调用内核模式下的任何函数。如果尝试，系统会产生保护性错误，程序直接终止。

    间接访问：用户程序通过调用系统服务来间接访问系统空间的数据或间接的来调用系统空间中的代码。

下面介绍用户程序调用API：ReadFile，如何到达内核层：



对应的汇编代码如下：





eax中保存的就是SSDT的索引。

在KiSystemServcie中，通过eax，索引SSDT中保存的地址，并调用之。

所以，如果我们知道SSDT中的每个地址对应的服务函数，并且知道此服务函数对应到用户层的API。那么我们可以编写一个驱动，加载到内核空间中，将驱动中的我们自己的函数地址替换到SSDT中，应用层调用API后，最后会拐到我们自己的函数中，达到Hook的目的。

系统有两张SSDT表，一个是导出的KeServiceDescriptorTable(ntoskrnl.exe)，一个是未导出的KeServiceDescriptorTableShadow(ntoskrnl.exe,win32k.sys)

由于内核已经导出KeServiceDescriptorTable全局变量，所以编写程序的时候，不需要定位KeServiceDescriptorTable。KeServiceDescriptorTableShadow未导出，所以需要使用一些非公开的方法来定位此地址，通常都是采用硬性编码的，没有系统适应性。

这两张表见图：



在我在做的反截屏驱动中，就是查找到 KeServiceDescriptorTableShadow地址，替换NtGdiBitBlt（对应的Win32 API为 BitBlt）等内核函数地址，进行功能过滤。

SSDT的缺点在于在64位的系统下，基本无法工作，除非你能跨过微软的安全防护。目前来看，还没有人破解win8.1.

Hook其他进程
下面的例子是否有问题：

示例1：A进程中有个MySleep函数，A进程通过IAT Hook的方式，将A进程中的IAT中对应的Sleep地址进行了替换，替换为MySleep函数地址， Hook是否能够成功？
示例2：A进程中有个MySleep函数，A进程通过IAT Hook的方式，将B进程中的IAT中对应的Sleep地址进行了替换，替换为MySleep函数地址，Hook是否能够成功？
我们知道，Windows下各个进程的空间是相互隔离的。A进程虽然能够替换B进程中的IAT地址（通过VirtualProtect，WriteProcessMemory可以实现），但是替换的MySleep的地址存在于A进程中，并不在B进程中，B进程直接调用，基本的可能就是崩溃了，如果这个地址正好是B进程的一个有效函数地址，还调用成功了，你会更加摸不着头脑。



自己Hook自己通常来说，没有太大意义，那么如何Hook其它进程？

如果使用的是SSDT hook，由于是在内核层，对所有的进程都是有效的。
如果是在应用层，如何Hook其它进程？我们可以将我们的函数放置到一个DLL中，将此DLL注入到其他进程中，这样其他进程调用DLL中的函数，将不会访问失败。


Windows提供了一种DLL注入的技术，注入的方式有：

使用注册表来注入
使用window 系统消息挂钩来注入（参见 Windows核心编程 22-DIPS示例）
使用远程线程来注入（参见 Windows核心编程 22-InjLib示例）…
…
这几种注入技术都在《 Windows核心编程 》详细讲解到。

使用注册表来注入
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\ 中：

有一个键：AppInit_DLLs，可以包含一组DLL（逗号或空格分隔），将我们的DLL路径写入此键值中。

创建一个名为LoadAppInit_DLLs，将其值设置为1.

当user32.dll被映射到一个新的进程时，会收到DLL_PROCESS_ATTACH通知。当user32.dll对它进行处理时，会取得上述注册表键值，并调用LoadLibrary载入这个键值存储的所有DLL。



缺点：

基于CUI的应用程序没有用到user32.dll，因此无法加载DLL。

我可能只想注入某些应用中，映射的越多，崩溃的可能性越大。

使用window 系统消息挂钩来注入
为了能让系统消息挂钩正常运行，Microsoft被迫设计出一种机制，让我们可以将DLL注入到另一进程空间中（想象一下：调用SetWindowsHookEx安装一个WH_GETMESSAGE钩子，如果让其他进程运行SetWindowsHookEx设置的函数？）

SetWindowsHookEx（WH_GETMESSAGE，GetMsgProc，hInstDll，0）；

GetMsgProc在调用此函数的进程空间中，假设为A进程。第三个参数为hInstDll，为当前进程空间中的一个DLL的句柄，此DLL包含了GetMsgProc函数，最后一个参数表示要给哪儿个线程安装，0表示给系统中所有的GUI线程安装挂钩。

接下来会发生什么：

B进程的一个线程准备向一个窗口发送一条消息。
系统检测到已经安装了一个WH_GETMESSAGE钩子。
系统检测GetMsgProc所在的DLL是否已经被映射到进程B地址空间中。
如果尚未映射，系统会强制调用LoadLibrary强制将DLL映射到B进程地址空间中，DLL引用计数加一。
DLL映射到B中的地址可能和A相同，也可能不同。如果不同，需要调整GetMsgProc的地址。
GetMsgProc = hInstDll B + （GetMsgProcA – hInstDll A）
系统在进程B中地址该DLL的引用计数。
在B空间调用GetMsgProc，在此函数里，可以做API Hook处理，还可以创建一些消息机制，通过A进程进行功能控制。
使用远程线程来注入
在另一个进程中创建远程线程：

HANDLE WINAPI CreateRemoteThread(
_In_ HANDLE hProcess,
_In_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
_In_ SIZE_T dwStackSize,
_In_ LPTHREAD_START_ROUTINE lpStartAddress,
_In_ LPVOID lpParameter,
_In_ DWORD dwCreationFlags,
_Out_ LPDWORD lpThreadId
);


只要使用这个远程线程调用LoadLibrary，来加载我们的DLL，就能达到DLL注入的目的。例如：

CreateRemoteThread（hProcessRemote，NULL， 0， LoadLibraryW，L"C:\\MyLib.dll", 0, NULL);

当远程线程在远程进程执行时，会立即调用LoadLibraryW，并传入DLL路径。



但并没有这么简单

CreateRemoteThread（hProcessRemote，NULL， 0， LoadLibraryW，L"C:\\MyLib.dll", 0, NULL);

但存在两个问题：

第一个问题是：
上面我们已经讲过LoadLibraryW是个导入函数，使用地址引用IAT的方式来调用，显然这个地址在不同的PE文件里是不同的。在其他进程中，这个地址是不一样的。

对CreateRemoteThread调用，假定本进程和远程进程中，Kernel32.dll被映射到地址空间是同一内存。（虽然是假定，到目前为止，都是同一地址，重启会变，但启动后不变）。

可以改变为：

PTHREAD_START_ROUNTINE pfnThreadRtn = (PTHREAD_START_ROUNTINE)GetProcAddress(GetModuleHandle(_T("Kernel32")), "LoadLibraryW");

CreateRemoteThread（hProcessRemote，NULL， 0， pfnThreadRtn，L"C:\\MyLib.dll", 0, NULL);

第二个问题：
L"C:\\MyLib.dll"字符串在调用进程中，目标进程并没有这个字符串，如果在目标程序执行，此地址则是执行一个未知地址，可能会崩溃。

解决这个问题的办法，需要把本地字符串放到远程进程去。调用VirtualAllocEx可以让一个进程在另一个进程中分配一块空间。WriteProcessMemory可以将字符串从本进程复制到远程进程中。

Hook 开发库
EasyHook（inline）
同时支持内核和用户层Hook，在使用中发现内核层有不少Bug，据说用户层很稳定。看其代码对多线程没有处理，可能会有问题。

Mhook（inline）
只支持用户层Hook，代码轻量，清晰。
