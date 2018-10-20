1.批处理
原理：在程序结束之前生成一个能删除自身的bat文件
#include<stdio.h>
#include<windows.h>
#include <shellapi.h>

//在完整路径中取得文件名
void *GetFilename(char *p)
{
   int x = strlen(p);
   char ch = '\\';
   char *q = strrchr(p,ch) + 1;
   return q;
}

int main()
{
    char strName[MAX_PATH];

    //获得自身的完整路径
    HMODULE hModule=GetModuleHandle(NULL);
    GetModuleFileName(hModule,strName,sizeof(strName));
    FILE *fp;
    fp=fopen("SelfDelete.bat","w+");
    fprintf(fp,"@echo off\r\n");
    fprintf(fp,":start\r\n\tif not exist %s goto done\r\n",GetFilename(strName));
    fprintf(fp,"\tdel /f /q %s\r\n",GetFilename(strName));
    fprintf(fp,"goto start\r\n");
    fprintf(fp,":done\r\n");
    fprintf(fp,"\tdel /f /q %0 \r\n");

    fclose(fp);
    //隐藏运行批处理文件，ShellExecute应该添加shellapi.h头文件，且这个头文件应该放在windows.h之后
    ShellExecute(NULL,"open","SelfDelete.bat",NULL,NULL,SW_HIDE);
    exit(1);
    return 0;
}
