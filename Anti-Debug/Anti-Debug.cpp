// Anti-Debug.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<Windows.h>
#include"xorstr.hpp"
#include"AntiDebug.h"

AntiDebug* ad = nullptr;
fnGetUserNameA Origin_GetUserNameA = NULL;
fnSleep Origin_Sleep = NULL;
void WINAPI khSleep(DWORD dwMilliseconds);
BOOL WINAPI hkOrigin_GetUserNameA(LPSTR  lpBuffer, LPDWORD lpnSize);
DWORD DrClearThread(LPVOID param);
//---------------------------------------------------------------------------------------------------------------------------------------
#pragma comment(linker, "/INCLUDE:__tls_used")
void NTAPI __stdcall TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    //初始化
    static bool init = false;
    if (!init)
    {
 
        ad = AntiDebug::GetInstance();
        ad->Init();
        ad->EatHook(xorstr_(L"Advapi32.dll"), xorstr_("GetUserNameA"), hkOrigin_GetUserNameA, (DWORD*)&Origin_GetUserNameA);
        ad->EatHook(xorstr_(L"Kernel32.dll"), xorstr_("Sleep"), khSleep, (DWORD*)&Origin_Sleep);
        //更新指针
        ad->winapi.lpGetUserNameA = (fnGetUserNameA)ad->_GetProcAddress(ad->_LoadLibrary(xorstr_(L"Advapi32.dll")), xorstr_("GetUserNameA"));
        ad->winapi.lpSleep = (fnSleep)ad->_GetProcAddress(ad->_LoadLibrary(xorstr_(L"Kernel32.dll")), xorstr_("Sleep"));
        if (ad->SehDetect() ||
            ad->VehDetect())
        {
            ad->_ExitProcess();
        }
        ad->DrClear();
        ad->CrashOD();
        init = true;
    }
}
#pragma data_seg(".CRT$XLX")
PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { TLS_CALLBACK, 0 };
#pragma data_seg()
//---------------------------------------------------------------------------------------------------------------------------------------
bool detect_Base = ad->BasicDebugDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_HideThread = ad->HideThread();
bool detect_Query = ad->QueryInfoDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_DObjAll = ad->DebugObejctDetect_All() ? (ad->_ExitProcess(), 0) : 0;
bool detect_DObjCreate = ad->DebugObejctDetect_Create() ? (ad->_ExitProcess(), 0) : 0;
bool detect_CloseHandle1 = ad->CloseInvaildHandleDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_CloseHandle2 = ad->CloseProtectHandleDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_CloseWindow = ad->CloseInvaildWindowDetect() ? (ad->_ExitProcess(), 0) : 0; 
bool detect_ClearNtGlobal = ad->NtGlobalClearDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_HeapInfo = ad->HeapSetInformationDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_HeapTail = ad->HeapTailDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_Time = ad->TimeDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_SystemBoot = ad->SystemBootDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_DFilter = ad->DebugFilterStateDetect() ? (ad->_ExitProcess(), 0) : 0;
bool detect_Seh = ad->SehDetect() ? (ad->_ExitProcess(), 0) : 0;
//---------------------------------------------------------------------------------------------------------------------------------------
BOOL running = false;
DWORD thread_DrClear = ad->winapi.lpCreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)DrClearThread,NULL,NULL,NULL);
//---------------------------------------------------------------------------------------------------------------------------------------
DWORD DrClearThread(LPVOID param)
{
    while (true)
    {
        running = true;
        ad->DrClear();
        if (ad->QueryInfoDetect())
            ad->_ExitProcess();
        ad->winapi.lpSleep(1000 * 10); //10秒清空一次
    }
    return NULL;
}
//---------------------------------------------------------------------------------------------------------------------------------------
void WINAPI khSleep(DWORD dwMilliseconds)
{
    ad->winapi.lpGetUserNameA(NULL,NULL);

    //检测线程
    static int count = 0;
    if (!running)
    {
        count++;
    }
    else
    {
        count = 0;
    }
    if (count > 10)
    {
        ad->winapi.lpCreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DrClearThread, NULL, NULL, NULL); //重新启动线程
        count = 0;
    }

    Origin_Sleep(dwMilliseconds);
}
BOOL WINAPI hkOrigin_GetUserNameA(LPSTR  lpBuffer, LPDWORD lpnSize)
{
    ////特征标记
    //_asm {
    //    jmp start
    //}
    ////61 6E 74 69 64 65 62 75 67
    //_asm _emit 0x61
    //_asm _emit 0x6E
    //_asm _emit 0x74
    //_asm _emit 0x69
    //_asm _emit 0x64
    //_asm _emit 0x65
    //_asm _emit 0x62
    //_asm _emit 0x75
    //_asm _emit 0x67
    //start:

    if(lpBuffer && lpnSize)
        Origin_GetUserNameA(lpBuffer, lpnSize);

    if (ad->QueryInfoDetect() ||
        ad->DebugObejctDetect_All() ||
        ad->DebugObejctDetect_Create() ||
        ad->CloseInvaildHandleDetect() ||
        ad->CloseInvaildWindowDetect() ||
        ad->CloseProtectHandleDetect() ||
        ad->NtGlobalClearDetect() ||
        ad->HeapSetInformationDetect() ||
        ad->HeapTailDetect() ||
        ad->TimeDetect() ||
        ad->SystemBootDetect() ||
        ad->DebugFilterStateDetect() ||
        ad->SehDetect() ||
        ad->VehDetect() ||
        !ad->HideThread())
    {
        ad->_ExitProcess();
    }
    return true;
}
int main()
{
    printf("请将调试器附加,并成功在GetTickCount上断下!\n");
    DWORD curtTick = GetTickCount();
    while (true)
    {
        printf("\r已经运行 %d 秒.", (GetTickCount() - curtTick)/1000);
        Sleep(1000);
    }
        
    system("pause");
}

