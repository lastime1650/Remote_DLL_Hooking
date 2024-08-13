// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>

#include "START_INIT.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HANDLE Thread_HANDLE = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)START_INIT, NULL, 0, NULL);
        
        if (Thread_HANDLE == 0) return TRUE;
        else {
            CloseHandle(Thread_HANDLE);
        }
        
   }
    return TRUE;
}
