#include "pch.h"
#include "Get_API_Addresses.h"

#include "USER32_HOOK_Functions.h"
#include "GRAPHIC_HOOK_Functions.h"
#include "SYSTEM_HOOK_Functions.h"
#ifdef __cplusplus
extern "C" {
#endif
    // 관리자 실행인지 확인.
    HRESULT CheckIfIsUserAdmin(PBOOLEAN pIsAdmin);


	UCHAR DLL_NAMES[][128] = {
		"user32.dll",
		"kernel32.dll",
        "msvcrt.dll",
        "ucrt.dll"
        "ntdll.dll",


		"gdi32.dll",
		"d3d1.dll",
		"dxgi.dll",
		"d3d11.dll"
        
	
	};


    // 정적 할당된 인덱스 순서대로 연결리스트에 등록된다.
	UCHAR API_NAMES[][128] = {
		"MessageBoxA",
		"BitBlt",


        // 원격 프로세스

        "CreateRemoteThread",
        "CreateProcessA",
        "CreateProcessW",
        "OpenProcess",
        "TerminateProcess",
        "ResumeThread",
        "SuspendThread",

        // 메모리 조작

        "ReadProcessMemory",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "VirtualFreeEx",

        // 핸들 조작

        "DuplicateHandle",
        "GetThreadContext",
        "SetThreadContext",

        // 프로세스 및 스레드 보안

        "AdjustTokenPrivileges",
        "OpenProcessToken",

        // 데이터 복사 및 파일 조작

        "NtReadFile",
        "NtWriteFile",
        "NtQueryInformationFile",
        "CreateFileA",
        "CreateFileW",
        "ReadFile",
        "WriteFile",

        // 기타

        "SetWindowsHookEx",
        "SendMessage",
        "PostMessage",

        // Basic API

        "malloc",
        "calloc",
        "realloc",
        "free",
        "fopen",
        "fclose",
        "fread",
        "fwrite",
        "exit",
        "abort"
	};

	// 아래 값은, API_NAMES 와 일치한 후크함수로 저장되어야함
	PVOID HOOK_API_ADDRESS[] = {
		HookedMessageBoxA,
		HookedBitBlt,

        // 원격 프로세스


        HookedCreateRemoteThread,
        HookedCreateProcessA,
        HookedCreateProcessW,
        HookedOpenProcess,
        HookedTerminateProcess,
        HookedResumeThread,
        HookedSuspendThread,

        // 메모리 조작

        HookedReadProcessMemory,
        HookedWriteProcessMemory,
        HookedVirtualAllocEx,
        HookedVirtualFreeEx,
        
        // 핸들 조작

        HookedDuplicateHandle,
        HookedGetThreadContext,
        HookedSetThreadContext,

        // 프로세스 및 스레드 보안

        HookedAdjustTokenPrivileges,
        HookedOpenProcessToken,

        // 데이터 복사 및 파일 조작

        HookedNtReadFile,
        HookedNtWriteFile,
        HookedNtQueryInformationFile,
        HookedCreateFileA,
        HookedCreateFileW,
        HookedReadFile,
        HookedWriteFile,

        // 기타

        HookedSetWindowsHookEx,
        HookedSendMessage,
        HookedPostMessage,
        
        // Basic API

        Hookedmalloc,
        Hookedcalloc,
        Hookedrealloc,
        Hookedfree,
        Hookedfopen,
        Hookedfclose,
        Hookedfread,
        Hookedfwrite,
        Hookedexit,
        Hookedabort
	};

	__declspec(dllexport) PAPI_LIST LOAD_API_ADDRESSES() {
		
        BOOLEAN is_admin_running = FALSE;
        CheckIfIsUserAdmin(&is_admin_running);

        
		PAPI_LIST Start_NODE = NULL;
		PAPI_LIST Current_NODE = NULL;

		// API_NAMES API[0] 인덱스부터 차례대로 주소를 찾도록 한다.  
		for (ULONG32 i = 0; i < (sizeof(API_NAMES) / sizeof(API_NAMES[0])); i++) {

			printf("API_NAMES[%d] = %s  / %d \n", i, API_NAMES[i], (sizeof(API_NAMES) / sizeof(API_NAMES[0])));

			
			//printf("DLL_MODULE->%lu\n", DLL_MODULE);

			// DLL 에 존재하는 API에만 PAPI_LIST 노드 축적 
			for (ULONG32 x = 0; x < (sizeof(DLL_NAMES) / sizeof(DLL_NAMES[0])); x++) {

				HMODULE DLL_MODULE = GetModuleHandleA((LPCSTR)DLL_NAMES[x]);
				if (DLL_MODULE == NULL) {
					continue;
				}


				FARPROC procAddress = GetProcAddress(DLL_MODULE, (LPCSTR)API_NAMES[i]);
				if (procAddress == NULL) {
					//printf("실패 procAddress->%lu\n", procAddress);
					continue;
				}
				else {
					
                    /*
                        커널에서도 참조할 후크 정보 연결리스트
                    */
					if (Start_NODE == NULL) {
						Start_NODE = CREATE_API_LIST_NODE((PUCHAR)&API_NAMES[i], sizeof(API_NAMES[i]), (PUCHAR)&DLL_NAMES[x], sizeof(DLL_NAMES[x]),  (PUCHAR)procAddress, is_admin_running);
						if (Start_NODE == NULL) continue;
						Current_NODE = Start_NODE;
					}
					else {
						Current_NODE = APPEND_API_LIST_NODE(Current_NODE, (PUCHAR)&API_NAMES[i], sizeof(API_NAMES[i]), (PUCHAR)&DLL_NAMES[x], sizeof(DLL_NAMES[x]), (PUCHAR)procAddress, is_admin_running);
						if (Current_NODE == NULL) continue;
					}
					
					printf("DLL -> %s / API %s API주소: %p  \n", DLL_NAMES[x], API_NAMES[i], Current_NODE->API_ADDRESS);

					// 후크함수 등록
					Current_NODE->HOOK_info.Hooked_API_ADDRESS = (PUCHAR)HOOK_API_ADDRESS[i];//HookedMessageBoxA;

					// 후크함수 내에서 사용된 Mutex 객체 생성
					Current_NODE->HOOK_info.MUTEX_HANDLE = CreateMutex(NULL, FALSE, NULL);

				}

			}

		}
		printf("Start_NODE -> %p\n", Start_NODE);
		return Start_NODE;
	}
	


    HRESULT CheckIfIsUserAdmin(PBOOLEAN pIsAdmin)
    {
        int b;
        HANDLE hProcess = NULL;
        HANDLE hProcessToken = NULL;
        HANDLE hLinkedToken = NULL;
        BOOL fIsAdmin = FALSE;
        DWORD dwLength = 0;
        OSVERSIONINFO osver = { sizeof(OSVERSIONINFO) };
        HRESULT hr = S_OK;

        *pIsAdmin = FALSE;

        hProcess = GetCurrentProcess();
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Exit;
        }

        char AdminSID[SECURITY_MAX_SID_SIZE];
        dwLength = sizeof(AdminSID);
        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &AdminSID, &dwLength))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Exit;
        }

        if (!CheckTokenMembership(NULL, &AdminSID, &fIsAdmin))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Exit;
        }

        if (fIsAdmin)
        {
            *pIsAdmin = TRUE;
            goto Exit;
        }


        if (osver.dwMajorVersion < 6)
        {
            goto Exit;
        }

        if (!GetTokenInformation(hProcessToken, TokenLinkedToken,
            (VOID*)&hLinkedToken, sizeof(HANDLE), &dwLength))
        {
            b = GetLastError();
            if (b == ERROR_NO_SUCH_LOGON_SESSION || b == ERROR_PRIVILEGE_NOT_HELD)
            {
                goto Exit;
            }

            hr = HRESULT_FROM_WIN32(b);
            goto Exit;
        }

        if (!CheckTokenMembership(hLinkedToken, &AdminSID, &fIsAdmin))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Exit;
        }

        if (fIsAdmin)
        {
            *pIsAdmin = TRUE;
        }

    Exit:
        if (hProcess)
        {
            CloseHandle(hProcess);
        }

        if (hProcessToken)
        {
            CloseHandle(hProcessToken);
        }

        if (hLinkedToken)
        {
            CloseHandle(hLinkedToken);
        }

        return hr;
    }



#ifdef __cplusplus
	}
#endif