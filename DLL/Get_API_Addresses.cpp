#include "pch.h"
#include "Get_API_Addresses.h"

#include "USER32_HOOK_Functions.h"


#ifdef __cplusplus
extern "C" {
#endif

	UCHAR DLL_NAMES[][128] = {
		"user32.dll",
		"kernel32.dll"
	
	};

	UCHAR API_NAMES[][128] = {
		"MessageBoxA"
	};

	// 아래 값은, API_NAMES 와 일치한 후크함수로 저장되어야함
	PVOID HOOK_API_ADDRESS[] = {
		HookedMessageBoxA
	};

	__declspec(dllexport) PAPI_LIST LOAD_API_ADDRESSES() {
		


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
					

					if (Start_NODE == NULL) {
						Start_NODE = CREATE_API_LIST_NODE((PUCHAR)&API_NAMES[i], sizeof(API_NAMES[i]), (PUCHAR)&DLL_NAMES[x], sizeof(DLL_NAMES[x]),  (PUCHAR)procAddress);
						if (Start_NODE == NULL) continue;
						Current_NODE = Start_NODE;
					}
					else {
						Current_NODE = APPEND_API_LIST_NODE(Current_NODE, (PUCHAR)&API_NAMES[i], sizeof(API_NAMES[i]), (PUCHAR)&DLL_NAMES[x], sizeof(DLL_NAMES[x]), (PUCHAR)procAddress);
						if (Current_NODE == NULL) continue;
					}
					
					printf("DLL -> %s / API %s API주소: %p  \n", DLL_NAMES[x], API_NAMES[i], Current_NODE->API_ADDRESS);

					// 후크함수 등록
					Current_NODE->HOOK_info.Hooked_API_ADDRESS = (PUCHAR)HookedMessageBoxA;

					// 후크함수 내에서 사용된 Mutex 객체 생성
					Current_NODE->HOOK_info.MUTEX_HANDLE = CreateMutex(NULL, FALSE, NULL);

				}

			}

		}
		printf("Start_NODE -> %p\n", Start_NODE);
		return Start_NODE;
	}
	

#ifdef __cplusplus
	}
#endif