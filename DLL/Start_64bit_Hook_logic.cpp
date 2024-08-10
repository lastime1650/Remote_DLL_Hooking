#include "pch.h"
#include "Start_64bit_Hook.h"





	


	BOOLEAN START_HOOKING(PAPI_LIST START_NODE) {

		PAPI_LIST CURRENT = START_NODE;
		while (CURRENT != NULL) {
			
			printf("%d\n", Set_Hook(CURRENT));

			CURRENT = (PAPI_LIST)CURRENT->NEXT_ADDR;

		}
		


		return TRUE;
	}


BOOLEAN Set_Hook(PAPI_LIST NODE) {

	printf("오리지날 %s 함수를 %p 주소로 후킹시도합니다. \n", NODE->API_NAME, NODE->HOOK_info.Hooked_API_ADDRESS);

	DWORD oldProtect = 0;

	DWORD Byte_Size_for_HOOK = 0;

	if (NODE->HOOK_info.Architecture == _64bit_) {
		//64비트
		Byte_Size_for_HOOK = 13;

		if (NODE->HOOK_info.Original_Byte == NULL) {
			NODE->HOOK_info.Original_Byte = (PUCHAR)malloc(Byte_Size_for_HOOK);
			if (NODE->HOOK_info.Original_Byte == NULL)
				return FALSE;
		}

		if (NODE->HOOK_info.Hooked_Byte == NULL) {
			NODE->HOOK_info.Hooked_Byte = (PUCHAR)malloc(Byte_Size_for_HOOK);
			if (NODE->HOOK_info.Hooked_Byte == NULL) {
				free(NODE->HOOK_info.Original_Byte);
				return FALSE;
			}
		}

		NODE->HOOK_info.Hooked_Byte[0] = 0x49;
		NODE->HOOK_info.Hooked_Byte[1] = 0xBA;
		*(UINT64*)(NODE->HOOK_info.Hooked_Byte + 2) = (UINT64)NODE->HOOK_info.Hooked_API_ADDRESS; // MOV R10, { 후크 주소(8바이트) } ;
		NODE->HOOK_info.Hooked_Byte[10] = 0x41;
		NODE->HOOK_info.Hooked_Byte[11] = 0xFF;
		NODE->HOOK_info.Hooked_Byte[12] = 0xE2; // JMP R10 ; 

	}
	else {
		//32비트
		Byte_Size_for_HOOK = 7;

		if (NODE->HOOK_info.Original_Byte == NULL) {
			NODE->HOOK_info.Original_Byte = (PUCHAR)malloc(Byte_Size_for_HOOK);
			if (NODE->HOOK_info.Original_Byte == NULL)
				return FALSE;
		}

		if (NODE->HOOK_info.Hooked_Byte == NULL) {
			NODE->HOOK_info.Hooked_Byte = (PUCHAR)malloc(Byte_Size_for_HOOK);
			if (NODE->HOOK_info.Hooked_Byte == NULL) {
				free(NODE->HOOK_info.Original_Byte);
				return FALSE;
			}
		}

		NODE->HOOK_info.Hooked_Byte[0] = 0xB8;
		*(UINT32*)(NODE->HOOK_info.Hooked_Byte + 1) = (UINT32)NODE->HOOK_info.Hooked_API_ADDRESS; // MOV R10, { 후크 주소(8바이트) } ;
		NODE->HOOK_info.Hooked_Byte[5] = 0xFF;
		NODE->HOOK_info.Hooked_Byte[6] = 0xE0;// JMP EAX ; 
	}

	

	// 잠시 보호 수준을 읽고 쓸 수 있도록 변경한다
	if (VirtualProtect(NODE->API_ADDRESS, Byte_Size_for_HOOK, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE) {
		free(NODE->HOOK_info.Hooked_Byte);
		free(NODE->HOOK_info.Original_Byte);
		return FALSE;
	}

	// 원본 바이트 저장 -> 복구를 위해서 기억해야함
	memcpy(NODE->HOOK_info.Original_Byte, NODE->API_ADDRESS, Byte_Size_for_HOOK);
	printf("Set_Hook 원본 바이트 저장 -> memcpy(%p , %p , %d )\n", NODE->HOOK_info.Original_Byte, NODE->API_ADDRESS, Byte_Size_for_HOOK);

	// 후킹
	memcpy(NODE->API_ADDRESS, NODE->HOOK_info.Hooked_Byte, Byte_Size_for_HOOK);

	// 메모리 보호 복원
	if (VirtualProtect(NODE->API_ADDRESS, Byte_Size_for_HOOK, oldProtect, &oldProtect) == FALSE) {
		free(NODE->HOOK_info.Hooked_Byte);
		free(NODE->HOOK_info.Original_Byte);
		return FALSE;
	}

	return TRUE;

}


BOOLEAN Set_TurnBack(PAPI_LIST NODE) {
	DWORD oldProtect = 0;

	DWORD Byte_Size_for_HOOK = 0;

	if (NODE->HOOK_info.Architecture == _64bit_) {
		//64비트
		Byte_Size_for_HOOK = 13;
	}
	else {
		Byte_Size_for_HOOK = 7;
	}


	printf("Set_TurnBack 시작 \n");
	// 잠시 보호 수준을 읽고 쓸 수 있도록 변경한다
	if (VirtualProtect(NODE->API_ADDRESS, Byte_Size_for_HOOK, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE) {
		printf("Set_TurnBack 실패 1 \n");
		return FALSE;
	}

	// 원본으로 되돌림
	memcpy(NODE->API_ADDRESS, NODE->HOOK_info.Original_Byte, Byte_Size_for_HOOK);
	printf("Set_TurnBack -> memcpy(%p , %p , %d )\n", NODE->API_ADDRESS, NODE->HOOK_info.Original_Byte, Byte_Size_for_HOOK);

	// 메모리 보호 복원
	if (VirtualProtect(NODE->API_ADDRESS, Byte_Size_for_HOOK, oldProtect, &oldProtect) == FALSE) {
		printf("Set_TurnBack 실패 2 \n");
		return FALSE;
	}

	return TRUE;
}

