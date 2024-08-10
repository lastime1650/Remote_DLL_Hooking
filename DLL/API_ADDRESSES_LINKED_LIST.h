#ifndef API_ADDRESSES_LINKED_LIST_H
#define API_ADDRESSES_LINKED_LIST_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>

#ifdef __cplusplus
extern "C" {
#endif

	// HOOK_STRUCT 후킹 전용
	typedef enum Arch {
		_64bit_ = 0,
		_32bit_ 
	}Arch;

	typedef struct HOOK_STRUCT {
		Arch Architecture;
		
		PUCHAR Original_Byte; // 동적할당 필요
		PUCHAR Hooked_Byte; // 후킹될 바이트

		PUCHAR Hooked_API_ADDRESS; // 후킹함수 주소

		HANDLE MUTEX_HANDLE; // 여러 스레드에서 접근하는 경우를 대비해야한다. 

	}HOOK_STRUCT, * P_HOOK_STRUCT;


typedef struct API_LIST {

	PUCHAR DLL_NAME;

	PUCHAR API_NAME;

	PUCHAR API_ADDRESS;


	HOOK_STRUCT HOOK_info;

	PUCHAR NEXT_ADDR;

}API_LIST, * PAPI_LIST;

extern PAPI_LIST external_API_LIST_start_address;
extern PAPI_LIST external_API_LIST_current_address;


PAPI_LIST CREATE_API_LIST_NODE(PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS);

PAPI_LIST APPEND_API_LIST_NODE(PAPI_LIST Current_node, PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS);

#ifdef __cplusplus
}
#endif

#endif