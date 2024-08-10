#include "pch.h"
#include "API_ADDRESSES_LINKED_LIST.h"

#ifdef __cplusplus
extern "C" {
#endif

	PAPI_LIST external_API_LIST_start_address = NULL;
	PAPI_LIST external_API_LIST_current_address = NULL;


	PAPI_LIST CREATE_API_LIST_NODE(PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS) {

		if (API_ADDRESS == NULL) return NULL;

		PAPI_LIST New_Node = (PAPI_LIST)malloc(sizeof(API_LIST));
		if (New_Node == NULL) return NULL;
		memset(New_Node, 0, sizeof(API_LIST));




		// API 문자열 저장
		New_Node->API_NAME = (PUCHAR)malloc(API_NAME_LENGTH);
		if (New_Node->API_NAME == NULL) {
			free(New_Node);
			return NULL;
		}
		memcpy(New_Node->API_NAME, API_NAME, API_NAME_LENGTH);
		printf("%s\n", New_Node->API_NAME);





		// DLL 문자열 저장
		New_Node->DLL_NAME = (PUCHAR)malloc(DLL_NAME_LENGTH);
		if (New_Node->DLL_NAME == NULL) {
			free(New_Node->API_NAME);
			free(New_Node);
			return NULL;
		}
		memcpy(New_Node->DLL_NAME, DLL_NAME, DLL_NAME_LENGTH);
		printf("%s\n", New_Node->DLL_NAME);






		// API 주소 저장
		New_Node->API_ADDRESS = API_ADDRESS;






		// 아키텍처 32 vs 64 인지 ..
		if (sizeof(PVOID) == 8) {
			// 64비트 실행
			/*
				64비트의 경우, 레지스터에 주소를 담고 그 레지스터를 JMP 시켜야함
			*/
			New_Node->HOOK_info.Architecture = _64bit_;
		}
		else {
			// 32비트 실행
			/*
				주소 점프가능
			*/
			New_Node->HOOK_info.Architecture = _32bit_;
		}

		New_Node->NEXT_ADDR = NULL;

		return New_Node;
	}

	PAPI_LIST APPEND_API_LIST_NODE(PAPI_LIST Current_node, PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS) {

		PAPI_LIST New_Node = CREATE_API_LIST_NODE(API_NAME, API_NAME_LENGTH, DLL_NAME, DLL_NAME_LENGTH, API_ADDRESS);
		if (New_Node == NULL) return NULL;

		Current_node->NEXT_ADDR = (PUCHAR)New_Node;

		return New_Node;

	}

#ifdef __cplusplus
	}
#endif