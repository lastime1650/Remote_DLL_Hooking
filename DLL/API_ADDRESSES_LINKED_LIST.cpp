#include "pch.h"
#include "API_ADDRESSES_LINKED_LIST.h"

#ifdef __cplusplus
extern "C" {
#endif

	PAPI_LIST external_API_LIST_start_address = NULL;
	PAPI_LIST external_API_LIST_current_address = NULL;


	PAPI_LIST CREATE_API_LIST_NODE(PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS, BOOLEAN is_admin_running) {

		if (API_ADDRESS == NULL) return NULL;

		PAPI_LIST New_Node = (PAPI_LIST)malloc(sizeof(API_LIST));
		if (New_Node == NULL) return NULL;
		memset(New_Node, 0, sizeof(API_LIST));




		// API ���ڿ� ����
		New_Node->API_NAME = (PUCHAR)malloc(API_NAME_LENGTH);
		if (New_Node->API_NAME == NULL) {
			free(New_Node);
			return NULL;
		}
		memcpy(New_Node->API_NAME, API_NAME, API_NAME_LENGTH);
		printf("%s\n", New_Node->API_NAME);





		// DLL ���ڿ� ����
		New_Node->DLL_NAME = (PUCHAR)malloc(DLL_NAME_LENGTH);
		if (New_Node->DLL_NAME == NULL) {
			free(New_Node->API_NAME);
			free(New_Node);
			return NULL;
		}
		memcpy(New_Node->DLL_NAME, DLL_NAME, DLL_NAME_LENGTH);
		printf("%s\n", New_Node->DLL_NAME);






		// API �ּ� ����
		New_Node->API_ADDRESS = API_ADDRESS;


		// ������ ��������..
		New_Node->is_admin_running = is_admin_running;



		// ��Ű��ó 32 vs 64 ���� ..
		if (sizeof(PVOID) == 8) {
			// 64��Ʈ ����
			/*
				64��Ʈ�� ���, �������Ϳ� �ּҸ� ��� �� �������͸� JMP ���Ѿ���
			*/
			New_Node->HOOK_info.Architecture = _64bit_;
		}
		else {
			// 32��Ʈ ����
			/*
				�ּ� ��������
			*/
			New_Node->HOOK_info.Architecture = _32bit_;
		}

		New_Node->NEXT_ADDR = NULL;

		return New_Node;
	}

	PAPI_LIST APPEND_API_LIST_NODE(PAPI_LIST Current_node, PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS, BOOLEAN is_admin_running) {

		PAPI_LIST New_Node = CREATE_API_LIST_NODE(API_NAME, API_NAME_LENGTH, DLL_NAME, DLL_NAME_LENGTH, API_ADDRESS, is_admin_running);
		if (New_Node == NULL) return NULL;

		Current_node->NEXT_ADDR = (PUCHAR)New_Node;

		return New_Node;

	}

	PAPI_LIST match_original_API_address_and_Hook_API_address(PUCHAR Give_me_Hook_API_Address) {
		if (external_API_LIST_start_address == NULL) return NULL;

		PAPI_LIST current = external_API_LIST_start_address;
		while (current != NULL) {

			if (current->HOOK_info.Hooked_API_ADDRESS == (PUCHAR)Give_me_Hook_API_Address) {
				printf("��ũ ��ġ if(  ��������( %s  %p ) == ��ũ�Լ��ּ�( %p) )", current->API_NAME, current->API_ADDRESS,Give_me_Hook_API_Address);
				return current;
			}

			current = (PAPI_LIST)current->NEXT_ADDR;
		}
		
		return NULL;
	}

#ifdef __cplusplus
	}
#endif