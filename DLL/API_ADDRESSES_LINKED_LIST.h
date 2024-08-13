#ifndef API_ADDRESSES_LINKED_LIST_H
#define API_ADDRESSES_LINKED_LIST_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>

#ifdef __cplusplus
extern "C" {
#endif

	// HOOK_STRUCT ��ŷ ����
	typedef enum Arch {
		_64bit_ = 0,
		_32bit_ 
	}Arch;

	typedef struct HOOK_STRUCT {
		Arch Architecture;
		
		PUCHAR Original_Byte; // �����Ҵ� �ʿ�
		PUCHAR Hooked_Byte; // ��ŷ�� ����Ʈ

		PUCHAR Hooked_API_ADDRESS; // ��ŷ�Լ� �ּ�

		HANDLE MUTEX_HANDLE; // ���� �����忡�� �����ϴ� ��츦 ����ؾ��Ѵ�. 

	}HOOK_STRUCT, * P_HOOK_STRUCT;


typedef struct API_LIST {

	PUCHAR DLL_NAME;

	PUCHAR API_NAME;

	PUCHAR API_ADDRESS;


	HOOK_STRUCT HOOK_info;

	BOOLEAN is_admin_running;

	PUCHAR NEXT_ADDR;

}API_LIST, * PAPI_LIST;

extern PAPI_LIST external_API_LIST_start_address;
extern PAPI_LIST external_API_LIST_current_address;


PAPI_LIST CREATE_API_LIST_NODE(PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS, BOOLEAN is_admin_running );

PAPI_LIST APPEND_API_LIST_NODE(PAPI_LIST Current_node, PUCHAR API_NAME, ULONG32 API_NAME_LENGTH, PUCHAR DLL_NAME, ULONG32 DLL_NAME_LENGTH, PUCHAR API_ADDRESS, BOOLEAN is_admin_running);

// �Ʒ� �Լ��� ȣ���ϱ�����, �������� �ּҰ��� NULL �ƴϾ���Ѵ�.
PAPI_LIST match_original_API_address_and_Hook_API_address(PUCHAR Give_me_Hook_API_Address);

#ifdef __cplusplus
}
#endif

#endif