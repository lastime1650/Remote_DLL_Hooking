#include "pch.h"
#include "USER32_HOOK_Functions.h"

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	
	// ��ġ�� API_LIST ��������
	PAPI_LIST current = external_API_LIST_start_address;
	while (current != NULL) {

		if (current->HOOK_info.Hooked_API_ADDRESS == (PUCHAR)HookedMessageBoxA) {
			printf("��ũ ��ġ if(  %p , %p )", current->API_NAME, current->API_ADDRESS);
			break;
		}

		current = (PAPI_LIST)current->NEXT_ADDR;
	}

	// ����
	WaitForSingleObject(current->HOOK_info.MUTEX_HANDLE, INFINITE);
	


	printf("��ũ����\n");

	// ����������
	Set_TurnBack(current);

	printf("��ũ����-��\n");

	int OUTPUT = MessageBoxA(hWnd, "Hooked Message", lpCaption, uType);

	// �ٽ� ��ũ�ɱ�
	Set_Hook(current);




	// ��������
	ReleaseMutex(current->HOOK_info.MUTEX_HANDLE);

	printf("��ũ��\n");

	return OUTPUT;
}