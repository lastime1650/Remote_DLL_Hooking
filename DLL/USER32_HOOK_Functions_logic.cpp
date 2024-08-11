#include "pch.h"
#include "USER32_HOOK_Functions.h"

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	
	UCHAR NAME[] = "MessageBoxA";

	// ��ġ�� API_LIST ��������
	PAPI_LIST hook_info_node =  match_original_API_address_and_Hook_API_address((PUCHAR)HookedMessageBoxA);
	if (hook_info_node == NULL) {
		return -1;
	}

	// ����
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	


	printf("��ũ����\n");

	// ����������
	Set_TurnBack(hook_info_node);

	printf("��ũ����-��\n");

	int OUTPUT = MessageBoxA(hWnd, "Hooked Message", lpCaption, uType);


	HOOK_IOCTL_DATA DATA = { 0, };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, NAME, sizeof(NAME));
	SEND_IOCTL(&DATA);
	//HANDLE Thread_HANDLE = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SEND_IOCTL, &DATA, 0, NULL);
	//CloseHandle(Thread_HANDLE);
	
	

	// �ٽ� ��ũ�ɱ�
	Set_Hook(hook_info_node);




	// ��������
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	printf("��ũ��\n");

	return OUTPUT;
}