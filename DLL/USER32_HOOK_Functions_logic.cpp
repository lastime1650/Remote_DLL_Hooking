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

	int OUTPUT = MessageBoxA(hWnd, lpText, lpCaption, uType);


	HOOK_IOCTL_DATA DATA = { 0, };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, NAME, sizeof(NAME));

	// �Ķ���� �����Ҵ�
	DATA.Start_Address = NULL;

	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hWnd, sizeof(hWnd));
	printf("1 -> %p \n", tmp_START_ADDR);
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpText, strlen(lpText)+1 );
	printf("2 -> %p \n", tmp_START_ADDR);
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpCaption, strlen(lpCaption)+1 );
	printf("3 -> %p \n", tmp_START_ADDR);
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&uType, sizeof(uType));
	printf("4 -> %p \n", tmp_START_ADDR);
	

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