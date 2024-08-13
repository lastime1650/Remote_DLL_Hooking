#include "pch.h"
#include "GRAPHIC_HOOK_Functions.h"

BOOL WINAPI HookedBitBlt(
	HDC   hdcDest,  // ��� ����̽� ���ؽ�Ʈ�� �ڵ�
	int   xDest,    // ��󿡼� ���簡 ���۵� X ��ǥ
	int   yDest,    // ��󿡼� ���簡 ���۵� Y ��ǥ
	int   width,    // ������ ��Ʈ���� �ʺ�
	int   height,   // ������ ��Ʈ���� ����
	HDC   hdcSrc,   // �ҽ� ����̽� ���ؽ�Ʈ�� �ڵ�
	int   xSrc,     // �ҽ����� ���簡 ���۵� X ��ǥ
	int   ySrc,     // �ҽ����� ���簡 ���۵� Y ��ǥ
	DWORD rop       // ������ ���� �ڵ�
) {


	// ��ġ�� API_LIST ��������
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedBitBlt);
	if (hook_info_node == NULL) {
		return -1;
	}

	// ����
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);



	printf("��ũ����\n");

	// ����������
	Set_TurnBack(hook_info_node);

	printf("��ũ����-��\n");

	BOOL OUTPUT = BitBlt(
		hdcDest,  // ��� ����̽� ���ؽ�Ʈ�� �ڵ�
		xDest,    // ��󿡼� ���簡 ���۵� X ��ǥ
		yDest,    // ��󿡼� ���簡 ���۵� Y ��ǥ
		width,    // ������ ��Ʈ���� �ʺ�
		height,   // ������ ��Ʈ���� ����
		hdcSrc,   // �ҽ� ����̽� ���ؽ�Ʈ�� �ڵ�
		xSrc,     // �ҽ����� ���簡 ���۵� X ��ǥ
		ySrc,     // �ҽ����� ���簡 ���۵� Y ��ǥ
		rop       // ������ ���� �ڵ�
	);



	HOOK_IOCTL_DATA DATA = { 0, };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	// �Ķ���� �����Ҵ�
	DATA.Start_Address = NULL;

	PHOOK_API_Parameters tmp_START_ADDR = NULL;


	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hdcDest, sizeof(hdcDest));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&xDest, sizeof(xDest));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&yDest, sizeof(yDest));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&width, sizeof(width));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&height, sizeof(height));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hdcSrc, sizeof(hdcSrc));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&xSrc, sizeof(xSrc));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&ySrc, sizeof(ySrc));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&rop, sizeof(rop));


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