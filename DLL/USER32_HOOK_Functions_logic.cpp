#include "pch.h"
#include "USER32_HOOK_Functions.h"

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	
	UCHAR NAME[] = "MessageBoxA";

	// 일치한 API_LIST 가져오기
	PAPI_LIST hook_info_node =  match_original_API_address_and_Hook_API_address((PUCHAR)HookedMessageBoxA);
	if (hook_info_node == NULL) {
		return -1;
	}

	// 점유
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	


	printf("후크시작\n");

	// 원본돌리기
	Set_TurnBack(hook_info_node);

	printf("후크시작-중\n");

	int OUTPUT = MessageBoxA(hWnd, "Hooked Message", lpCaption, uType);


	HOOK_IOCTL_DATA DATA = { 0, };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, NAME, sizeof(NAME));
	SEND_IOCTL(&DATA);
	//HANDLE Thread_HANDLE = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SEND_IOCTL, &DATA, 0, NULL);
	//CloseHandle(Thread_HANDLE);
	
	

	// 다시 후크걸기
	Set_Hook(hook_info_node);




	// 점유해제
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	printf("후크끝\n");

	return OUTPUT;
}