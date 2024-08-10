#include "pch.h"
#include "USER32_HOOK_Functions.h"

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	
	// 일치한 API_LIST 가져오기
	PAPI_LIST current = external_API_LIST_start_address;
	while (current != NULL) {

		if (current->HOOK_info.Hooked_API_ADDRESS == (PUCHAR)HookedMessageBoxA) {
			printf("후크 일치 if(  %p , %p )", current->API_NAME, current->API_ADDRESS);
			break;
		}

		current = (PAPI_LIST)current->NEXT_ADDR;
	}

	// 점유
	WaitForSingleObject(current->HOOK_info.MUTEX_HANDLE, INFINITE);
	


	printf("후크시작\n");

	// 원본돌리기
	Set_TurnBack(current);

	printf("후크시작-중\n");

	int OUTPUT = MessageBoxA(hWnd, "Hooked Message", lpCaption, uType);

	// 다시 후크걸기
	Set_Hook(current);




	// 점유해제
	ReleaseMutex(current->HOOK_info.MUTEX_HANDLE);

	printf("후크끝\n");

	return OUTPUT;
}