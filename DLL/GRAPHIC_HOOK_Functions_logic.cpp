#include "pch.h"
#include "GRAPHIC_HOOK_Functions.h"

BOOL WINAPI HookedBitBlt(
	HDC   hdcDest,  // 대상 디바이스 컨텍스트의 핸들
	int   xDest,    // 대상에서 복사가 시작될 X 좌표
	int   yDest,    // 대상에서 복사가 시작될 Y 좌표
	int   width,    // 복사할 비트맵의 너비
	int   height,   // 복사할 비트맵의 높이
	HDC   hdcSrc,   // 소스 디바이스 컨텍스트의 핸들
	int   xSrc,     // 소스에서 복사가 시작될 X 좌표
	int   ySrc,     // 소스에서 복사가 시작될 Y 좌표
	DWORD rop       // 래스터 연산 코드
) {


	// 일치한 API_LIST 가져오기
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedBitBlt);
	if (hook_info_node == NULL) {
		return -1;
	}

	// 점유
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);



	printf("후크시작\n");

	// 원본돌리기
	Set_TurnBack(hook_info_node);

	printf("후크시작-중\n");

	BOOL OUTPUT = BitBlt(
		hdcDest,  // 대상 디바이스 컨텍스트의 핸들
		xDest,    // 대상에서 복사가 시작될 X 좌표
		yDest,    // 대상에서 복사가 시작될 Y 좌표
		width,    // 복사할 비트맵의 너비
		height,   // 복사할 비트맵의 높이
		hdcSrc,   // 소스 디바이스 컨텍스트의 핸들
		xSrc,     // 소스에서 복사가 시작될 X 좌표
		ySrc,     // 소스에서 복사가 시작될 Y 좌표
		rop       // 래스터 연산 코드
	);



	HOOK_IOCTL_DATA DATA = { 0, };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	// 파라미터 동적할당
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



	// 다시 후크걸기
	Set_Hook(hook_info_node);




	// 점유해제
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	printf("후크끝\n");

	return OUTPUT;


}