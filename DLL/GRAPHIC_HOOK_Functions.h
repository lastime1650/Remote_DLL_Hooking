#ifndef GRAPHIC_HOOK_Functions_H
#define GRAPHIC_HOOK_Functions_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>
#include "API_ADDRESSES_LINKED_LIST.h"
#include "Start_Hook.h"
#include "Hooked_IOCTL.h"

#ifdef __cplusplus
extern "C" {
#endif


	// 대부분 스크린 샷 차단을 위한 로깅 

	HBITMAP WINAPI HookedCreateCompatibleBitmap(HDC hdc, int Width, int Height);
	
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
	);

	


	//int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

#ifdef __cplusplus
}
#endif

#endif // !GRAPHIC_HOOK_Functions_H
