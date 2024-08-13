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


	// ��κ� ��ũ�� �� ������ ���� �α� 

	HBITMAP WINAPI HookedCreateCompatibleBitmap(HDC hdc, int Width, int Height);
	
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
	);

	


	//int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

#ifdef __cplusplus
}
#endif

#endif // !GRAPHIC_HOOK_Functions_H
