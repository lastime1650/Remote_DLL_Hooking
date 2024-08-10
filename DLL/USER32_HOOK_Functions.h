#ifndef USER32_HOOK_Functions_H
#define USER32_HOOK_Functions_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>
#include "API_ADDRESSES_LINKED_LIST.h"
#include "Start_64bit_Hook.h"

#ifdef __cplusplus
extern "C" {
#endif

	int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

#ifdef __cplusplus
}
#endif

#endif // !USER32_HOOK_Functions_H
