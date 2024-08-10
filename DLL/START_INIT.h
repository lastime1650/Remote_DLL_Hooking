#ifndef START_INIT_H
#define START_INIT_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>

#include "Get_API_Addresses.h"
#include "Start_64bit_Hook.h"

#ifdef __cplusplus
extern "C" {
#endif


	DWORD WINAPI START_INIT(PVOID none);


#ifdef __cplusplus
}
#endif

#endif // !START_INIT_H
