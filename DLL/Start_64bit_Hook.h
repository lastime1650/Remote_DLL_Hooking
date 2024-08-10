#ifndef _64_HOOK_H
#define _64_HOOK_H


#include <stdio.h>
#include <Windows.h>
#include <cstdlib>
#include "API_ADDRESSES_LINKED_LIST.h"

#ifdef __cplusplus
extern "C" {
#endif

	BOOLEAN Set_Hook(PAPI_LIST NODE);
	BOOLEAN Set_TurnBack(PAPI_LIST NODE);


	BOOLEAN START_HOOKING(PAPI_LIST START_NODE);


#ifdef __cplusplus
}
#endif

#endif // !_64_HOOK_H
