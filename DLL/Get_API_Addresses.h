#ifndef Get_API_Addresses_H
#define Get_API_Addresses_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>

#include "API_ADDRESSES_LINKED_LIST.h" // ���Ḯ��Ʈ

#ifdef __cplusplus
extern "C" {
#endif


	// ���Ḯ��Ʈ ���� �ּҸ� �����Ѵ�. 
	__declspec(dllexport) PAPI_LIST LOAD_API_ADDRESSES();

#ifdef __cplusplus
	}
#endif

#endif