#ifndef Get_API_Addresses_H
#define Get_API_Addresses_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>

#include "API_ADDRESSES_LINKED_LIST.h" // 연결리스트

#ifdef __cplusplus
extern "C" {
#endif


	// 연결리스트 시작 주소를 추출한다. 
	__declspec(dllexport) PAPI_LIST LOAD_API_ADDRESSES();

#ifdef __cplusplus
	}
#endif

#endif