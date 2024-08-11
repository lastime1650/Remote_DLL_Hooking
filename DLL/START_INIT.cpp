#include "pch.h"
#include "START_INIT.h"


#ifdef __cplusplus
extern "C" {
#endif

	DWORD WINAPI START_INIT(PVOID none) {

        printf("시작\n");

        // 미리 준비된 API - DLL 매핑하여 주소 얻기를 연결리스트로 가져오도록 함
        PAPI_LIST NODE = LOAD_API_ADDRESSES();
        if (NODE == NULL)
            return 0;


        PAPI_LIST current = NODE;
        while (current != NULL) {

            printf(" %s -> %s / 후크된 주소 : %p \n", current->DLL_NAME, current->API_NAME, current->HOOK_info.Hooked_API_ADDRESS);

            current = (PAPI_LIST)current->NEXT_ADDR;
        }

        // 전역변수에 등록 ( 후크 함수에서 써먹어야함 ) 
        external_API_LIST_start_address = NODE;


        // 후킹 수행 ( 32비트 또는 64비트 확인 필요 ) 
        START_HOOKING(NODE);

        printf("START_INIT 종료\n");
		return 0;
	}

#ifdef __cplusplus
}
#endif