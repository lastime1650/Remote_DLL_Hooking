#include "pch.h"
#include "START_INIT.h"


#ifdef __cplusplus
extern "C" {
#endif

	DWORD WINAPI START_INIT(PVOID none) {

        printf("����\n");

        // �̸� �غ�� API - DLL �����Ͽ� �ּ� ��⸦ ���Ḯ��Ʈ�� ���������� ��
        PAPI_LIST NODE = LOAD_API_ADDRESSES();
        if (NODE == NULL)
            return 0;


        PAPI_LIST current = NODE;
        while (current != NULL) {

            printf(" %s -> %s / ��ũ�� �ּ� : %p \n", current->DLL_NAME, current->API_NAME, current->HOOK_info.Hooked_API_ADDRESS);

            current = (PAPI_LIST)current->NEXT_ADDR;
        }

        // ���������� ��� ( ��ũ �Լ����� ��Ծ���� ) 
        external_API_LIST_start_address = NODE;


        // ��ŷ ���� ( 32��Ʈ �Ǵ� 64��Ʈ Ȯ�� �ʿ� ) 
        START_HOOKING(NODE);

        printf("START_INIT ����\n");
		return 0;
	}

#ifdef __cplusplus
}
#endif