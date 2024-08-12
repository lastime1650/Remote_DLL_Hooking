#include "pch.h"
#include "Hooked_IOCTL.h"

HANDLE hDevice = 0;

BOOLEAN SEND_IOCTL(PHOOK_IOCTL_DATA parm) {

	// IOCTL 열기
	if (hDevice == 0) {
		hDevice = CreateFile(TEXT("\\\\.\\My_AGENT_Device"),
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (hDevice == INVALID_HANDLE_VALUE) {
			printf("IOCTL 심볼릭 링크 열 수 없음\n");
			return FALSE;
		}
		printf("IOCTL_핸들값 -> %lu\n", hDevice);
	}
	

	PCOMMUNICATION_IOCTL SEND_RECEIVE_BUFFER = (PCOMMUNICATION_IOCTL)malloc(sizeof(COMMUNICATION_IOCTL));
	if (SEND_RECEIVE_BUFFER == NULL) return FALSE;
	memset(SEND_RECEIVE_BUFFER, 0, sizeof(COMMUNICATION_IOCTL));

	SEND_RECEIVE_BUFFER->information = HOOK_MON;

	SEND_RECEIVE_BUFFER->API_HOOK_MON.PID = parm->PID;
	memcpy( SEND_RECEIVE_BUFFER->API_HOOK_MON.Hooked_API_NAME, parm->Hooked_API_NAME, sizeof(parm->Hooked_API_NAME) ); // 128 고정임

	SEND_RECEIVE_BUFFER->API_HOOK_MON.Start_Address = parm->Start_Address;

	DWORD bytesReturned;

	// IOCTL 요청 보내기
	BOOL success = DeviceIoControl(hDevice,
		IOCTL_TEST,
		SEND_RECEIVE_BUFFER,
		sizeof(COMMUNICATION_IOCTL),
		SEND_RECEIVE_BUFFER,
		sizeof(COMMUNICATION_IOCTL),
		&bytesReturned,
		NULL
	);

	free(SEND_RECEIVE_BUFFER);

	return TRUE;
}

/// <summary>
///  동적 파라미터를 연결리스트로 동적 추가
/// </summary>
/// <param name="DATA"></param>
/// <param name="SIZE"></param>
/// <returns></returns>
PHOOK_API_Parameters Create_HOOK_API_Parm_Node(PHOOK_API_Parameters Previous_node, PUCHAR DATA, ULONG32 SIZE) {
	PHOOK_API_Parameters New_Node = NULL;
	New_Node = (PHOOK_API_Parameters)VirtualAlloc(NULL, sizeof(HOOK_API_Parameters), MEM_COMMIT, PAGE_READWRITE);
	if (New_Node == NULL) return NULL;

	New_Node->Previous_Addr = (PUCHAR)Previous_node;

	New_Node->parameter_data = (PUCHAR)VirtualAlloc(NULL, SIZE, MEM_COMMIT, PAGE_READWRITE);
	memcpy(New_Node->parameter_data, DATA, SIZE);
	New_Node->parameter_data_size = SIZE;

	New_Node->Next_Addr = NULL;

	return New_Node;
}
PHOOK_API_Parameters Append_HOOK_API_Parm_Node(PHOOK_API_Parameters current_node, PUCHAR DATA, ULONG32 SIZE) {

	current_node->Next_Addr = (PUCHAR)Create_HOOK_API_Parm_Node(current_node, DATA,SIZE);


	if (current_node->Next_Addr == NULL) return NULL;
	

	return (PHOOK_API_Parameters)current_node->Next_Addr;
}


PHOOK_API_Parameters FIND_Start_Address(PHOOK_API_Parameters parm_current_node);

// 리턴하는 값은 항상 Start노드 시작 주소만을 리턴함

PHOOK_API_Parameters ALL_in_One_HOOK_API_Parm_MAKE_NODE(PHOOK_API_Parameters* node_saved_addr, PUCHAR DATA, ULONG32 SIZE) {
	if (node_saved_addr == NULL) return NULL;

	if (*node_saved_addr == NULL) {
		*node_saved_addr = Create_HOOK_API_Parm_Node(NULL, DATA, SIZE);
	}
	else {
		*node_saved_addr = Append_HOOK_API_Parm_Node(*node_saved_addr, DATA, SIZE);
	}

	if (*node_saved_addr == NULL) {
		return NULL;
	}
	else {
		return FIND_Start_Address(*node_saved_addr); // 항상 연결리스트이 시작 주소만을 리턴하도록 해야함
	}
	
}


PHOOK_API_Parameters FIND_Start_Address(PHOOK_API_Parameters parm_current_node) {

	PHOOK_API_Parameters current = parm_current_node;

	while (current != NULL) {

		PHOOK_API_Parameters tmp_remember = current;

		current = (PHOOK_API_Parameters)current->Previous_Addr;
		if (current == NULL) {
			current = tmp_remember;
			break;
		}

	}

	return current;
}