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