#ifndef IOCTL_H
#define IOCTL_H

#include <stdio.h>
#include <Windows.h>

/*
	IOCTL 작업 헤더들
*/
#include "Hooking.h"

#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum communication_ioctl_ENUM {

	CHECK = 1,

	SUCCESS = 100,
	FAIL = 101,
	REQUEST_all = 1029,
	REQUESET_without_AGENT_ID = 1030,
	WAIT_FAILED_from_Center_Server = 2000,
	WAIT_FAILED_from_Kernel = 2001,
	WAIT_FAILED_from_User = 2002,


	HOOKING_request = 3000

} COMMUNICATION_IOCTL_ENUM;


// 주로 커널이 유저모드에게 전달하는 후킹 전달 요청 데이터
typedef struct comunication_ioctl_for_HOOKING {

	HANDLE PID;
	HANDLE Process_HANDLE;

}comunication_ioctl_for_HOOKING, *Pcomunication_ioctl_for_HOOKING;

typedef struct communication_ioctl {
	COMMUNICATION_IOCTL_ENUM information;
	UCHAR license_ID[128];
	UCHAR Agent_ID[128];

	HANDLE Ioctl_User_Mode_ProcessId; // 추가됨 

	comunication_ioctl_for_HOOKING HOOK_DATA; // 추가됨

} COMMUNICATION_IOCTL, * PCOMMUNICATION_IOCTL;



BOOLEAN Initialize_communicate(PCOMMUNICATION_IOCTL BUFFER, HANDLE* hDevice);

BOOLEAN Keeping_communicate(PCOMMUNICATION_IOCTL BUFFER, HANDLE hDevice);



#endif // IOCTL.h