#ifndef Hooked_IOCTL_H
#define Hooked_IOCTL_H

#include <stdio.h>
#include <Windows.h>
#include <cstdlib>


#include <winioctl.h>
#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum communication_ioctl_ENUM {

	HOOK_MON = 3001// API 후크된 함수에서 요청하는 것임

} COMMUNICATION_IOCTL_ENUM;

typedef struct HOOK_IOCTL_DATA {
	HANDLE PID;//자신의 PID 
	UCHAR Hooked_API_NAME[128]; // 후크 걸린 API 이름
}HOOK_IOCTL_DATA, *PHOOK_IOCTL_DATA;


typedef struct comunication_ioctl_for_HOOKING {

	HANDLE PID;
	HANDLE Process_HANDLE;

}comunication_ioctl_for_HOOKING, * Pcomunication_ioctl_for_HOOKING;

typedef struct communication_ioctl {
	COMMUNICATION_IOCTL_ENUM information;
	UCHAR license_ID[128];
	UCHAR Agent_ID[128];

	HANDLE Ioctl_User_Mode_ProcessId; // 추가됨 

	comunication_ioctl_for_HOOKING HOOK_DATA; // 추가됨

	HOOK_IOCTL_DATA API_HOOK_MON;

} COMMUNICATION_IOCTL, * PCOMMUNICATION_IOCTL;

#ifdef __cplusplus
extern "C" {
#endif

	BOOLEAN SEND_IOCTL(PHOOK_IOCTL_DATA parm);
	

#ifdef __cplusplus
}
#endif

#endif