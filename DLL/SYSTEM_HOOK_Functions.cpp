#include "pch.h"
#define _CRT_SECURE_NO_WARNINGS
#include "SYSTEM_HOOK_Functions.h"

// CreateRemoteThread
HANDLE WINAPI HookedCreateRemoteThread(
	HANDLE hProcess,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId
) {
	// ��ġ�� API_LIST ��������
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedCreateRemoteThread);
	if (hook_info_node == NULL) {
		return 0;
	}

	// ����
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);



	printf("��ũ����\n");

	// ����������
	Set_TurnBack(hook_info_node);

	printf("��ũ����-��\n");

	HANDLE OUTPUT = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);


	HOOK_IOCTL_DATA DATA = { 0, };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	// �Ķ���� �����Ҵ�
	DATA.Start_Address = NULL;

	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hProcess, sizeof(hProcess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpThreadAttributes, sizeof(SECURITY_ATTRIBUTES) );
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwStackSize, sizeof(dwStackSize));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpStartAddress, sizeof(lpStartAddress));

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpParameter,	sizeof(lpParameter));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwCreationFlags, sizeof(dwCreationFlags));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpThreadId, sizeof(DWORD));


	SEND_IOCTL(&DATA);
	//HANDLE Thread_HANDLE = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SEND_IOCTL, &DATA, 0, NULL);
	//CloseHandle(Thread_HANDLE);



	// �ٽ� ��ũ�ɱ�
	Set_Hook(hook_info_node);




	// ��������
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	printf("��ũ��\n");

	return OUTPUT;
}

BOOL WINAPI HookedCreateProcessA(
	LPCSTR lpApplicationName,        // ���ø����̼� �̸�
	LPSTR lpCommandLine,             // ��� ��
	LPSECURITY_ATTRIBUTES lpProcessAttributes, // ���μ��� ���� �Ӽ�
	LPSECURITY_ATTRIBUTES lpThreadAttributes,  // ������ ���� �Ӽ�
	BOOL bInheritHandles,            // �ڵ� ��� ����
	DWORD dwCreationFlags,           // ���μ��� ���� �÷���
	LPVOID lpEnvironment,            // ȯ�� ����
	LPCSTR lpCurrentDirectory,       // ���� �۾� ���͸�
	LPSTARTUPINFOA lpStartupInfo,     // ���� ����
	LPPROCESS_INFORMATION lpProcessInformation // ���μ��� ����
) {
	// ��ġ�� API_LIST ��������
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedCreateProcessA);
	if (hook_info_node == NULL) {
		return FALSE; // ��ũ ������ ������ FALSE ��ȯ
	}

	// ����
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);

	// ��ũ ����
	printf("��ũ ����: CreateProcessA\n");

	// ���� CreateProcessA ȣ��
	Set_TurnBack(hook_info_node);
	BOOL result = CreateProcessA(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);

	// ��ũ ������ �������� ����
	HOOK_IOCTL_DATA DATA = { 0, };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	// �Ķ���� �����Ҵ�
	PHOOK_API_Parameters tmp_START_ADDR = NULL;
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpApplicationName, sizeof(lpApplicationName));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpCommandLine, sizeof(lpCommandLine));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpProcessAttributes, sizeof(lpProcessAttributes));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpThreadAttributes, sizeof(lpThreadAttributes));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&bInheritHandles, sizeof(bInheritHandles));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwCreationFlags, sizeof(dwCreationFlags));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpEnvironment, sizeof(lpEnvironment));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpCurrentDirectory, sizeof(lpCurrentDirectory));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpStartupInfo, sizeof(lpStartupInfo));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpProcessInformation, sizeof(lpProcessInformation));

	// ��ũ ������ ������
	SEND_IOCTL(&DATA);

	// ��ũ ����
	Set_Hook(hook_info_node);

	// ���� ����
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	// ��ũ ����
	printf("��ũ ����: CreateProcessA\n");

	// ���� �Լ��� ��ȯ�� ��ȯ
	return result;
}

// CreateProcess
BOOL WINAPI HookedCreateProcessW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) {
	// ���� API �ּҿ� ��ũ�� API �ּҸ� ��Ī�Ͽ� ��ũ ������ �����ɴϴ�.
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedCreateProcessW);
	if (hook_info_node == NULL) {
		return FALSE; // ��ũ ������ ������ FALSE ��ȯ
	}

	// ��ũ ������ ��ȣ�ϱ� ���� ���ؽ� ���
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);

	printf("��ũ����\n");

	// ���� API ȣ��
	Set_TurnBack(hook_info_node); // ���� API ȣ���� ���� ��ũ�� ����
	BOOL result = CreateProcessW(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);

	// ��ŷ ������ ����ü �ʱ�ȭ
	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	// �Ķ���� �����Ҵ� �� ������ ����
	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpApplicationName, sizeof(LPCWSTR));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpCommandLine, sizeof(LPWSTR));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpProcessAttributes, sizeof(SECURITY_ATTRIBUTES));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpThreadAttributes, sizeof(SECURITY_ATTRIBUTES));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&bInheritHandles, sizeof(bInheritHandles));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwCreationFlags, sizeof(dwCreationFlags));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpEnvironment, sizeof(LPVOID));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpCurrentDirectory, sizeof(LPCWSTR));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpStartupInfo, sizeof(STARTUPINFO));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpProcessInformation, sizeof(PROCESS_INFORMATION));

	// ��ŷ ������ ����
	SEND_IOCTL(&DATA);

	// ���� API ȣ�� �� �ٽ� ��ũ ����
	Set_Hook(hook_info_node);

	// ���ؽ� ��� ����
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	printf("��ũ��\n");

	return result; // ���� API ȣ�� ��� ��ȯ
}

// OpenProcess
HANDLE WINAPI HookedOpenProcess(
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwProcessId
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedOpenProcess);
	if (hook_info_node == NULL) {
		return NULL;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	HANDLE result = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwDesiredAccess, sizeof(dwDesiredAccess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&bInheritHandle, sizeof(bInheritHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwProcessId, sizeof(dwProcessId));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// TerminateProcess
BOOL WINAPI HookedTerminateProcess(
	HANDLE hProcess,
	UINT uExitCode
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedTerminateProcess);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = TerminateProcess(hProcess, uExitCode);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hProcess, sizeof(hProcess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&uExitCode, sizeof(uExitCode));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// ResumeThread
DWORD WINAPI HookedResumeThread(
	HANDLE hThread
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedResumeThread);
	if (hook_info_node == NULL) {
		return (DWORD)-1;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	DWORD result = ResumeThread(hThread);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hThread, sizeof(hThread));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// SuspendThread
DWORD WINAPI HookedSuspendThread(
	HANDLE hThread
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedSuspendThread);
	if (hook_info_node == NULL) {
		return (DWORD)-1;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	DWORD result = SuspendThread(hThread);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hThread, sizeof(hThread));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// ReadProcessMemory
BOOL WINAPI HookedReadProcessMemory(
	HANDLE hProcess,
	LPCVOID lpBaseAddress,
	LPVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesRead
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedReadProcessMemory);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hProcess, sizeof(hProcess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpBaseAddress, sizeof(LPCVOID));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpBuffer, sizeof(LPVOID));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&nSize, sizeof(nSize));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpNumberOfBytesRead, sizeof(SIZE_T*));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// WriteProcessMemory
BOOL WINAPI HookedWriteProcessMemory(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedWriteProcessMemory);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hProcess, sizeof(hProcess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpBaseAddress, sizeof(LPVOID));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpBuffer, sizeof(LPCVOID));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&nSize, sizeof(nSize));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpNumberOfBytesWritten, sizeof(SIZE_T*));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}
// VirtualAllocEx
LPVOID WINAPI HookedVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedVirtualAllocEx);
	if (hook_info_node == NULL) {
		return NULL;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	LPVOID result = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hProcess, sizeof(hProcess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpAddress, sizeof(lpAddress));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwSize, sizeof(dwSize));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&flAllocationType, sizeof(flAllocationType));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&flProtect, sizeof(flProtect));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// VirtualFreeEx
BOOL WINAPI HookedVirtualFreeEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedVirtualFreeEx);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hProcess, sizeof(hProcess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpAddress, sizeof(lpAddress));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwSize, sizeof(dwSize));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwFreeType, sizeof(dwFreeType));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// DuplicateHandle
BOOL WINAPI HookedDuplicateHandle(
	HANDLE hSourceProcessHandle,
	HANDLE hSourceHandle,
	HANDLE hTargetProcessHandle,
	LPHANDLE lpTargetHandle,
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwOptions
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedDuplicateHandle);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hSourceProcessHandle, sizeof(hSourceProcessHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hSourceHandle, sizeof(hSourceHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hTargetProcessHandle, sizeof(hTargetProcessHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpTargetHandle, sizeof(LPHANDLE));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwDesiredAccess, sizeof(dwDesiredAccess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&bInheritHandle, sizeof(bInheritHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwOptions, sizeof(dwOptions));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// GetThreadContext
BOOL WINAPI HookedGetThreadContext(
	HANDLE hThread,
	LPCONTEXT lpContext
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedGetThreadContext);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = GetThreadContext(hThread, lpContext);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hThread, sizeof(hThread));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpContext, sizeof(LPCONTEXT));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// SetThreadContext
BOOL WINAPI HookedSetThreadContext(
	HANDLE hThread,
	CONST CONTEXT* lpContext
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedSetThreadContext);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = SetThreadContext(hThread, lpContext);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hThread, sizeof(hThread));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpContext, sizeof(CONST CONTEXT*));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// ���μ��� �� ������ ���� 

// AdjustTokenPrivileges
BOOL WINAPI HookedAdjustTokenPrivileges(
	HANDLE TokenHandle,
	BOOL DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD ReturnLength
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedAdjustTokenPrivileges);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&TokenHandle, sizeof(TokenHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&DisableAllPrivileges, sizeof(DisableAllPrivileges));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)NewState, sizeof(PTOKEN_PRIVILEGES));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&BufferLength, sizeof(BufferLength));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)PreviousState, sizeof(PTOKEN_PRIVILEGES));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)ReturnLength, sizeof(PDWORD));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// OpenProcessToken
BOOL WINAPI HookedOpenProcessToken(
	HANDLE ProcessHandle,
	DWORD DesiredAccess,
	PHANDLE TokenHandle
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedOpenProcessToken);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&ProcessHandle, sizeof(ProcessHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&DesiredAccess, sizeof(DesiredAccess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)TokenHandle, sizeof(PHANDLE));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// NtReadFile (NTAPI)
NTSTATUS NTAPI HookedNtReadFile(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedNtReadFile);
	if (hook_info_node == NULL) {
		return 1;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	NTSTATUS result = ((pNtReadFile)hook_info_node->API_ADDRESS)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&FileHandle, sizeof(FileHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&Event, sizeof(Event));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)ApcRoutine, sizeof(ApcRoutine));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)ApcContext, sizeof(ApcContext));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)IoStatusBlock, sizeof(IoStatusBlock));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)Buffer, sizeof(Buffer));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&Length, sizeof(Length));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)ByteOffset, sizeof(ByteOffset));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)Key, sizeof(Key));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// NtWriteFile (NTAPI)
NTSTATUS NTAPI HookedNtWriteFile(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedNtWriteFile);
	if (hook_info_node == NULL) {
		return 1;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	NTSTATUS result = ((pNtWriteFile)hook_info_node->API_ADDRESS)(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&FileHandle, sizeof(FileHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&Event, sizeof(Event));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)ApcRoutine, sizeof(ApcRoutine));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)ApcContext, sizeof(ApcContext));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)IoStatusBlock, sizeof(IoStatusBlock));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)Buffer, sizeof(Buffer));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&Length, sizeof(Length));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)ByteOffset, sizeof(ByteOffset));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)Key, sizeof(Key));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// NtQueryInformationFile (NTAPI)
NTSTATUS NTAPI HookedNtQueryInformationFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedNtQueryInformationFile);
	if (hook_info_node == NULL) {
		return 1;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	NTSTATUS result = ((pNtQueryInformationFile)hook_info_node->API_ADDRESS)(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&FileHandle, sizeof(FileHandle));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)IoStatusBlock, sizeof(IoStatusBlock));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)FileInformation, sizeof(FileInformation));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&Length, sizeof(Length));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&FileInformationClass, sizeof(FileInformationClass));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// CreateFile
HANDLE WINAPI HookedCreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedCreateFileA);
	if (hook_info_node == NULL) {
		return INVALID_HANDLE_VALUE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);
	
	HANDLE result = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpFileName, sizeof(lpFileName));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwDesiredAccess, sizeof(dwDesiredAccess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwShareMode, sizeof(dwShareMode));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpSecurityAttributes, sizeof(lpSecurityAttributes));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwCreationDisposition, sizeof(dwCreationDisposition));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwFlagsAndAttributes, sizeof(dwFlagsAndAttributes));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hTemplateFile, sizeof(hTemplateFile));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// HookedCreateFileW �Լ� ����
HANDLE WINAPI HookedCreateFileW(
	LPCWSTR lpFileName,                // ���� �̸�
	DWORD dwDesiredAccess,            // ���� ���� ����
	DWORD dwShareMode,                // ���� ���� ���
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, // ���� �Ӽ�
	DWORD dwCreationDisposition,      // ���� ���� ����
	DWORD dwFlagsAndAttributes,       // ���� �Ӽ�
	HANDLE hTemplateFile              // ���ø� ���� �ڵ�
)
{
	// ��ġ�� API_LIST ��������
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedCreateFileW);
	if (hook_info_node == NULL) {
		return INVALID_HANDLE_VALUE;
	}

	// ����
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);

	// ���� API ȣ��
	HANDLE hFile = CreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	// ��ŷ ���� ������ �غ�
	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	// �Ķ���� ���� �Ҵ�
	PHOOK_API_Parameters tmp_START_ADDR = NULL;
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpFileName, sizeof(lpFileName));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwDesiredAccess, sizeof(dwDesiredAccess));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwShareMode, sizeof(dwShareMode));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lpSecurityAttributes, sizeof(lpSecurityAttributes));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwCreationDisposition, sizeof(dwCreationDisposition));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwFlagsAndAttributes, sizeof(dwFlagsAndAttributes));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hTemplateFile, sizeof(hTemplateFile));

	// IOCTL ����
	SEND_IOCTL(&DATA);

	// ��ŷ �缳��
	Set_Hook(hook_info_node);

	// ���� ����
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return hFile;
}

// ReadFile
BOOL WINAPI HookedReadFile(
	HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedReadFile);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hFile, sizeof(hFile));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpBuffer, sizeof(lpBuffer));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&nNumberOfBytesToRead, sizeof(nNumberOfBytesToRead));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpNumberOfBytesRead, sizeof(LPDWORD));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpOverlapped, sizeof(lpOverlapped));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// WriteFile
BOOL WINAPI HookedWriteFile(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedWriteFile);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hFile, sizeof(hFile));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpBuffer, sizeof(lpBuffer));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&nNumberOfBytesToWrite, sizeof(nNumberOfBytesToWrite));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpNumberOfBytesWritten, sizeof(LPDWORD));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpOverlapped, sizeof(lpOverlapped));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// SetWindowsHookEx
HHOOK WINAPI HookedSetWindowsHookEx(
	int idHook,
	HOOKPROC lpfn,
	HINSTANCE hMod,
	DWORD dwThreadId
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedSetWindowsHookEx);
	if (hook_info_node == NULL) {
		return NULL;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	HHOOK result = SetWindowsHookEx(idHook, lpfn, hMod, dwThreadId);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&idHook, sizeof(idHook));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)lpfn, sizeof(lpfn));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hMod, sizeof(hMod));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&dwThreadId, sizeof(dwThreadId));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// SendMessage
LRESULT WINAPI HookedSendMessage(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedSendMessage);
	if (hook_info_node == NULL) {
		return 0;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	LRESULT result = SendMessage(hWnd, Msg, wParam, lParam);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hWnd, sizeof(hWnd));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&Msg, sizeof(Msg));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&wParam, sizeof(wParam));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lParam, sizeof(lParam));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// PostMessage
BOOL WINAPI HookedPostMessage(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam
)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)HookedPostMessage);
	if (hook_info_node == NULL) {
		return FALSE;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	BOOL result = PostMessage(hWnd, Msg, wParam, lParam);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&hWnd, sizeof(hWnd));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&Msg, sizeof(Msg));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&wParam, sizeof(wParam));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&lParam, sizeof(lParam));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// malloc
void* Hookedmalloc(size_t size)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedmalloc);
	if (hook_info_node == NULL) {
		return NULL;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	void* result = malloc(size);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&size, sizeof(size));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// calloc
void* Hookedcalloc(size_t num, size_t size)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedcalloc);
	if (hook_info_node == NULL) {
		return NULL;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	void* result = calloc(num, size);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&num, sizeof(num));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&size, sizeof(size));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// realloc
void* Hookedrealloc(void* ptr, size_t size)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedrealloc);
	if (hook_info_node == NULL) {
		return NULL;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	void* result = realloc(ptr, size);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&ptr, sizeof(ptr));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&size, sizeof(size));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// free
void Hookedfree(void* ptr)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedfree);
	if (hook_info_node == NULL) {
		return;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	free(ptr);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&ptr, sizeof(ptr));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);
}

// fopen
FILE* Hookedfopen(const char* filename, const char* mode)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedfopen);
	if (hook_info_node == NULL) {
		return NULL;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	FILE* result = fopen(filename, mode);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)filename, sizeof(filename));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)mode, sizeof(mode));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// fclose
int Hookedfclose(FILE* stream)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedfclose);
	if (hook_info_node == NULL) {
		return EOF;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	int result = fclose(stream);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&stream, sizeof(stream));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// fread
size_t Hookedfread(void* ptr, size_t size, size_t count, FILE* stream)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedfread);
	if (hook_info_node == NULL) {
		return 0;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	size_t result = fread(ptr, size, count, stream);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&ptr, sizeof(ptr));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&size, sizeof(size));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&count, sizeof(count));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&stream, sizeof(stream));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}

// fwrite
size_t Hookedfwrite(const void* ptr, size_t size, size_t count, FILE* stream)
{
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedfwrite);
	if (hook_info_node == NULL) {
		return 0;
	}

	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);
	Set_TurnBack(hook_info_node);

	size_t result = fwrite(ptr, size, count, stream);

	HOOK_IOCTL_DATA DATA = { 0 };
	DATA.PID = (HANDLE)GetCurrentProcessId();
	memcpy(DATA.Hooked_API_NAME, hook_info_node->API_NAME, strlen((PCHAR)hook_info_node->API_NAME) + 1);

	DATA.Start_Address = NULL;
	PHOOK_API_Parameters tmp_START_ADDR = NULL;

	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&ptr, sizeof(ptr));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&size, sizeof(size));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&count, sizeof(count));
	DATA.Start_Address = ALL_in_One_HOOK_API_Parm_MAKE_NODE(&tmp_START_ADDR, (PUCHAR)&stream, sizeof(stream));

	SEND_IOCTL(&DATA);
	Set_Hook(hook_info_node);
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	return result;
}


void Hookedexit(int status) {
	// ��ġ�� API_LIST ��������
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedexit);
	if (hook_info_node == NULL) {
		return; // ��ũ ������ ������ �׳� ����
	}

	// ����
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);

	// ��ũ ����
	printf("��ũ ����: exit\n");

	// ���� exit ȣ��
	Set_TurnBack(hook_info_node);
	exit(status);  // ���� ���� exit ȣ��

	// ��ũ ����
	Set_Hook(hook_info_node);

	// ���� ����
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	// ��ũ ����
	printf("��ũ ����: exit\n");
}

void Hookedabort(void) {
	// ��ġ�� API_LIST ��������
	PAPI_LIST hook_info_node = match_original_API_address_and_Hook_API_address((PUCHAR)Hookedabort);
	if (hook_info_node == NULL) {
		return; // ��ũ ������ ������ �׳� ����
	}

	// ����
	WaitForSingleObject(hook_info_node->HOOK_info.MUTEX_HANDLE, INFINITE);

	// ��ũ ����
	printf("��ũ ����: abort\n");

	// ���� abort ȣ��
	Set_TurnBack(hook_info_node);
	abort();  // ���� ���� abort ȣ��

	// ��ũ ����
	Set_Hook(hook_info_node);

	// ���� ����
	ReleaseMutex(hook_info_node->HOOK_info.MUTEX_HANDLE);

	// ��ũ ����
	printf("��ũ ����: abort\n");
}
