#include "Hooking.h"

CHAR DLL_NAME[] = "C:\\Users\\Administrator\\Desktop\\DLL_INJECTOR_dll.dll";

VOID START_HOOKING(HOOKING_move* PROCESS_CONTEXT) {

	if (PROCESS_CONTEXT->PID <= (HANDLE)1000) return;


	printf("\n��ũ���� ->PID %lu / HANDLE %lu  + OpenProcess -> %lu\n", PROCESS_CONTEXT->PID, PROCESS_CONTEXT->PROCESS_HANDLE, OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESS_CONTEXT->PID));

	HANDLE process_handle = 0;

	// �������� �������� ���μ����� DLL���Խõ� 


	// Ÿ�� ���μ����� DLL ���ڿ� �����Ҵ�
	LPVOID get_allocated_mem_addr = NULL;
	
	
	if((get_allocated_mem_addr = VirtualAllocEx(PROCESS_CONTEXT->PROCESS_HANDLE, NULL, sizeof(DLL_NAME), MEM_COMMIT, PAGE_READWRITE)) != NULL){
		process_handle = PROCESS_CONTEXT->PROCESS_HANDLE;
		printf("1 get_allocated_mem_addr �� ����!\n");
	}
	else if ((get_allocated_mem_addr = VirtualAllocEx(OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESS_CONTEXT->PID), NULL, sizeof(DLL_NAME), MEM_COMMIT, PAGE_READWRITE)) != NULL) {
		process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESS_CONTEXT->PID);
		printf("2 get_allocated_mem_addr �� ����!\n");
	}
	else {
		printf("����!\n");
		return;
	}

	// ����
	if (WriteProcessMemory(process_handle, get_allocated_mem_addr, (LPVOID)DLL_NAME, sizeof(DLL_NAME), NULL) == FALSE) {
		printf("WriteProcessMemory �� FALSE!\n");
		return;
	}


	// DLL �ε��� �ּ� �˾Ƴ���
	LPTHREAD_START_ROUTINE LOADLIBRARYW_ADDR = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	// ������ ����
	HANDLE hThread = CreateRemoteThread(process_handle, NULL, 0, LOADLIBRARYW_ADDR, get_allocated_mem_addr, 0, NULL);
	//if (hThread == 0) return;
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	printf("\nworked!\n");



	return;
}