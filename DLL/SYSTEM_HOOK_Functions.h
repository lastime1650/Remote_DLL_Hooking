#ifndef SYSTEM_HOOK_Functions_H
#define SYSTEM_HOOK_Functions_H
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <cstdlib>
#include "API_ADDRESSES_LINKED_LIST.h"
#include "Start_Hook.h"
#include "Hooked_IOCTL.h"
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif


	// ��� ���μ��� ���� ���� ��ŷ 

	// ���μ��� �ڵ� �� ������ ����

	// CreateRemoteThread
	HANDLE WINAPI HookedCreateRemoteThread(
		HANDLE hProcess,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		SIZE_T dwStackSize,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		DWORD dwCreationFlags,
		LPDWORD lpThreadId
	);

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
	);

	// CreateProcessW
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
	);

	// OpenProcess
	HANDLE WINAPI HookedOpenProcess(
		DWORD dwDesiredAccess,
		BOOL bInheritHandle,
		DWORD dwProcessId
	);

	// TerminateProcess
	BOOL WINAPI HookedTerminateProcess(
		HANDLE hProcess,
		UINT uExitCode
	);

	//Resume
	DWORD HookedResumeThread(
		HANDLE hThread
	);

	// SuspendThread
	DWORD WINAPI HookedSuspendThread(
		HANDLE hThread
	);

	// �޸� ���� 

	// ReadProcessMemory
	BOOL WINAPI HookedReadProcessMemory(
		HANDLE hProcess,
		LPCVOID lpBaseAddress,
		LPVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesRead
	);

	// WriteProcessMemory
	BOOL WINAPI HookedWriteProcessMemory(
		HANDLE hProcess,
		LPVOID lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesWritten
	);

	// VirtualAllocEx
	LPVOID WINAPI HookedVirtualAllocEx(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD flAllocationType,
		DWORD flProtect
	);

	// VirtualFreeEx
	BOOL WINAPI HookedVirtualFreeEx(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD dwFreeType
	);

	// �ڵ� ���� 

	// DuplicateHandle
	BOOL WINAPI HookedDuplicateHandle(
		HANDLE hSourceProcessHandle,
		HANDLE hSourceHandle,
		HANDLE hTargetProcessHandle,
		LPHANDLE lpTargetHandle,
		DWORD dwDesiredAccess,
		BOOL bInheritHandle,
		DWORD dwOptions
	);

	// GetThreadContext
	BOOL WINAPI HookedGetThreadContext(
		HANDLE hThread,
		LPCONTEXT lpContext
	);

	// SetThreadContext
	BOOL WINAPI HookedSetThreadContext(
		HANDLE hThread,
		CONST CONTEXT* lpContext
	);

	// ���μ��� �� ������ ���� 

	// AdjustTokenPrivileges
	BOOL WINAPI HookedAdjustTokenPrivileges(
		HANDLE TokenHandle,
		BOOL DisableAllPrivileges,
		PTOKEN_PRIVILEGES NewState,
		DWORD BufferLength,
		PTOKEN_PRIVILEGES PreviousState,
		PDWORD ReturnLength
	);

	// OpenProcessToken
	BOOL WINAPI HookedOpenProcessToken(
		HANDLE ProcessHandle,
		DWORD DesiredAccess,
		PHANDLE TokenHandle
	);

	// ������ ���� �� ���� ���� 
	
	// NtReadFile (NTAPI)
	typedef NTSTATUS(NTAPI* pNtReadFile)(
		HANDLE FileHandle,
		HANDLE Event,
		PIO_APC_ROUTINE ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key
		);

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
	);

	// NtWriteFile (NTAPI)
	typedef NTSTATUS(NTAPI* pNtWriteFile)(
		HANDLE FileHandle,
		HANDLE Event,
		PIO_APC_ROUTINE ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID Buffer,
		ULONG Length,
		PLARGE_INTEGER ByteOffset,
		PULONG Key
		);

	
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
	);

	// NtQueryInformationFile (NTAPI)
	typedef NTSTATUS(NTAPI* pNtQueryInformationFile)(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG Length,
		FILE_INFORMATION_CLASS FileInformationClass
		);

	NTSTATUS NTAPI HookedNtQueryInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG Length,
		FILE_INFORMATION_CLASS FileInformationClass
	);

	// CreateFile
	HANDLE HookedCreateFileA(
		LPCSTR lpFileName,                   // ���� �̸�
		DWORD dwDesiredAccess,               // ���� ����
		DWORD dwShareMode,                   // ���� ���
		LPSECURITY_ATTRIBUTES lpSecurityAttributes, // ���� �Ӽ�
		DWORD dwCreationDisposition,         // ���� ����
		DWORD dwFlagsAndAttributes,           // ���� �Ӽ�
		HANDLE hTemplateFile                 // ���ø� ���� �ڵ�
	);

	HANDLE WINAPI HookedCreateFileW(
		LPCWSTR lpFileName,                // ���� �̸�
		DWORD dwDesiredAccess,            // ���� ���� ����
		DWORD dwShareMode,                // ���� ���� ���
		LPSECURITY_ATTRIBUTES lpSecurityAttributes, // ���� �Ӽ�
		DWORD dwCreationDisposition,      // ���� ���� ����
		DWORD dwFlagsAndAttributes,       // ���� �Ӽ�
		HANDLE hTemplateFile              // ���ø� ���� �ڵ�
	);

	BOOL HookedReadFile(
		HANDLE hFile,                       // ���� �ڵ�
		LPVOID lpBuffer,                   // ���� �����͸� ������ ����
		DWORD nNumberOfBytesToRead,        // ���� ����Ʈ ��
		LPDWORD lpNumberOfBytesRead,       // ������ ���� ����Ʈ ��
		LPOVERLAPPED lpOverlapped          // �񵿱� I/O�� ���� ����ü
	);


	BOOL HookedWriteFile(
		HANDLE hFile,                       // ���� �ڵ�
		LPCVOID lpBuffer,                  // �� ������
		DWORD nNumberOfBytesToWrite,       // �� ����Ʈ ��
		LPDWORD lpNumberOfBytesWritten,    // ������ �� ����Ʈ ��
		LPOVERLAPPED lpOverlapped          // �񵿱� I/O�� ���� ����ü
	);


	// ��Ÿ

	// SetWindowsHookEx
	HHOOK WINAPI HookedSetWindowsHookEx(
		int idHook,
		HOOKPROC lpfn,
		HINSTANCE hMod,
		DWORD dwThreadId
	);

	// SendMessage
	LRESULT WINAPI HookedSendMessage(
		HWND hWnd,
		UINT Msg,
		WPARAM wParam,
		LPARAM lParam
	);

	// PostMessage
	BOOL WINAPI HookedPostMessage(
		HWND hWnd,
		UINT Msg,
		WPARAM wParam,
		LPARAM lParam
	);

	// Basic API

	void* Hookedmalloc(size_t size);

	void* Hookedcalloc(size_t num, size_t size);

	void* Hookedrealloc(void* ptr, size_t size);

	void Hookedfree(void* ptr);

	FILE* Hookedfopen(const char* filename, const char* mode);

	int Hookedfclose(FILE* stream);

	size_t Hookedfread(void* ptr, size_t size, size_t count, FILE* stream);

	size_t Hookedfwrite(const void* ptr, size_t size, size_t count, FILE* stream);

	void Hookedexit(int status);

	void Hookedabort(void);

#ifdef __cplusplus
}
#endif


#endif