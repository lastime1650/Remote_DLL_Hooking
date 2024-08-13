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


	// 상대 프로세스 접근 관련 후킹 

	// 프로세스 핸들 및 스레드 접근

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
		LPCSTR lpApplicationName,        // 애플리케이션 이름
		LPSTR lpCommandLine,             // 명령 줄
		LPSECURITY_ATTRIBUTES lpProcessAttributes, // 프로세스 보안 속성
		LPSECURITY_ATTRIBUTES lpThreadAttributes,  // 스레드 보안 속성
		BOOL bInheritHandles,            // 핸들 상속 여부
		DWORD dwCreationFlags,           // 프로세스 생성 플래그
		LPVOID lpEnvironment,            // 환경 변수
		LPCSTR lpCurrentDirectory,       // 현재 작업 디렉터리
		LPSTARTUPINFOA lpStartupInfo,     // 시작 정보
		LPPROCESS_INFORMATION lpProcessInformation // 프로세스 정보
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

	// 메모리 조작 

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

	// 핸들 조작 

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

	// 프로세스 및 스레드 보안 

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

	// 데이터 복사 및 파일 조작 
	
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
		LPCSTR lpFileName,                   // 파일 이름
		DWORD dwDesiredAccess,               // 접근 권한
		DWORD dwShareMode,                   // 공유 모드
		LPSECURITY_ATTRIBUTES lpSecurityAttributes, // 보안 속성
		DWORD dwCreationDisposition,         // 생성 조건
		DWORD dwFlagsAndAttributes,           // 파일 속성
		HANDLE hTemplateFile                 // 템플릿 파일 핸들
	);

	HANDLE WINAPI HookedCreateFileW(
		LPCWSTR lpFileName,                // 파일 이름
		DWORD dwDesiredAccess,            // 파일 접근 권한
		DWORD dwShareMode,                // 파일 공유 모드
		LPSECURITY_ATTRIBUTES lpSecurityAttributes, // 보안 속성
		DWORD dwCreationDisposition,      // 파일 생성 조건
		DWORD dwFlagsAndAttributes,       // 파일 속성
		HANDLE hTemplateFile              // 템플릿 파일 핸들
	);

	BOOL HookedReadFile(
		HANDLE hFile,                       // 파일 핸들
		LPVOID lpBuffer,                   // 읽은 데이터를 저장할 버퍼
		DWORD nNumberOfBytesToRead,        // 읽을 바이트 수
		LPDWORD lpNumberOfBytesRead,       // 실제로 읽은 바이트 수
		LPOVERLAPPED lpOverlapped          // 비동기 I/O를 위한 구조체
	);


	BOOL HookedWriteFile(
		HANDLE hFile,                       // 파일 핸들
		LPCVOID lpBuffer,                  // 쓸 데이터
		DWORD nNumberOfBytesToWrite,       // 쓸 바이트 수
		LPDWORD lpNumberOfBytesWritten,    // 실제로 쓴 바이트 수
		LPOVERLAPPED lpOverlapped          // 비동기 I/O를 위한 구조체
	);


	// 기타

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