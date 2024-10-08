# Remote_DLL_Hooking ( feat. IOCTL )

이 레포지토리는 [C_PROTEGO_자체개발 엔드포인트 보안솔루션 레포지토리에 속하는 내용입니다.](https://github.com/lastime1650/C.ProtegoAI)

DLL 파트만 유심히 보면 될 것 같습니다. 

이 DLL은 CreateRemoteThread API에 의해 실행될 때 구동되는 것으로 시연하였으며, 더욱 다양한 후크 API를 정의하고 있는 상황입니다.

전역 연결리스트를 이용하고, 이를 통해서 후킹함수, 후킹을 위한 어셈블리 바이트, DLL 문자열, API 문자열 등등

[상세 설명은 저의 블로그를 방문해주세요!](https://blog.naver.com/lastime1650/223545928057)

# 2024/08/13

이제 후크된 API는 기존 ( 2024/08/11 ) 정보는 물론, 파라미터 정보까지 전달할 수 있습니다. 

단, 파라미터 전달은 직접 정적코드 구현하여 수동적으로 연결리스트를 만들어야합니다. ( 단, 너무 간단합니다. ) 

# 2024/08/11

이제 후크된 API는 커널 IOCTL요청을 할 수 있어, 로깅이 가능합니다.


<br><br>


# 정의된 후크 함수들 

"MessageBoxA",
"BitBlt",


// 원격 프로세스

"CreateRemoteThread",
"CreateProcessA",
"CreateProcessW",
"OpenProcess",
"TerminateProcess",
"ResumeThread",
"SuspendThread",

// 메모리 조작

"ReadProcessMemory",
"WriteProcessMemory",
"VirtualAllocEx",
"VirtualFreeEx",

// 핸들 조작

"DuplicateHandle",
"GetThreadContext",
"SetThreadContext",

// 프로세스 및 스레드 보안

"AdjustTokenPrivileges",
"OpenProcessToken",

// 데이터 복사 및 파일 조작

"NtReadFile",
"NtWriteFile",
"NtQueryInformationFile",
"CreateFileA",
"CreateFileW",
"ReadFile",
"WriteFile",

// 기타

"SetWindowsHookEx",
"SendMessage",
"PostMessage",

// Basic API

"malloc",
"calloc",
"realloc",
"free",
"fopen",
"fclose",
"fread",
"fwrite",
"exit",
"abort"
