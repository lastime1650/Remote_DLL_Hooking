# Remote_DLL_Hooking

이 레포지토리는 [C_PROTEGO_자체개발 엔드포인트 보안솔루션 레포지토리에 속하는 내용입니다.](https://github.com/lastime1650/C.ProtegoAI)

DLL 파트만 유심히 보면 될 것 같습니다. 

이 DLL은 CreateRemoteThread API에 의해 실행될 때 구동되는 것으로 시연하였으며, MessageBoxA에 대한 것에만 후크 함수가 구현되어 있습니다. 

전역 연결리스트를 이용하고, 이를 통해서 후킹함수, 후킹을 위한 어셈블리 바이트, DLL 문자열, API 문자열 등등
