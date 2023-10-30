#include <Windows.h>
#include <detours.h>

#include <string>

#include "../hooking_common.h"

const uint32_t drawSettingsRVA = 0x35C0D0;
const uint32_t singlePlayerButton_clickedRVA = 0x362E10;

int NewSettings()
{
	exit(0);
	return 0;
}

void InstallHook(void* func2hook, void* payloadFunction)
{
	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	//32 bit relative jump opcode is E9, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of jmpInstruction, we need the offset between 
	//the payload function and the instruction immediately AFTER the jmp instruction
	const uint32_t relAddr = (uint32_t)payloadFunction - ((uint32_t)func2hook + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);

	//install the hook
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
}

void* GetFunc2HookAddr()
{
	uint32_t functionRVA = 0x35C0D0;
	uint32_t func2HookAddr = (uint32_t)GetBaseModuleForProcess(GetCurrentProcess()) + functionRVA;
	return (void*)func2HookAddr;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID lpvReserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		__try {
			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			LONG res = DetourAttach((PVOID*)singlePlayerButton_clickedRVA, NewSettings);
			MessageBox(NULL, std::to_string(res).c_str(), "", 0);
			if (res == NOERROR)
				DetourTransactionCommit();
			else
			{

				DetourTransactionAbort();
				MessageBox(NULL, std::to_string(res).c_str(), "", 0);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// 捕获并处理异常
			// 异常信息可以在GetExceptionCode和GetExceptionInformation中获取
			DWORD exceptionCode = GetExceptionCode();
			//void* exceptionInfo = GetExceptionInformation();

			// 显示异常消息
			std::string errorMsg = "异常代码: " + std::to_string(exceptionCode);
			MessageBoxA(nullptr, errorMsg.c_str(), "异常消息", MB_ICONERROR);

		}

		//MessageBox(NULL, "Process attach!", "Inject All The Things!", 0);
		//HMODULE gdiPlusModule = FindModuleInProcess(GetCurrentProcess(), ("gdiplus.dll"));
		//void* localHookFunc4 = GetProcAddress(gdiPlusModule, ("GdipSetSolidFillColor"));
		//InstallHook(GetFunc2HookAddr(), NewSettings);
	}
	return true;
}
