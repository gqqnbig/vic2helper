#include <Windows.h>
#include <detours.h>

#include <string>

#include "../hooking_common.h"

const uint32_t drawSettingsRVA = 0x35C0D0;
auto singlePlayerButton_clickedRVA = reinterpret_cast<int (* const)(int th)>(0x362E10);

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

void SetStdOutToNewConsole()
{
	FILE* fpFile;
	AllocConsole(); // or AttachConsole(ATTACH_PARENT_PROCESS); // if parent has one
	freopen_s(&fpFile, "CONOUT$", "w", stdout); // redirect stdout to console
	freopen_s(&fpFile, "CONOUT$", "w", stderr); // redirect stderr to console
	freopen_s(&fpFile, "CONIN$", "r", stdin); // redirect stdin to console
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD ul_reason_for_call, LPVOID lpvReserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		SetStdOutToNewConsole();
		printf("Start hooking\n");
		__try {
			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());

			uint32_t func2HookAddr = (uint32_t)GetBaseModuleForProcess(GetCurrentProcess()) + reinterpret_cast<uint32_t>(singlePlayerButton_clickedRVA);

			LONG res = DetourAttach(&(PVOID&)func2HookAddr, NewSettings);
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
			std::string errorMsg = "Error code: " + std::to_string(exceptionCode);
			MessageBox(nullptr, errorMsg.c_str(), "Hooking Failed", MB_ICONERROR);

		}

		//MessageBox(NULL, "Process attach!", "Inject All The Things!", 0);
		//HMODULE gdiPlusModule = FindModuleInProcess(GetCurrentProcess(), ("gdiplus.dll"));
		//void* localHookFunc4 = GetProcAddress(gdiPlusModule, ("GdipSetSolidFillColor"));
		//InstallHook(GetFunc2HookAddr(), NewSettings);
	}
	return true;
}
