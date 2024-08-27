#define _CRT_SECURE_NO_WARNINGS // freopen

#define HOOK_TYPE_MINHOOK 0				// body
#define HOOK_TYPE_PATCH_FUNC 1			// body
#define HOOK_TYPE_DEFAULT_CALL_HOOK 2	// calls
#define HOOK_TYPE_PLUGIN_SDK 3			// calls

#define HOOK_TYPE HOOK_TYPE_PATCH_FUNC //-------------------- 4 change


#include <Windows.h>
#include <iostream>

#if (HOOK_TYPE == HOOK_TYPE_MINHOOK)
	#include "MinHook.h"
	#pragma comment(lib, "minhook.x32.lib")
	MH_STATUS Hook;
	typedef void(__cdecl* DrawRadarFunc)();
	DrawRadarFunc OriginalDrawRadar = nullptr;
#elif (HOOK_TYPE == HOOK_TYPE_PATCH_FUNC)
	void* OriginalDrawRadar = nullptr; //  ((void(__cdecl*)())OriginalDrawRadar)();
	SIZE_T BytesWrittenHookedFunc = 0; // +w flag
	char OriginalBytesHookedFunc[6] = {};
	inline static void* InstallHook(void* pAddr, void* pHookedFunc)
	{
		if (!pAddr) { return NULL; }
		// read orig bytes
		SIZE_T bytesRead = 0;
		ReadProcessMemory(GetCurrentProcess(), pAddr, OriginalBytesHookedFunc, 6, &bytesRead);
		// prepare patch
		char patch[6] = { 0 };
		memcpy_s(patch, 1, "\x68", 1); // [push pHookFunc] Insert 'push' instruction to store the function address on the stack
		memcpy_s(patch + 1, 4, &pHookedFunc, 4); // Write the address of the target function to be called
		memcpy_s(patch + 5, 1, "\xC3", 1); // [ret] End the patch with 'ret' to transfer control to the function address on the stack (instead of 'call')
		// set patch
		WriteProcessMemory(GetCurrentProcess(), pAddr, patch, sizeof(patch), &BytesWrittenHookedFunc);
		return pAddr;
	}
	inline static void DisableHook(void* pAddr)
	{
		WriteProcessMemory(GetCurrentProcess(), pAddr, OriginalBytesHookedFunc, sizeof(OriginalBytesHookedFunc), &BytesWrittenHookedFunc); // unpatch
		BytesWrittenHookedFunc = 0;
	}
#elif ((HOOK_TYPE == HOOK_TYPE_DEFAULT_CALL_HOOK) ||  (HOOK_TYPE == HOOK_TYPE_PLUGIN_SDK))
	#if (HOOK_TYPE == HOOK_TYPE_PLUGIN_SDK)
		#include "plugin.h"
		using namespace plugin;
	#endif
	void* OriginalDrawRadar = nullptr; //  ((void(__cdecl*)())OriginalDrawRadar)();
	inline static void* CalcPointer(void* op_addr, uintptr_t offset, int op_len = 1)
	{
		return (void*)((uintptr_t)op_addr + op_len + sizeof(uintptr_t) + offset);
	}
	inline static void* CalcOffset(void* op_addr, void* to, int op_len = 1)
	{
		return (void*)((uintptr_t)to - (uintptr_t)op_addr - sizeof(op_addr) - op_len);
	}
#endif

// 1.0
#define pDrawRadarFunc 0x58A330
#define pDrawRadarCall 0x58FC53

void __cdecl Hook_DrawRadar()
{
	std::cout << "Hooked" << "\n";
	// do not call pDrawRadarFunc otherwise recursion will occur
#if (HOOK_TYPE != HOOK_TYPE_MINHOOK)
	#if (HOOK_TYPE == HOOK_TYPE_PATCH_FUNC)
		DisableHook((void*)pDrawRadarFunc); // fix orig func 4 call
	#endif
	if (OriginalDrawRadar) { ((void(__cdecl*)())OriginalDrawRadar)(); } // void __cdecl CHud::DrawRadar() 0x58A330
	#if (HOOK_TYPE == HOOK_TYPE_PATCH_FUNC)
		InstallHook((void*)pDrawRadarFunc, Hook_DrawRadar); // rehook after fix and call
	#endif
#endif
}

void InstallHooks()
{
	std::cout << "InstallHooks()" << "\n";
#if (HOOK_TYPE == HOOK_TYPE_MINHOOK)
	if (MH_Initialize() != MH_OK) { return; }

	MH_CreateHook((void*)pDrawRadarFunc, &Hook_DrawRadar, (LPVOID*)(&OriginalDrawRadar));
	MH_EnableHook((void*)pDrawRadarFunc);
#elif (HOOK_TYPE == HOOK_TYPE_PATCH_FUNC)
	//https://github.com/matthieu-hackwitharts/Win32_Offensive_Cheatsheet/blob/main/hooking/inline.cpp
	InstallHook((void*)pDrawRadarFunc, Hook_DrawRadar);
	OriginalDrawRadar = (void*)pDrawRadarFunc; // or use pDrawRadarFunc only
#elif (HOOK_TYPE == HOOK_TYPE_DEFAULT_CALL_HOOK)
	OriginalDrawRadar = CalcPointer((void*)pDrawRadarCall, *(uintptr_t*)(pDrawRadarCall + 1)); // +1 0xE8 call (compatibility!!)
	DWORD oldProtect;
	VirtualProtect((void*)(pDrawRadarCall + 1), sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
	*(uintptr_t*)(pDrawRadarCall + 1) = (uintptr_t)CalcOffset((void*)pDrawRadarCall, Hook_DrawRadar);
	VirtualProtect((void*)(pDrawRadarCall + 1), sizeof(uintptr_t), oldProtect, &oldProtect);
#elif (HOOK_TYPE == HOOK_TYPE_PLUGIN_SDK)
	OriginalDrawRadar = CalcPointer((void*)pDrawRadarCall, plugin::patch::GetUInt(pDrawRadarCall + 1)); // +1 0xE8 call (compatibility!!)
	plugin::patch::RedirectCall(pDrawRadarCall, Hook_DrawRadar);
#endif
}

// entry
#if (HOOK_TYPE == HOOK_TYPE_PLUGIN_SDK)
class gtaSA_HookExample {
public:
	gtaSA_HookExample() {
		AllocConsole();
		freopen("CONOUT$", "w", stdout); // mb printf?
		InstallHooks();
	}
} _gtaSA_HookExample;
#else
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		AllocConsole();
		freopen("CONOUT$", "w", stdout); // mb printf?
		InstallHooks();
	}
	return TRUE;
}
#endif