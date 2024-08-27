#pragma once
#include "Windows.h" // ƒл€ VirtualProtect
#include <iostream>
#include <sstream>
#include "MsgAPI.h"
#include "opcode_len_calc.h"
//#include <cstdint>




/**
* Calculate memory address relatively to another memory.
*
* @param to       Address result relatives to.
* @param address  Address to call/jump code.
*
* @returns        Relative address.
*/
inline static void* Relative(void* to, void* address)
{
	return (void*)((uintptr_t)to - (uintptr_t)address - sizeof(address));
}

inline static void *Relativex86(void* to, void* address)
{
	return (void *)((int)to - (unsigned int)address - sizeof address);
}

/**
* Offsets address at specified bytes count.
*
* @param addr    Address that will be offsetted.
* @param offset  Bytes count.
*
* @returns       Offsetted address.
*/
inline static void* Transpose(void* addr, intptr_t offset, bool deref = false)
{
	auto res = (void*)((intptr_t)addr + offset);

	return deref ? *(void**)res : res;
}

inline static void *Transposex86(void* addr, int offset, bool deref = false)
{
	auto res = (void *)((int)addr + offset);

	return deref ? *(void **)res : res;
}

/**
* Allocated executable heap memory for splicing.
*
* @param uSize   Memory size to allocate.
*
* @returns       Allocated memory.
*/
inline static void *AllocateExecutableMemory(unsigned int uSize)
{
	auto ret = malloc(uSize);
	if (!ret)
		return nullptr;

	DWORD oldProtect;
	if (!VirtualProtect(ret, uSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		return nullptr;

	return ret;
}

/**
* Writes data in memory address.
*
* @param address    Address where value will be written.
* @param value      Data.
*
* @returns          Address offsetted by size of value type.
*/
template<typename T> void* Write(void* address, T value, int offset = 0)
{
	if (address == nullptr)
		XM_Error("Incorrect address.");

	uintptr_t new_address = reinterpret_cast<uintptr_t>(address) + offset;

	DWORD oldProtect;
	if (!VirtualProtect(reinterpret_cast<void*>(new_address), sizeof(T), PAGE_READWRITE, &oldProtect))
		XM_Error("XM_Error while calling VirtualProtect.");

	memcpy(reinterpret_cast<void*>(new_address), &value, sizeof(T));

	VirtualProtect(reinterpret_cast<void*>(new_address), sizeof(T), oldProtect, &oldProtect);

	return reinterpret_cast<void*>(new_address + sizeof(T));
}

template<typename T> void* Writex86(void* address, T value, int offset = 0)
{
	if (address == nullptr)
		XM_Error("Incorrect address.");

	address = (void *)((int)address + offset);

	unsigned long oldProtect;
	if (!VirtualProtect(address, sizeof T, PAGE_READWRITE, &oldProtect))
		XM_Error("XM_Error while calling VirtualProtect.");

	CopyMemory(address, &value, sizeof T);

	VirtualProtect(address, sizeof T, oldProtect, &oldProtect);

	return &((unsigned char *)address)[sizeof T];
}

/**
* Checks value at specified address.
*
* @param address    Address to check.
* @param value      Value.
* @param offset     Offset from address.
*
* @returns          True if address deref value is equal to value from arguments, false otherwise.
*/
template<typename T> bool Check(void* address, T value, int offset = 0)
{
	if (!address)
		return false;

	return *(T *)&((unsigned char *)address)[offset] == value;
}

/**
* Inserts call/jmp instruction at specified address.
*
* @param addrFrom    Call from.
* @param addrTo      Call to.
* @param bIsCall     If true, then 0xE8 (call) will be written, otherwise - 0xE9 (jmp).
*/
static void InsertFunc(void* addrFrom, void* addrTo, bool bIsCall)
{
	if (!addrFrom || !addrTo) { XM_Error("Incorrect arguments."); }

	auto pAddr = Write<unsigned char>(addrFrom, bIsCall ? 0xE8 : 0xE9);
	auto pRelAddr = Relative(addrTo, pAddr);

	Write<void *>(pAddr, pRelAddr);
}

/**
* Inserts jmp instruction at specified address.
*
* @param pFunc    Jump address.
*/
inline static void InsertJump(void* pStart, void* pFunc)
{
	InsertFunc(pStart, pFunc, false);
}

/**
* Inserts call instruction at specified address.
*
* @param pStart   Position to insert opcode.
* @param pFunc    Jump address.
*/
inline static void InsertCall(void* pStart, void* pFunc)
{
	InsertFunc(pStart, pFunc, true);
}

/**
* Writes NOP sled. Pretty slow algo, but legit for single uses.
*
* @param address   Position to write.
* @param count     NOPs count.
*/
inline static void WriteNOPs(void *address, int count)
{
	for (int i = 0; i < count; i++)
	{
		Write<unsigned char>(&((unsigned char *)address)[i], 0x90);
	}
}

/**
* Hooks function.
*
* @param pStart     Function to hook.
* @param pNewFunc   New function.
* @param uCodeSize  NOP sled size.
*
* @returns          Function trampoline.
*/
template <typename T> T HookRegular(void* pStart, T pNewFunc, unsigned int uCodeSize = 0)
{
	if (!pStart)
		XM_Error("Incorrect arguments.");

	if (!pNewFunc)
		return nullptr;

	if (uCodeSize == 0)
	{
		while (uCodeSize < 5)
		{
			auto size = InstructionLength(Transpose(pStart, uCodeSize));

			if (size == 0)
				XM_Error("Could not calculate instruction size.");

			uCodeSize += size;
		}
	}

	auto pTrampoline = AllocateExecutableMemory(sizeof(unsigned char) + sizeof(void *) + uCodeSize);

	if (!pTrampoline)
		XM_Error("Could not allocate memory for trampoline.");

	CopyMemory(pTrampoline, pStart, uCodeSize);
	InsertFunc(Transpose(pTrampoline, uCodeSize), Transpose(pStart, uCodeSize), false);
	InsertFunc(pStart, pNewFunc, false);

	if (uCodeSize > 5)
	{
		auto sled = Transpose(pStart, 5);
		WriteNOPs(sled, uCodeSize - 5);
	}

	return (T)pTrampoline;
}

/**
* Hooks exported function in module.
*
* @param hInstance  Module base address
* @param pszName    Export function name.
* @param pNewFunc   Inserted function address.
*
* @returns          Function trampoline.
*/
template <typename T> T HookExport(HMODULE hInstance, const char* pszName, T pNewFunc, unsigned int uCodeSize = 0)
{
	if (pszName == nullptr || *pszName == '\0' || pNewFunc == nullptr)
		XM_Error("Invalid arguments.");

	auto pFunc = GetProcAddress(hInstance, pszName);
	if (pFunc == NULL)
		XM_Error("Function not found.");

	return HookRegular(pFunc, pNewFunc, uCodeSize);
}








//--------------------------------------DK----MOD

std::string intToHexString(int value, bool ox = true)
{
	std::ostringstream stream;
	if (ox) { stream << "0x"; }
	stream << std::hex << value;// << std::dec;
	return stream.str();
}

//---------DK--MOD 31/08

/**
* Get value at specified address.
*
* @param address    Address to leak.
* @param offset     Offset from address.
*
* @returns          Leak.
*/
template<typename T> T Leak(void* address, int offset = 0)
{
	if (!address)
		return T();

	uintptr_t ptr_value = *reinterpret_cast<uintptr_t*>((reinterpret_cast<unsigned char*>(address) + offset));
	return *reinterpret_cast<T*>(static_cast<unsigned char*>(address) + offset);
}
template<typename T> T Leakx86(void* address, int offset = 0)
{
	if (!address)
		return T();

	return *(T*)&((unsigned char*)address)[offset];
}


uintptr_t VoidPtr2IntPtr(void* _addr) { return reinterpret_cast<uintptr_t>(_addr); }
void* IntPtr2VoidPtr(uintptr_t _addr) { return reinterpret_cast<void*>(_addr); }
template <typename T> T ReadPtrDanger(void* ptr) { return *(static_cast<T*>(ptr)); } //  0x80000001 ERROR NO CATCHABLE
template <typename T> void WriteDanger(void* ptr, const T& value) { (*(static_cast<T*>(ptr))) = value; }




bool CheckPointerBoundsRead(void* pointer) // есть ли такой адрес?
{
	if (!pointer) { return false; }

	MEMORY_BASIC_INFORMATION memInfo;
	if (VirtualQuery(pointer, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
	{
		//if (memInfo.State == MEM_COMMIT && (memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_MAPPED)) { return true; } // ORIG!!!
		//if ((memInfo.State == MEM_COMMIT) && ((memInfo.Protect & PAGE_READWRITE) || (memInfo.Protect & PAGE_READONLY))) { return true; }
		//if ((memInfo.State == MEM_COMMIT) && ((memInfo.Protect & PAGE_READWRITE) || (memInfo.Protect & PAGE_READONLY)) && (memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_MAPPED)) { return true; }

		if (memInfo.State == MEM_COMMIT)
		{
			if (((memInfo.Protect & PAGE_READONLY) ||
				(memInfo.Protect & PAGE_EXECUTE_READ) ||
				(memInfo.Protect & PAGE_EXECUTE_WRITECOPY) ||
				(memInfo.Protect & PAGE_READWRITE) ||
				(memInfo.Protect & PAGE_EXECUTE_READWRITE)) && !(memInfo.Protect & PAGE_GUARD)) // PAGE_GUARD 0x80000001 нельз€ разименовать
			{
				return true;
			}
		}
	}
	return false;
}


template <typename T> bool CheckPointerReadByType(void* ptr) // может ли данный тип там лежать?
{
	int SZ = sizeof(T); // unintptr_t x86 4b, x64 8b
	for (int byte_offset = 0; byte_offset < SZ; byte_offset++) // провер€ем адресацию каждого байта дл€ T типа
	{
		ptr = Transpose(ptr, byte_offset);
		if (!CheckPointerBoundsRead(ptr)) { return false; }
	}
	return true;
}



bool CheckPointerBoundsWrite(void* pointer) // робит
{
	if (!pointer) { return false; }

	MEMORY_BASIC_INFORMATION memInfo;
	if (VirtualQuery(pointer, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
	{
		if (memInfo.State == MEM_COMMIT)
		{
			if (((memInfo.Protect & PAGE_READWRITE) ||
				(memInfo.Protect & PAGE_EXECUTE_READWRITE) ||
				(memInfo.Protect & PAGE_EXECUTE_WRITECOPY)) && !(memInfo.Protect & PAGE_GUARD))
			{
				return true;
			}
		}
	}
	return false;
}


template <typename T> bool CheckPointerWriteByType(void* ptr) // может ли данный тип там лежать?
{
	int SZ = sizeof(T); // unintptr_t x86 4b, x64 8b
	for (int byte_offset = 0; byte_offset < SZ; byte_offset++) // провер€ем адресацию каждого байта дл€ T типа
	{
		ptr = Transpose(ptr, byte_offset);
		if (!CheckPointerBoundsWrite(ptr)) { return false; }
	}
	return true;
}



int GetRegionSizeByPointer(void* ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	//if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) { } // err handler
	VirtualQuery(ptr, &mbi, sizeof(mbi));
	return mbi.RegionSize;
}

void* GetRegionBaseByPointer(void* ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	//if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) { } // err handler
	VirtualQuery(ptr, &mbi, sizeof(mbi));
	return mbi.BaseAddress;
}

MEMORY_BASIC_INFORMATION GetRegionInfoByPointer(void* ptr) // if (mbi.BaseAddress == nullptr) {} err
{
	MEMORY_BASIC_INFORMATION mbi;
	//if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) { } // err handler
	VirtualQuery(ptr, &mbi, sizeof(mbi));
	return mbi;
}


void* CalcPointerFromJMPE9Offset(void* op_addr, int offset) // call offset => pointer func
{
	uintptr_t op_address = (uintptr_t)op_addr;
	uintptr_t dest_address = op_address + 1 + sizeof(uintptr_t) + offset;
	return (void*)dest_address;
}

// op_addr e9, dest pointer
int CalcJMPE9Offset(void* op_addr, void* dest_ptr) // считает офсет дл€ прыжка jmp. можно -значени€, прыгает по офсету после ласт байта инструкции, E9 00 00 00 00 + offset
{
	uintptr_t op_address = (uintptr_t)op_addr;
	uintptr_t dest_address = (uintptr_t)dest_ptr;
	int offset = (int)(dest_address - (op_address + 1 + sizeof(uintptr_t))); // -16 fffffff0 jump upper
	return offset;
}

// переносит exec байты в новую расширенную область через jmp
// sz patch redirect x86 5bytes 1 + 4
// OrigPtr указатель на инструкцию дл€ хука
// OrigSzBlock размер байтов дл€ патча
// PatchSzBlock кол-во байт дл€ патча помиио нужных патчу mysz+ret+sz(void*)
// OutPatchPtr выходной параметр patch sz (на скопированный опкод)
// OutPatchSzBlock выделенный размер (больше чем запрашиваемый)
//jmp_patch_in_end_region false jmp после нашего блока PatchSzBlock, true в конце региона
//offset оффсет переноса кода от начала блока
// !!!!!!!!!!!!!!!!!!!!!!!!!OrigSzBlock минимум 5 байт, не использовать перенос комманд mov jz jmp так как они работачт через оффсет своего адреса
// !!!!!!!!!!!!!!!!!!!!!!!!!если юзаешь mov jz jmp нужно патчить их оффсет
bool SetPatchBlock(void* OrigPtr, int OrigSzBlock, int PatchSzBlock, void*& OutPatchPtr, int& OutPatchSzBlock, bool jmp_patch_in_end_region = false, uintptr_t offset = 0) // !! NO MOVE OFFSETS INSTRUCTIONS (jmp, mov) они раюотают по оффсету из своего адреса
{
	MEMORY_BASIC_INFORMATION mbi_orig = GetRegionInfoByPointer(OrigPtr);
	if (!mbi_orig.RegionSize) { return false; } // cant find base+sz
	if (offset < 0) { return false; }
	DWORD oldProtect_orig;
	bool orig_protect_ch = false; // флаг дл€ возврата оригинальных прав блока
	unsigned char nop = 0x90;
	unsigned char jmp = 0xE9; // прыжок со смещением 4байта (opcode addr + sz(0xE9) + sz(offset) + *offset(*(start+sz(opcode))))
	uintptr_t jmp_sz = (sizeof(unsigned char) + sizeof(void*));
	uintptr_t need_block_sz = (OrigSzBlock + PatchSzBlock + jmp_sz); // orig opcode + patch + jmp

	bool return_orig_protect = true;

	//if (!_CheckPointerReadByType<char>(OrigPtr)) { return; } // no readable
	if (!CheckPointerBoundsRead(OrigPtr)) { return false; } // no readable mini optimize


	//if (!_CheckPointerWriteByType<char>(OrigPtr)) // cant patch
	if (!CheckPointerBoundsWrite(OrigPtr)) // cant patch mini optimize
	{
		//MEMORY_BASIC_INFORMATION mbi = GetRegionInfoByPointer(originalCodeBlock);
		//if (!mbi.RegionSize) { return; } // cant find base+sz
		orig_protect_ch = true;
		VirtualProtect((LPVOID)mbi_orig.BaseAddress, mbi_orig.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect_orig);
	}


	//-------MK PATCH BLOCK
	// patched_block_sz чисто дл€ выделени€ пам€ти, VirtualAlloc даЄт больше пам€ти
	//void* patchBlock = VirtualAlloc(nullptr, need_block_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //(LPVOID) nullptr => random memory
	void* patchBlock = VirtualAlloc(nullptr, need_block_sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //(LPVOID) nullptr => random memory
	if (patchBlock == nullptr) { return false; } // cant create memblock 4 patch
	MEMORY_BASIC_INFORMATION mbi_patched = GetRegionInfoByPointer(patchBlock);

	//DWORD oldProtect_patched; // можно выше установить PAGE_EXECUTE_READWRITE в VirtualAlloc
	///////VirtualProtect(patchBlock, patched_block_sz, PAGE_EXECUTE_READWRITE, &oldProtect_patched); // PAGE_EXECUTE_READ // !!выдел€етьс€ больше чем запрашиваем
	//VirtualProtect(patchBlock, mbi_patched.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect_patched); // PAGE_EXECUTE_READ дл€ alloc PAGE_READWRITE

	//----INIT OUT PARAMS
	OutPatchPtr = patchBlock; //OutPatchPtr = mbi_patched.BaseAddress;
	OutPatchSzBlock = mbi_patched.RegionSize;



	// orig block jmp -> patched block(istruction from orig + my instr) jmp -> orig block
	//-------------------------PREPEARE--PATCHED--BLOCK
	//memset(buffer, 0, sizeof(buffer));
	memset(patchBlock, nop, mbi_patched.RegionSize);
	//memset(patchBlock, nop, patched_block_sz);

	uintptr_t full_block_sz = jmp_patch_in_end_region ? (mbi_patched.RegionSize - jmp_sz) : (need_block_sz - jmp_sz);
	if (offset > (full_block_sz - OrigSzBlock)) { offset = 0; } // можно офсетить больше PatchSzBlock если jmp в конце
	//if (offset > (full_block_sz - OrigSzBlock)) { VirtualFree(patchBlock, 0, MEM_RELEASE); return false; } // можно офсетить больше PatchSzBlock если jmp в конце
	//if (offset > PatchSzBlock) { offset = 0; } // only patch block. additional not used
	std::memcpy(Transpose(patchBlock, offset), OrigPtr, OrigSzBlock); // to from sz  OrigSzBlock=6

	void* ptr_to_orig_jmp = nullptr;
	//---JMP IN END BLOCK !! universal
	//ptr_to_orig_jmp = Transpose(patchBlock, (mbi_patched.RegionSize - sizeof(char) - sizeof(void*)));
	//---JMP AFTER PATCH SZ !! logical
	//ptr_to_orig_jmp = Transpose(patchBlock, (OrigSzBlock + PatchSzBlock));
	//---JMP AFTER ORIG OPCODE IN PATCHED BLOCK !! no patching space in patched region
	//ptr_to_orig_jmp = Transpose(patchBlock, OrigSzBlock);

	if (jmp_patch_in_end_region) { ptr_to_orig_jmp = Transpose(patchBlock, (mbi_patched.RegionSize - jmp_sz)); }
	else { ptr_to_orig_jmp = Transpose(patchBlock, (OrigSzBlock + PatchSzBlock)); }

	WriteDanger<char>(ptr_to_orig_jmp, jmp); // jmp to orig block
	int offset1 = CalcJMPE9Offset(ptr_to_orig_jmp, Transpose(OrigPtr, OrigSzBlock));
	WriteDanger<int>(Transpose(ptr_to_orig_jmp, sizeof(unsigned char)), offset1); // pointer to jump (ret to orig block)
	//PD_WriteDanger<uintptr_t>(Transpose(patchBlock, block_sz + 1), PD_VoidPtr2IntPtr(Transpose(originalCodeBlock, block_sz))); // bug !!only offset




	//---------------------------PREPEARE--ORIGINAL--BLOCK
	memset(OrigPtr, nop, OrigSzBlock); // nop // nop 6, patch 5 bytes

	void* ptr_to_patched_jmp = Transpose(OrigPtr, 0);
	WriteDanger<unsigned char>(ptr_to_patched_jmp, jmp); // jmp
	int offset2 = CalcJMPE9Offset(ptr_to_patched_jmp, patchBlock);
	WriteDanger<int>(Transpose(ptr_to_patched_jmp, sizeof(unsigned char)), offset2); // pointer to jump (ret to orig block)
	//PD_WriteDanger<uintptr_t>(Transpose(originalCodeBlock, 1), PD_VoidPtr2IntPtr(patchBlock)); // pointer to jump (jmp 2 patch)




	//------------------------ORIG---PROTECT
	if (return_orig_protect && orig_protect_ch)
	{
		DWORD oldProtect_ch;
		VirtualProtect((LPVOID)mbi_orig.BaseAddress, mbi_orig.RegionSize, oldProtect_orig, &oldProtect_ch);
	}

	//------------------------PATCHED--PROTECT
	//{ // modify block after func
	//	DWORD oldProtect_ptch;
	//	VirtualProtect(patchBlock, patched_block_sz, PAGE_EXECUTE_READ, &oldProtect_ptch); // PAGE_EXECUTE_READWRITE
	//}



	//std::cout << "ORIG: 0x" << originalCodeBlock << "\n";
	//std::cout << "PATCH: 0x" << patchBlock << "\n";
	//std::cout << "PATCH SZ BLOCK: " << mbi_patched.RegionSize << "\n";
	//VirtualFree(patchBlock, 0, MEM_RELEASE);
	return true;
}

//SetPatchBlock ---EXAMPLE!!!!
//void PatchStartCalls()
//{
//	//--check version->save call/jmp ptrs->move block->patch block offsets logic->add my patches
//	//WriteDanger<int>(Transpose(ptr_to_patched_jmp, sizeof(char)), offset2); // pointer to jump (ret to orig block)
//	//---CHECK 1.0V
//	void* InitialiseGamePtr = (void*)0x48E7E0; // InitialiseGame
//	if (ReadPtrDanger<uintptr_t>(InitialiseGamePtr) != 0x5F58B068) { InitConsole(); std::cout << "ERROR CHECK INIFUNC!! PatchCalls()" << "\n"; return; }
//
//	//-------------------------------------INIT---GAME-----------------------------------------------------
//	//---MOVE--BLOCK--DATA
//	int available_sz_patch = 29; // дЄрнуть байты из орига (+3 align 10h можно добавить, без них работает)
//	int need_sz_patch = 200; // bytes // доп блок
//	int offset = 0; // max need_sz_patch(будет в конце перед jmp)  block(200+51+1+4)
//	bool jmp_patch_in_end_region = false;
//
//	//---COLLECT--ORIG--DATA--OR--POINTERS--TO--PATCH--MOVED---BLOCK (mov/jmp/jz/je/jnz/jne/call)!!
//	// push from ptr not need patch. this is not offset
//	int offset_call1 = 9;
//	int offset_call2 = 22;
//	void* call1 = Transpose(InitialiseGamePtr, offset_call1); // call gta3.exe + 0x8D770 (0x48E7E9)
//	void* call2 = Transpose(InitialiseGamePtr, offset_call2); // call gta3.exe + 0x8BED0 (0x48E7F6)
//	//void* call1 = (void*)0x48E7E9; // call gta3.exe + 0x8D770 (0x48E7E9)
//	//void* call2 = (void*)0x48E7F6; // call gta3.exe + 0x8BED0 (0x48E7F6)
//	void* call1dest = CalcPointerFromJMPE9Offset(call1, ReadPtrDanger<uintptr_t>(Transpose(call1, sizeof(unsigned char)))); // вычисл€ю указатель который вызывал call
//	void* call2dest = CalcPointerFromJMPE9Offset(call2, ReadPtrDanger<uintptr_t>(Transpose(call2, sizeof(unsigned char))));
//	//std::cout << "call1dest: 0x" << call1dest << "  call2dest: 0x" << call2dest << "\n"; // dump
//	//----------------------END----COLLECT
//
//	//---OUT
//	void* out_patch_ptr = nullptr;
//	int out_patch_sz = 0; // mbi.region_sz
//	//bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, true, offset); // jmp in the end region
//	bool res = SetPatchBlock(InitialiseGamePtr, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, jmp_patch_in_end_region, offset); // jmp after need_sz_patch
//	void* moved_block = Transpose(out_patch_ptr, offset); // указатель на скопированный блок
//
//
//	//-------------------------------PATCHED---BLOCK---
//	//----PATCH--LOGIC---BLOCK
//	void* call1_patchedptr = Transpose(moved_block, offset_call1); // E8
//	void* call2_patchedptr = Transpose(moved_block, offset_call2); // E8
//	InsertCall(call1_patchedptr, call1dest); // fix call offset
//	InsertCall(call2_patchedptr, call2dest);
//
//
//	//---PATCH (nop block default!!)
//	//call ptr 5bytes
//	int offset_orig_retn_block = 27;
//	//-COPY retn block 4 insert call 5 bytes before retn
//	WriteDanger<uint16_t>(Transpose(moved_block, offset_orig_retn_block + sizeof(unsigned char) + sizeof(void*)), ReadPtrDanger<uint16_t>(Transpose(moved_block, offset_orig_retn_block)));
//
//	//---INSERT CALL
//	WriteDanger<unsigned char>(Transpose(moved_block, offset_orig_retn_block), 0xE8); // call
//	InsertCall(Transpose(moved_block, offset_orig_retn_block), OnStartGameHandler);
//
//
//	//--------------------------------------------------------------------------------------------------------
//
//
//
//	//void* buff = MkMem((4 * sizeof(void*))); // bytes // usage 4 * 3
//	//InsertJump(jmp, retn_false_label_ptr);
//}

//----EXAMPLE V2
//void PatchRestartCalls()
//{
//	//---CHECK 1.0V
//	void* InitialiseWhenRestartingPtr = (void*)0x582F9D; // call InitialiseWhenRestarting (0xE8)
//	if (ReadPtrDanger<unsigned char>(InitialiseWhenRestartingPtr) != 0xE8) // if char -24 (not unsigned 0xFFE8)
//	{
//		InitConsole(); std::cout << "ERROR CHECK INIFUNC(0xE8)!! PatchCalls() [" << ((int)ReadPtrDanger<unsigned char>(InitialiseWhenRestartingPtr)) << "]\n"; return;
//	}
//
//
//	//-------------------------------------INIT---GAME-----------------------------------------------------
//	//---MOVE--BLOCK--DATA
//	int available_sz_patch = 5; // дЄрнуть байты из орига (+3 align 10h можно добавить, без них работает)
//	int need_sz_patch = 5; // bytes // доп блок 1 + 4 (5 байт которые переместили из ориг суммируютьс€ в функции), только доп байты!!
//	int offset = 0; // max need_sz_patch(будет в конце перед jmp)  block(200+51+1+4)
//	bool jmp_patch_in_end_region = false;
//
//	//---COLLECT--ORIG--DATA--OR--POINTERS--TO--PATCH--MOVED---BLOCK (mov/jmp/jz/je/jnz/jne/call)!!
//	// push from ptr not need patch. this is not offset
//	void* call1dest = CalcPointerFromJMPE9Offset(InitialiseWhenRestartingPtr, ReadPtrDanger<uintptr_t>(Transpose(InitialiseWhenRestartingPtr, sizeof(unsigned char)))); // вычисл€ю указатель который вызывал call
//	//std::cout << "call1dest: 0x" << call1dest << "  call2dest: 0x" << call2dest << "\n"; // dump
//	//----------------------END----COLLECT
//
//	//---OUT
//	void* out_patch_ptr = nullptr;
//	int out_patch_sz = 0; // mbi.region_sz
//	//bool res = SetPatchBlock(orig_ptr_for_patch_reference, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, true, offset); // jmp in the end region
//	bool res = SetPatchBlock(InitialiseWhenRestartingPtr, available_sz_patch, need_sz_patch, out_patch_ptr, out_patch_sz, jmp_patch_in_end_region, offset); // jmp after need_sz_patch
//	void* moved_block = Transpose(out_patch_ptr, offset); // указатель на скопированный блок
//
//
//	//-------------------------------PATCHED---BLOCK---
//	//----PATCH--LOGIC---BLOCK
//	InsertCall(moved_block, call1dest); // fix call offset
//
//
//	//---PATCH (nop block default!!)
//	//call ptr 5bytes
//	//---INSERT CALL
//	//int offset_orig_retn_block = offset + (sizeof(unsigned char) + sizeof(void*)); // orig call + offset 0
//	//WriteDanger<unsigned char>(Transpose(moved_block, offset_orig_retn_block), 0xE8); // call
//	//InsertCall(Transpose(moved_block, offset_orig_retn_block), OnCGame_ReInitGameObjectVariables);
//
//	//---INSERT CALL
//	void* PatchFreeSpacePtr = Transpose(moved_block, available_sz_patch);
//	WriteDanger<unsigned char>(PatchFreeSpacePtr, 0xE8); // call
//	InsertCall(PatchFreeSpacePtr, OnCGame_ReInitGameObjectVariables);
//	//--------------------------------------------------------------------------------------------------------
//
//
//	//void* buff = MkMem((4 * sizeof(void*))); // bytes // usage 4 * 3
//	//InsertJump(jmp, retn_false_label_ptr);
//}


void* MkMem(int sz, int protect = PAGE_READWRITE) { return VirtualAlloc(nullptr, sz, MEM_COMMIT, protect); }

void RmMem(void* ptr) { VirtualFree(ptr, 0, MEM_RELEASE); }





// указатель можно любой из региона
//----можно на них переписать патчер выше
// out block start + block size // return val is success. ischanged val is result check region
bool UnProtRegion4Patch(void* Ptr, void*& OutPtr, int& OutSzBlock, bool& IsChanged, unsigned long& old_protect)
{
	MEMORY_BASIC_INFORMATION mbi_orig = GetRegionInfoByPointer(Ptr);
	if (!mbi_orig.RegionSize) { return false; } // cant find base+sz
	DWORD oldProtect_orig;

	OutPtr = nullptr; // init
	OutSzBlock = 0;
	IsChanged = false;
	old_protect = 0;

	//if (!_CheckPointerReadByType<char>(OrigPtr)) { return; } // no readable
	if (!CheckPointerBoundsRead(Ptr)) { return false; } // no readable mini optimize


	//if (!_CheckPointerWriteByType<char>(OrigPtr)) // cant patch
	if (!CheckPointerBoundsWrite(Ptr)) // cant patch mini optimize
	{
		//MEMORY_BASIC_INFORMATION mbi = GetRegionInfoByPointer(originalCodeBlock);
		//if (!mbi.RegionSize) { return; } // cant find base+sz
		VirtualProtect((LPVOID)mbi_orig.BaseAddress, mbi_orig.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect_orig);
		OutPtr = (LPVOID)mbi_orig.BaseAddress;
		OutSzBlock = mbi_orig.RegionSize;
		IsChanged = true;
		old_protect = oldProtect_orig;
		return true;
	}
	return false;
}

void ReturnProtRegion4Patch(void* Ptr, unsigned long protect)
{
	MEMORY_BASIC_INFORMATION mbi_orig = GetRegionInfoByPointer(Ptr);
	if (!mbi_orig.RegionSize) { return; } // cant find base+sz
	DWORD oldProtect_ch;
	VirtualProtect((LPVOID)mbi_orig.BaseAddress, mbi_orig.RegionSize, protect, &oldProtect_ch);
}

//void PatchAfter(void* core_base_pointer)
//{
//	//update / draw / frame / idle / init / start / time update
//	//P_Scene::render(P_Scene * this, struct P_Camera* a2) e2mfc.dll  1 link
//	//P_TriangleMeshBase::render(P_VirtualObject * a1, int a2, int a3)  many links
//
//	void* P_Scene_renderPtr = Transpose(core_base_pointer, 0x18EC0); // 0x10018EC0. e2mfc.dll P_Scene::render
//	//std::cout << "P_Scene_renderPtr: 0x" << P_Scene_renderPtr << "\n";
//	void* P_Scene_render_PatchPtr = Transpose(P_Scene_renderPtr, 0xB1A); // nop nop nop nop !!!!(+0xB20 return) (199DA)
//	if (ReadPtrDanger<uint32_t>(P_Scene_render_PatchPtr) != 0x90909090)
//	{
//		InitConsole(); std::cout << "ERROR CHECK!! Patch()" << "\n"; return;
//	}
//
//
//	void* o_BaseBlock = nullptr;
//	int o_SizeBlock = 0;
//	bool o_IsChanged = false;
//	DWORD o_oldProtect;
//	UnProtRegion4Patch(P_Scene_render_PatchPtr, o_BaseBlock, o_SizeBlock, o_IsChanged, o_oldProtect); // можно и core_base_pointer
//
//	WriteDanger<unsigned char>(P_Scene_render_PatchPtr, 0xE8); // call
//	InsertCall(P_Scene_render_PatchPtr, Hook);
//
//	if (o_IsChanged) { ReturnProtRegion4Patch(P_Scene_render_PatchPtr, o_oldProtect); }
//}
