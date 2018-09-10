#include "RegHook.h"
#include "fde\fde64.h"

class RegHookShared {
public:
	static size_t min_size;
	static byte* hkpatch;
	static byte* funcpatch;
	const static SIZE_T hkpatch_size;
	const static SIZE_T funcpatch_size;
	static size_t GetInstructionLength(void*);
	const static size_t instruction_max;
};

size_t RegHookShared::GetInstructionLength(void* buff) {
	void *ptr = (void*)buff;
	fde64s cmd;
	decode(ptr, &cmd);
	ptr = (void *)((uintptr_t)ptr + cmd.len);
	return cmd.len;
}

size_t RegHookShared::min_size = 17;
const size_t RegHookShared::instruction_max = 15;

const size_t RegHookShared::hkpatch_size = 83;
byte* RegHookShared::hkpatch = new byte[RegHookShared::hkpatch_size]{
	0x48, 0x8B, 0x05, 0x89, 0x00, 0x00, 0x00,  //  mov rax, [rip + 137]  ;  0x90
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  //  nop * 26
	0x48, 0x89, 0x0D, 0x60, 0x00, 0x00, 0x00,  //  mov [rip + 96], rcx ; ->0x88
	0x48, 0x89, 0x15, 0x51, 0x00, 0x00, 0x00,  //  mov [rip + 81], rdx ; ->0x80
	0x48, 0x89, 0x2D, 0x42, 0x00, 0x00, 0x00,  //  mov [rip + 66], rbp ; ->0x78
	0x48, 0x89, 0x35, 0x33, 0x00, 0x00, 0x00,  //  mov [rip + 51], rsi ; ->0x70
	0x48, 0x89, 0x3D, 0x24, 0x00, 0x00, 0x00,  //  mov [rip + 36], rdi ; ->0x68
	0x48, 0x89, 0x25, 0x15, 0x00, 0x00, 0x00,  //  mov [rip + 21], rsp ; ->0x60
	0x48, 0x89, 0x1D, 0x06, 0x00, 0x00, 0x00,  //  mov [rip + 6], rbx ; ->0x58
	0xC3  //  ret
};

const size_t RegHookShared::funcpatch_size = 32;
byte* RegHookShared::funcpatch = new byte[RegHookShared::funcpatch_size]{
	0x48, 0x89, 0x04, 0x25, 0x90, 0x34, 0x12, 0x00,		// mov [raxpath], rax
	0x48, 0xC7, 0xC0, 0x00, 0x34, 0x12, 0x00,		// mov rax, this->HookedAddress
	0xFF, 0xD0 ,		// call rax ;	0x17
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; // extra nops

bool RegHook::CreateHookV6() {
	if (this->lengthOfInstructions > 26 || this->lengthOfInstructions < RegHookShared::min_size) return false;
	this->HookedAddress = (DWORD_PTR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RegHook::ReadMem((LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions);
	byte* hkpatch = RegHookShared::hkpatch;
	memcpy(hkpatch + 7, &this->toFixPatch, this->lengthOfInstructions);
	RegHook::WriteMem((LPVOID)this->HookedAddress, hkpatch, RegHookShared::hkpatch_size);
	byte* funcpatch = RegHookShared::funcpatch;
	DWORD_PTR raxpatch = this->HookedAddress + 0x90;
	memcpy(funcpatch + 11, &this->HookedAddress, 4);
	memcpy(funcpatch + 4, &raxpatch, 4);
	RegHook::WriteMem((LPVOID)this->FuncAddress, funcpatch, this->lengthOfInstructions);
	this->HookInstances.push_back(this);
	return true;
}
void RegHook::ReadMem(void* dst, void* src, const size_t size) {
	DWORD protect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &protect);
	memcpy(src, dst, size);
	VirtualProtect(dst, size, protect, nullptr);
}

void RegHook::WriteMem(void* dst, void* src, const size_t size) {
	DWORD protect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &protect);
	memcpy(dst, src, size);
	VirtualProtect(dst, size, protect, nullptr);
}

size_t RegHook::GetFuncLen() {
	DWORD_PTR addr = this->FuncAddress;
	while (this->lengthOfInstructions < RegHookShared::min_size) {
		byte buff[RegHookShared::instruction_max];
		RegHook::ReadMem((LPVOID)addr, &buff, RegHookShared::instruction_max);
		size_t tmpsize = RegHookShared::GetInstructionLength(&buff);
		this->lengthOfInstructions += tmpsize;
		addr += tmpsize;
	}
	return this->lengthOfInstructions;
}

DWORD_PTR RegHook::GetAddressOfHook() {
	if (this->HookedAddress == 0) {
		CreateHookV6();
	}
	return this->HookedAddress;
}

void RegHook::DestroyHook() {
	if (this->toFixPatch[0] != 0)
		RegHook::WriteMem((LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions);
}

void RegHook::DestroyAllHooks() {
	for (int i = 0; i < HookInstances.size(); i++) {
		HookInstances[i]->DestroyHook();
	}
}

RegDump RegHook::GetRegDump() {
	RegDump pDump;
	RegHook::ReadMem((LPVOID)this->GetAddressOfHook(), &pDump, sizeof(RegDump));
	return pDump;
}

RegHook::RegHook(DWORD_PTR _FuncAddress) {
	this->FuncAddress = _FuncAddress;
	this->lengthOfInstructions = this->GetFuncLen();
}

std::vector<RegHook*> RegHook::HookInstances;

// ------------------------------------------------------------

bool RegHookEx::CreateHookV6() {
	if (this->lengthOfInstructions > 26 || this->lengthOfInstructions < RegHookShared::min_size) return false;
	this->HookedAddress = (DWORD_PTR)VirtualAllocEx(this->hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	ReadProcessMemory(this->hProcess, (LPCVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
	byte* hkpatch = RegHookShared::hkpatch;
	memcpy(hkpatch + 7, &this->toFixPatch, this->lengthOfInstructions);
	WriteProcessMemory(this->hProcess, (LPVOID)this->HookedAddress, hkpatch, RegHookShared::hkpatch_size, NULL);
	byte* funcpatch = RegHookShared::funcpatch;
	DWORD_PTR raxpatch = this->HookedAddress + 0x90;
	memcpy(funcpatch + 11, &this->HookedAddress, 4);
	memcpy(funcpatch + 4, &raxpatch, 4);
	WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, funcpatch, this->lengthOfInstructions, NULL);
	this->HookInstances.push_back(this);
	return true;
}

size_t RegHookEx::GetFuncLen() {
	DWORD_PTR addr = this->FuncAddress;
	while (this->lengthOfInstructions < RegHookShared::min_size) {
		byte buff[RegHookShared::instruction_max];
		ReadProcessMemory(this->hProcess, (LPCVOID)addr, &buff, RegHookShared::instruction_max, NULL);
		size_t tmpsize = RegHookShared::GetInstructionLength(&buff);
		this->lengthOfInstructions += tmpsize;
		addr += tmpsize;
	}
	return this->lengthOfInstructions;
}

DWORD_PTR RegHookEx::GetAddressOfHook() {
	if (this->HookedAddress == 0) {
		CreateHookV6();
	}
	return this->HookedAddress;
}

void RegHookEx::DestroyHook() {
	if (this->toFixPatch[0] != 0)
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
}

void RegHookEx::DestroyAllHooks() {
	for (int i = 0; i < HookInstances.size(); i++) {
		HookInstances[i]->DestroyHook();
	}
}

RegDump RegHookEx::GetRegDump() {
	RegDump pDump;
	ReadProcessMemory(this->hProcess, (LPVOID)this->GetAddressOfHook(), &pDump, sizeof(RegDump), nullptr);
	return pDump;
}

RegHookEx::RegHookEx(HANDLE _hProcess, DWORD_PTR _FuncAddress) {
	this->hProcess = _hProcess;
	this->FuncAddress = _FuncAddress;
	this->lengthOfInstructions = this->GetFuncLen();
}

std::vector<RegHookEx*> RegHookEx::HookInstances;