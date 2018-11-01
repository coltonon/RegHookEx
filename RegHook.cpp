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

size_t RegHookShared::min_size = 16;
const size_t RegHookShared::instruction_max = 15;

const size_t RegHookShared::hkpatch_size = 158;
byte* RegHookShared::hkpatch = new byte[RegHookShared::hkpatch_size]{
	 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nop ; * min_size*instruction_max
	 0x48, 0x89, 0x05, 0xF3, 0x00, 0x00, 0x00, 	//	mov[rip + 0xf3], rax
	 0x48, 0x89, 0x1D, 0xE4, 0x00, 0x00, 0x00, 	//	mov[rip + 0xe4], rbx
	 0x48, 0x89, 0x0D, 0xD5, 0x00, 0x00, 0x00, 	//	mov[rip + 0xd5], rcx
	 0x48, 0x89, 0x15, 0xC6, 0x00, 0x00, 0x00, 	//	mov[rip + 0xc6], rdx
	 0x48, 0x89, 0x2D, 0xB7, 0x00, 0x00, 0x00, 	//	mov[rip + 0xb7], rbp
	 0x48, 0x89, 0x25, 0xA8, 0x00, 0x00, 0x00, 	//	mov[rip + 0xa8], rsp
	 0x48, 0x89, 0x35, 0x99, 0x00, 0x00, 0x00, 	//	mov[rip + 0x99], rsi
	 0x48, 0x89, 0x3D, 0x8A, 0x00, 0x00, 0x00, 	//	mov[rip + 0x8a], rdi
	 0x4C, 0x89, 0x05, 0x7B, 0x00, 0x00, 0x00, 	//	mov[rip + 0x7b], r8
	 0x4C, 0x89, 0x0D, 0x6C, 0x00, 0x00, 0x00, 	//	mov[rip + 0x6c], r9
	 0x4C, 0x89, 0x15, 0x5D, 0x00, 0x00, 0x00, 	//	mov[rip + 0x5d], r10
	 0x4C, 0x89, 0x1D, 0x4E, 0x00, 0x00, 0x00, 	//	mov[rip + 0x4e], r11
	 0x4C, 0x89, 0x25, 0x3F, 0x00, 0x00, 0x00, 	//	mov[rip + 0x3f], r12
	 0x4C, 0x89, 0x2D, 0x30, 0x00, 0x00, 0x00, 	//	mov[rip + 0x30], r13
	 0x4C, 0x89, 0x35, 0x21, 0x00, 0x00, 0x00, 	//	mov[rip + 0x21], r14
	 0x4C, 0x89, 0x3D, 0x12, 0x00, 0x00, 0x00, 	//	mov[rip + 0x12], r15
	 0x50,	// push rax
	 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rax, FuncAddress + lengthOfInstructions
	 0x48, 0x87, 0x04, 0x24,	// xchg [rsp], rax
	 0xC3	// ret
};

const size_t RegHookShared::funcpatch_size = 31;
byte* RegHookShared::funcpatch = new byte[RegHookShared::funcpatch_size]{
	0x50,	// push rax
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// movabs rax, jump location
	0x48, 0x87, 0x04, 0x24,	// xchg [rsp], rax
	0xC3,	// ret
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; // extra nops

bool RegHook::CreateHookV6() {
	if (this->lengthOfInstructions > RegHookShared::min_size + RegHookShared::instruction_max || this->lengthOfInstructions < RegHookShared::min_size) return false;
	this->HookedAddress = (DWORD_PTR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RegHook::ReadMem((LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions);
	byte* hkpatch = RegHookShared::hkpatch;
	memcpy(hkpatch, &this->toFixPatch, this->lengthOfInstructions);
	DWORD_PTR returnAddress = this->lengthOfInstructions + this->FuncAddress; // get the address to return to
	memcpy(hkpatch + 145, &returnAddress, 8);	// write it into the hkpatch
	RegHook::WriteMem((LPVOID)this->HookedAddress, hkpatch, RegHookShared::hkpatch_size);
	byte* funcpatch = RegHookShared::funcpatch;
	memcpy(funcpatch + 3, &this->HookedAddress, 8);
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
	if (this->lengthOfInstructions > RegHookShared::min_size + RegHookShared::instruction_max || this->lengthOfInstructions < RegHookShared::min_size) return false;
	this->HookedAddress = (DWORD_PTR)VirtualAllocEx(this->hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	ReadProcessMemory(this->hProcess, (LPCVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
	byte* hkpatch = RegHookShared::hkpatch;
	memcpy(hkpatch, &this->toFixPatch, this->lengthOfInstructions);
	DWORD_PTR returnAddress = this->lengthOfInstructions + this->FuncAddress; // get the address to return to
	memcpy(hkpatch + 145, &returnAddress, 8);	// write it into the hkpatch
	WriteProcessMemory(this->hProcess, (LPVOID)this->HookedAddress, hkpatch, RegHookShared::hkpatch_size, NULL);
	byte* funcpatch = RegHookShared::funcpatch;
	memcpy(funcpatch + 3, &this->HookedAddress, 8); // write the address to jump to
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