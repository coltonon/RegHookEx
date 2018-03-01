#include "Includes.h"

class RegHookEx {
private:
	static std::vector<RegHookEx*> HookInstances;
	HANDLE hProcess;
	DWORD64 FuncAddress;
	DWORD lengthOfInstructions;
	byte reg;
	DWORD64 HookedAddress = 0;
	byte toFixPatch[60];

	bool CreateHookV3() {
		if (this->lengthOfInstructions > 31 || this->lengthOfInstructions < 16) return false;
		this->HookedAddress = (DWORD64)VirtualAllocEx(this->hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		ReadProcessMemory(this->hProcess, (LPCVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
		FlushInstructionCache(this->hProcess, (LPCVOID)this->FuncAddress, this->lengthOfInstructions);
		byte* jmp = new byte[16]{ 0x50, 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x04, 0x24, 0xc3 };
		DWORD64 hookFuncStart = this->HookedAddress + 8;
		memcpy(jmp + 3, &hookFuncStart, 8);
		byte nop[15] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, jmp, 16, NULL);
		WriteProcessMemory(this->hProcess, (LPVOID)(this->FuncAddress + 16), &nop, (this->lengthOfInstructions - 16), NULL);
		WriteProcessMemory(this->hProcess, (LPVOID)((DWORD64)this->HookedAddress + 0x8), &this->toFixPatch, this->lengthOfInstructions, NULL);
		byte* returnFromHook = new byte[24]{ 0x48, 0x89, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0xB8,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x04, 0x24, 0xC3 };
		DWORD64 resumeFunction = this->FuncAddress + 16;
		memmove(returnFromHook + 4, &this->HookedAddress, 4);
		memmove(returnFromHook + 11, &resumeFunction, 8);
		returnFromHook[2] = this->reg;
		WriteProcessMemory(this->hProcess, (LPVOID)(this->HookedAddress + 0x8 + this->lengthOfInstructions), returnFromHook, 24, NULL);
		this->HookInstances.push_back(this);
		return true;
	}
public:
	static struct Regs {
		const static byte RBX = 0x1c;
		const static byte RCX = 0x0c;
		const static byte RDX = 0x14;
		const static byte RBP = 0x2c;
		const static byte RSI = 0x34;
		const static byte RDI = 0x3c;
		const static byte RSP = 0x24;
	};

	RegHookEx(HANDLE _hProcess, DWORD64 _FuncAddress, DWORD _lengthOfInstructions, byte _reg) {
		this->hProcess = _hProcess;
		this->FuncAddress = _FuncAddress;
		this->lengthOfInstructions = _lengthOfInstructions;
		this->reg = _reg;
	}

	DWORD64 GetAddressOfHook() {
		if (this->HookedAddress == 0) {
			CreateHookV3();
		}
		return this->HookedAddress;
	}

	void DestroyHook() {
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
	}

	static void DestroyAllHooks() {
		for (int i = 0; i < HookInstances.size(); i++) {
			HookInstances[i]->DestroyHook();
		}
	}

};

std::vector<RegHookEx*> RegHookEx::HookInstances;