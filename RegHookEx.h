#include <windows.h>
#include <vector>

class RegDump
{
public:
	char pad_0000[80]; //0x0000
	DWORD64 RBX; //0x0050
	DWORD64 RCX; //0x0058
	DWORD64 RDX; //0x0060
	DWORD64 RBP; //0x0068
	DWORD64 RSI; //0x0070
	DWORD64 RDI; //0x0078
	DWORD64 RSP; //0x0080
	char pad_0088[952]; //0x0088
}; //Size: 0x0440



class RegHookEx {
private:
	static std::vector<RegHookEx*> HookInstances;
	HANDLE hProcess;
	DWORD64 FuncAddress;
	size_t lengthOfInstructions;
	DWORD64 HookedAddress = 0;
	byte toFixPatch[60];


	bool CreateHookV5() {
		this->HookedAddress = (DWORD64)VirtualAllocEx(this->hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		byte* hkpatch = new byte[72] { 0x90, 0x90, 0x90, 0x90, 0x90,  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x89, 0x1D, 0x33, 0x00, 0x00, 0x00, 0x48, 0x89, 0x0D, 0x34, 0x00, 0x00, 0x00, 0x48, 0x89, 0x15, 0x35, 0x00, 0x00, 0x00, 0x48, 0x89, 0x2D, 0x36, 0x00, 0x00, 0x00, 0x48, 0x89, 0x35, 0x37, 0x00, 0x00, 0x00, 0x48, 0x89, 0x3D, 0x38, 0x00, 0x00, 0x00, 0x48, 0x89, 0x25, 0x39, 0x00, 0x00, 0x00, 0xC3 };
		ReadProcessMemory(this->hProcess, (LPCVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
		memcpy(hkpatch, &this->toFixPatch, this->lengthOfInstructions);
		WriteProcessMemory(this->hProcess, (LPVOID)this->HookedAddress, hkpatch, 72, NULL);

		byte nop[15] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, &nop, this->lengthOfInstructions, NULL);

		byte* funcpath = new byte[9]{ 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd0 };
		memcpy(funcpath + 3, &this->HookedAddress, 4);
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, funcpath, 9, NULL);

		
		this->HookInstances.push_back(this);
		return true;
	}

public:
	

	RegHookEx(HANDLE _hProcess, DWORD64 _FuncAddress, size_t _lengthOfInstructions) {
		this->hProcess = _hProcess;
		this->FuncAddress = _FuncAddress;
		this->lengthOfInstructions = _lengthOfInstructions;
	}
	RegHookEx(){}

	DWORD64 GetAddressOfHook() {
		if (this->HookedAddress == 0) {
			CreateHookV5();
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