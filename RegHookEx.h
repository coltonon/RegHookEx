#include <windows.h>
#include <vector>

class RegDump
{
public:
	char pad_0000[88]; //0x0000
	DWORD64 RBX; //0x0058
	DWORD64 RSP; //0x0060
	DWORD64 RDI; //0x0068
	DWORD64 RSI; //0x0070
	DWORD64 RBP; //0x0078
	DWORD64 RDX; //0x0080
	DWORD64 RCX; //0x0088
	DWORD64 RAX; //0x0090
}; //Size: 0x0140



class RegHookEx {
private:
	static std::vector<RegHookEx*> HookInstances;
	HANDLE hProcess;
	DWORD64 FuncAddress;
	size_t lengthOfInstructions;
	DWORD64 HookedAddress = 0;
	byte toFixPatch[60];


	bool CreateHookV6() {

		if (this->lengthOfInstructions > 32 || this->lengthOfInstructions < 17) return false;

		// allocate space for the hkedfunc
		this->HookedAddress = (DWORD64)VirtualAllocEx(this->hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		// Copy they bytes from the original function
		ReadProcessMemory(this->hProcess, (LPCVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
		
		// shellcode for the hkedfunc
		byte* hkpatch = new byte[83]{	// using byte* so I don't have to cast when using memcpy
			// use rip relative addressing to make things more efficent
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

		// write the origfunc over the nops in the hkedfunc.  Size doesn't matter because of the nops
		memcpy(hkpatch + 7, &this->toFixPatch, this->lengthOfInstructions);

		// write the hkedfunc to memory.  Uses RIP addressing so it can be left mostly intact.
		WriteProcessMemory(this->hProcess, (LPVOID)this->HookedAddress, hkpatch, 83, NULL);

		// writing the hook.  Need to write the address of the saved RAX register in, as well as the hkfunc address
		byte* funcpath = new byte[32]{ 
			0x48, 0x89, 0x04, 0x25, 0x90, 0x34, 0x12, 0x00,		// mov [raxpath], rax
			0x48, 0xC7, 0xC0, 0x00, 0x34, 0x12, 0x00,		// mov rax, this->HookedAddress
			0xFF, 0xD0 ,		// call rax ;	0x17
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; // extra nops
		
		DWORD64 raxpath = this->HookedAddress + 4;
		memcpy(funcpath + 11, &this->HookedAddress, 4);	// copy the hookedaddress into funcpath shellcode
		memcpy(funcpath + 4, &raxpath, 4);	// copy the raxaddress into the funcpath shellcode

		// install the hook on the original function
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, funcpath, this->lengthOfInstructions, NULL);

		this->HookInstances.push_back(this);	// add current instance to the static vector for iteration and unhooking
		return true;
	}

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
		// write the originally saved byte buffer back to the original function.  Leave the hkedfunc, as it won't be executed.
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
	}

	static void DestroyAllHooks() {
		for (int i = 0; i < HookInstances.size(); i++) {
			HookInstances[i]->DestroyHook();
		}
	}

};

std::vector<RegHookEx*> RegHookEx::HookInstances;