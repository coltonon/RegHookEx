#include <windows.h>
#include <vector>

// output class
class RegDump
{
public:
	char pad_0000[160]; //0x0000
	DWORD_PTR R15; //0x00A0
	DWORD_PTR R14; //0x00A8
	DWORD_PTR R13; //0x00B0
	DWORD_PTR R12; //0x00B8
	DWORD_PTR R11; //0x00C0
	DWORD_PTR R10; //0x00C8
	DWORD_PTR R9; //0x00D0
	DWORD_PTR R8; //0x00D8
	DWORD_PTR RDI; //0x00E0
	DWORD_PTR RSI; //0x00E8
	DWORD_PTR RSP; //0x00F0
	DWORD_PTR RBP; //0x00F8
	DWORD_PTR RDX; //0x0100
	DWORD_PTR RCX; //0x0108
	DWORD_PTR RBX; //0x0110
	DWORD_PTR RAX; //0x0118
};

class RegHook {
private:
	static std::vector<RegHook*> HookInstances;
	DWORD_PTR FuncAddress;
	size_t lengthOfInstructions;
	DWORD_PTR HookedAddress = 0;
	byte toFixPatch[60];
	bool CreateHookV6();
	size_t GetFuncLen();
	static void ReadMem(void*, void*, const size_t);
	static void WriteMem(void*, void*, const size_t);
public:
	RegHook(DWORD_PTR _FuncAddress);
	DWORD_PTR GetAddressOfHook();
	void DestroyHook();
	static void DestroyAllHooks();
	RegDump GetRegDump();
};

class RegHookEx{
private:
	static std::vector<RegHookEx*> HookInstances;
	HANDLE hProcess;
	DWORD_PTR FuncAddress;
	DWORD_PTR HookedAddress = 0;
	byte toFixPatch[60];
	bool CreateHookV6();
	size_t GetFuncLen();
	size_t lengthOfInstructions;
public:
	RegHookEx(HANDLE _hProcess, DWORD_PTR _FuncAddress);
	DWORD_PTR GetAddressOfHook();
	void DestroyHook();
	static void DestroyAllHooks();
	RegDump GetRegDump();
};

