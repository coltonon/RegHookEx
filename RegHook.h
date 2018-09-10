#include <windows.h>
#include <vector>

// output class
class RegDump
{
public:
	char pad_0000[88]; //0x0000
	DWORD_PTR RBX; //0x0058
	DWORD_PTR RSP; //0x0060
	DWORD_PTR RDI; //0x0068
	DWORD_PTR RSI; //0x0070
	DWORD_PTR RBP; //0x0078
	DWORD_PTR RDX; //0x0080
	DWORD_PTR RCX; //0x0088
	DWORD_PTR RAX; //0x0090
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
	size_t lengthOfInstructions;
	DWORD_PTR HookedAddress = 0;
	byte toFixPatch[60];
	bool CreateHookV6();
	size_t GetFuncLen();
public:
	RegHookEx(HANDLE _hProcess, DWORD_PTR _FuncAddress);
	DWORD_PTR GetAddressOfHook();
	void DestroyHook();
	static void DestroyAllHooks();
	RegDump GetRegDump();
};

