#include <windows.h>
#include <vector>

// output class
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
	const size_t min_size = 17;
	bool CreateHookV6();
	bool CreateHookV5();
	size_t GetInstructionLength(void* buff);
	size_t GetFuncLen();
public:
	RegHookEx(HANDLE _hProcess, DWORD64 _FuncAddress);
	RegHookEx() {}
	DWORD64 GetAddressOfHook();
	void DestroyHook();
	static void DestroyAllHooks();
};
