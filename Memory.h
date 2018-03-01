#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>

class RPM {
private:
	DWORD Proc_ID;
	LPCSTR _WindowName;
public:
	HANDLE hProcess;
	DWORD *base;

	static HANDLE GetProcessByName(PCSTR name)
	{
		DWORD pid = 0;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 process;
		ZeroMemory(&process, sizeof(process));
		process.dwSize = sizeof(process);
		if (Process32First(snapshot, &process))
		{
			do
			{
				if (std::string(process.szExeFile) == std::string(name))
				{
					pid = process.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &process));
		}

		CloseHandle(snapshot);

		if (pid != 0)
		{
			return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		}
		return NULL;
	}


	void attach(LPCSTR WindowName) {
		HWND hWindow = FindWindowA(NULL, WindowName);
		if (hWindow)
		{
			GetWindowThreadProcessId(hWindow, &Proc_ID);
			hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION /*| PROCESS_ALL_ACCESS*/, FALSE, Proc_ID);
			HANDLE hModule = INVALID_HANDLE_VALUE;
			MODULEENTRY32 ePoint;
			hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Proc_ID);
			ePoint.dwSize = sizeof(MODULEENTRY32);
			Module32First(hModule, &ePoint);
			base = (DWORD*)ePoint.modBaseAddr;
			CloseHandle(hModule);
		}
	}

	template <class cData>
	cData read(DWORD64(Address)) {
		try {
			if (Proc_ID > 0) {
				cData B;
				ReadProcessMemory(hProcess, (LPCVOID)Address, &B, sizeof(B), NULL);
				return B;
			}
			else {
				throw 1;
			}
		}
		catch (int error) {
			std::cout << "ERROR:\t" << error << std::endl;
		}
	}
	template <class cData>

	cData write(DWORD64(Address), cData B) {
		try {
			if (Proc_ID > 0) {
				VirtualProtectEx(hProcess, (LPVOID)(Address), sizeof(B), PAGE_EXECUTE_READWRITE, NULL);
				WriteProcessMemory(hProcess, (LPVOID)(Address), &B, sizeof(B), NULL);
				return B;
			}
			else {
				throw 1;
			}
		}
		catch (int error) {
			std::cout << "ERROR:\t" << error << std::endl;
		}
	}

	bool inject(std::string dll) {
		HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->Proc_ID);
		if (process == NULL) return false;
		LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		if (addr == NULL) return false;
		LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(dll.c_str()), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (arg == NULL) return false;
		int n = WriteProcessMemory(process, arg, dll.c_str(), strlen(dll.c_str()), NULL);
		if (n == 0) return false;
		HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
		if (threadID == NULL) return false;
		CloseHandle(process);
		return true;
	}

	void * PatternScan(char* base, unsigned int size, char* pattern, char*mask)
	{
		unsigned int patternLength = strlen(mask);

		for (unsigned int i = 0; i < size - patternLength; i++)
		{
			bool found = true;
			for (unsigned int j = 0; j < patternLength; j++)
			{
				if (mask[j] != '?' && pattern[j] != *(base + i + j))
				{
					found = false;
					break;
				}
			}
			if (found)
			{
				return (void*)(base + i);
			}
		}
		return nullptr;
	}

	void * PatternScanEx( char* pattern, char*  mask)
	{
		uintptr_t currentChunk = (uintptr_t)this->base;
		SIZE_T bytesRead;

		while (currentChunk < (uintptr_t)this->base + 0x10000000)
		{
			char buffer[4096];

			DWORD oldprotect;
			VirtualProtectEx(this->hProcess, (void*)currentChunk, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldprotect);
			ReadProcessMemory(this->hProcess, (void*)currentChunk, &buffer, sizeof(buffer), &bytesRead);
			VirtualProtectEx(this->hProcess, (void*)currentChunk, sizeof(buffer), oldprotect, NULL);

			if (bytesRead == 0)
			{
				return nullptr;
			}

			void* internalAddress = PatternScan((char*)&buffer, bytesRead, pattern, mask);

			if (internalAddress != nullptr)
			{
				uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
				return (void*)(currentChunk + offsetFromBuffer);
			}
			else
			{
				currentChunk = currentChunk + bytesRead;
			}
		}
		return nullptr;
	}

	DWORD64 FindOffsetEx(DWORD64 address) {
		DWORD64 Offset = address + 3;
		byte first = this->read<BYTE>(Offset + 4);
		DWORD Offset2 =this->read<DWORD>(Offset);
		return Offset + Offset2 + 4;
	}
};
