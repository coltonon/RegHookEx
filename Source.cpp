#include "Memory.h"
#include "RegHookEx.h"


bool ctrlh(DWORD event)
{
	if (event == CTRL_CLOSE_EVENT) {
		std::cout << "Deleting All Hooks" << std::endl;
		RegHookEx::DestroyAllHooks();
		return TRUE;
	}
	return FALSE;
}

void main() {
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)(ctrlh), TRUE);

	RPM rpm;
	rpm.attach("STAR WARS BATTLEFRONT II");


	//0x1415de651 old

	//0x1415de64e
	//0x1415de664

	RegHookEx AngleFuncHook(rpm.hProcess, 0x1415de64e);
	std::cout << std::hex << AngleFuncHook.GetAddressOfHook() << std::endl;

	std::cout << "Done" << std::endl;
	getchar();
}
