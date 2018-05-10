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


	RegHookEx AngleFuncHook(rpm.hProcess, 0x14163AE33);
	
	DWORD64 pAngleFunc = AngleFuncHook.GetAddressOfHook();
	std::cout << std::hex << pAngleFunc << std::endl;

	std::cout << "Done" << std::endl;
	getchar();
}
