# RegHook/RegHookEx

RegHook is a way of creating your own pointers, copied from registers in a function.  
RegHook is for **internal** usage, RegHookEx is for **externals**.

More specificly, it's a midfunction hooking library, who's purpose is 
to retrieve register data at any particular point in a process.

### Sample:

```c++
RegHook AngleFuncHook(OFFSET_VIEWANGLEFUNC);
((ViewAngle*)AngleFuncHook.GetRegDump().RBX)->Pitch = 0;
```

`regHook.GetRegDump()` returns a `RegDump` class.
```c++
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
```

## Usage

###### Internal
```c++
RegHook AngleFuncHook(OFFSET_VIEWANGLEFUNC);
if (IsValidPtr((LPVOID)AngleFuncHook.GetRegDump().RBX)) {
	((ViewAngle*)AngleFuncHook.GetRegDump().RBX)->Pitch = 0;
	((ViewAngle*)AngleFuncHook.GetRegDump().RBX)->Yaw = 0;
}

```

##### External
```c++
RegHookEx AngleFuncHook(rpm.hProcess, OFFSET_VIEWANGLEFUNC);
if (rpm.read<RegDump>(AngleFuncHook.GetAddressOfHook()).RBX != 0) {
	//Read
	ViewAngle pViewAngle = rpm.read<ViewAngle>(AngleFuncHook.GetRegDump().RBX);
	//pViewAngle.Yaw, pViewAngle.Pitch
	//Write
	RegDump pRegDump = rpm.read<RegDump>(AngleFuncHook.GetAddressOfHook());
	rpm.write<float>(pRegDump.RBX + offsetof(ViewAngle, ViewAngle::Yaw), 0);
	rpm.write<float>(pRegDump.RBX + offsetof(ViewAngle, ViewAngle::Pitch), 0);
}
```

#### fde64

The hook takes 16 bytes to write, and requires RAX to be used for the call.  
I'm using [fde64](https://github.com/GiveMeZeny/fde64/) for length dissasembly, 
so the nearest instruction end after 16 is located automaticlly.

#### Original Function
Here is the function with RegHookEx installed.

![](https://s31.postimg.cc/nw0ffmqkr/image.png)

The first thing that happens, is some memory is allocated for the hooked function.  
This is where program flow will be redirected to temporarily.

```nasm
push rax
movabs rax, jump location
xchg [rsp], rax
ret
```

This takes up 16 bytes.  Any unused bytes must be NOP'd, in this example none need 
to be since the function we're overwriting already is 16 bytes.

#### Hooked Function
Now at the hooked function:

![](https://s31.postimg.cc/l377vg5m3/image.png)


The next 17 bytes have been copied from the original function, 
and placed here.  The target process doesn't know this ever happened.


This is followed by a shitload of NOPs.  This allows for all 
instructions to get hooked (up to 15 bytes, aka max).

#### RIP Relative Addressing

![](https://s31.postimg.cc/h6tvzoxjv/image.png)

Writing all of these manually would be a pain, so I'm using relative 
addressing.  I'm writing it by:

```nasm
mov[rip + 0xf3], rax
mov[rip + 0xe4], rbx
mov[rip + 0xd5], rcx
mov[rip + 0xc6], rdx
mov[rip + 0xb7], rbp
mov[rip + 0xa8], rsp
mov[rip + 0x99], rsi
mov[rip + 0x8a], rdi
mov[rip + 0x7b], r8
mov[rip + 0x6c], r9
mov[rip + 0x5d], r10
mov[rip + 0x4e], r11
mov[rip + 0x3f], r12
mov[rip + 0x30], r13
mov[rip + 0x21], r14
mov[rip + 0x12], r15
```

This accounts for the `RET`, as well as the misalignment of 
the class, thus re-aligning it to the 8'th byte.

#### Optimization

Due to the wonders of the RIP register, I only need to write one 
address into the hooked function for it to work.  The hook itself 
requires two in order to preserve RAX.  You no longer need to specify 
a length for RegHookEx to work, that is done for you too.


#### Full Shellcode

The Hooked Function allocated in memory:

```c++
// shellcode for the hkedfunc
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
```

The hook:

```c++
    0x50,	// push rax
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// movabs rax, jump location
	0x48, 0x87, 0x04, 0x24,	// xchg [rsp], rax
	0xC3,	// ret
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 
```

## Unhooking

Unhooking can be done in two different ways.
1. Per-class
2. With the static method
3. Using the static method on exit

##### Per-class unhooking:

Unhooks and repairs the original function.

```c++
AngleFuncHook.DestroyHook();
```

##### Static Method:

Unhooks and repairs original functions of all active instances of RegHookEx.

```c++
RegHookEx::DestroyAllHooks();
```

##### Automated Unhooking:

Use this for externals to Unhook whenever you exit the console.

```c++
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
    // your stuff
}
```

For internals, you can call the static function in your DllMain.
```c++
BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwAttached, LPVOID lpvReserved)
{
	if (dwAttached == DLL_PROCESS_ATTACH) {
		//...
	}
	if (dwAttached == DLL_PROCESS_DETACH) {
		RegHook::DestroyAllHooks();
		FreeConsole();
	}
	return 1;
}
```
