# RegHookEx

RegHookEx is a way of creating your own pointers, copied from registers in a function.  
It works **both** **internally** and **externally**.

More specificly, it's a midfunction hooking library, who's purpose is 
to retrieve register data at any particular point in a process.

### Sample:

```c++
RegHookEx AngleFuncHook(rpm.hProcess, 0x1415de64e);
DWORD64 pAngleFunc = AngleFuncHook.GetAddressOfHook();
```

`pAngleFunc` is equal to a value allocated in memory by RegHookEx.  
For example, `0x2880000`.  At this address, is a class of type `RegDump`.  

```c++
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
```

This is very helpful both internally and externally.  
Say I have a class, `ViewAngle`.  `ViewAngle` contains a float for 
yaw at 0x68, and a float for pitch at 0x6c.  I know that at the function 
at `0x1415de64e`, register RBX is a ViewAngle pointer.  
Here are some samples for this example on how to do this both internally 
and externally.

### Internal:

```c++
RegHookEx AngleFuncHook(GetCurrentProcess(), 0x1415de64e);
RegDump* pRegDump = (RegDump*)AngleFuncHook.GetAddressOfHook();
ViewAngle* pViewAngle = (ViewAngle*)(pRegDump->RDI);
```

### External:

```c++
RegHookEx AngleFuncHook(mem.hProcess, 0x1415de64e);
RegDump pRegDump = mem.Read<RegDump>(AngleFuncHook.GetAddressOfHook());
ViewAngle pViewAngle = mem.Read<ViewAngle>(pRegDump.RDI);
```

Viola, writeable viewangles.

___

## How it works

RegHookEx is rather complicated, but is still efficient.  
Using the same address and function as I used above, here's what 
goes on behind the scenes.


#### fde64

The hook takes 17 bytes to write, and requires RAX to be used for the call.  
I'm using [fde64](https://github.com/GiveMeZeny/fde64/) for length dissasembly, 
so the nearest instruction end after 17 is located automaticlly.

#### Original Function
Here is the function with RegHookEx installed.
![](https://s31.postimg.org/nw0ffmqkr/image.png)

The first thing that happens, is some memory is allocated for the hooked function.  
This is where program flow will be redirected to temporarily.

```nasm
mov [0x2880090], rax    ; save rax to allocated space address + 0x90
mov rax, 0x2880000      ; move allocated space address into rax
call rax
```

This takes up 17 bytes.  Any unused bytes must be NOP'd, in this example none need 
to be since the function we're overwriting already is 17 bytes.

#### Hooked Function
Now at the hooked function:
![](https://s31.postimg.org/l377vg5m3/image.png)

First thing, rax gets restored.  

```nasm
mov rax, [0x2880090]
```

The next 17 bytes have been copied from the original function, 
and placed here.  The target process doesn't know this ever happened.


This is followed by a shitload of NOPs.  This allows for all 
instructions to get hooked (up to 15 bytes, aka max).

#### RIP Relative Addressing

![](https://s31.postimg.org/h6tvzoxjv/image.png)

Writing all of these manually would be a pain, so I'm using RIP 
addressing.  I'm writing it by:

```nasm
mov [rip + 96], rcx ; ->0x88
mov [rip + 81], rdx ; ->0x80
mov [rip + 66], rbp ; ->0x78
mov [rip + 51], rsi ; ->0x70
mov [rip + 36], rdi ; ->0x68
mov [rip + 21], rsp ; ->0x60
mov [rip + 6], rbx ; ->0x58
```

This accounts for the `RET`, as well as the misalignment of 
the class, thus re-aligning it to the 0'th byte.

#### Optimization

Due to the wonders of the RIP register, I only need to write one 
address into the hooked function for it to work.  The hook itself 
requires two in order to preserve RAX.  You no longer need to specify 
a length for RegHookEx to work, that is done for you too.


#### Full Shellcode

The Hooked Function allocated in memory:

```c++
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
```

The hook:

```c++

byte* funcpath = new byte[32]{ 
    0x48, 0x89, 0x04, 0x25, 0x90, 0x34, 0x12, 0x00,		// mov [raxpath], rax
    0x48, 0xC7, 0xC0, 0x00, 0x34, 0x12, 0x00,		// mov rax, this->HookedAddress
    0xFF, 0xD0 ,		// call rax ;	0x17
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; // extra nops
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