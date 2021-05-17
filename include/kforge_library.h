#ifndef _KFORGE_LIBRARY_H_
#define _KFORGE_LIBRARY_H_

// max arguments for KfCall(): 4 over the registers and 9 over the stack
#define MAX_ARGS (4 + 9)

// convert KfCall() call arguments
#define KF_ARG(_val_) ((PVOID)(_val_))

// convert KfCall() return value
#define KF_RET(_val_) ((PVOID *)(_val_))

#ifdef __cplusplus

extern "C"
{

#endif

/**
 * Initialize Kernel Forge library: reads kernel image into the user mode memory,
 * finds needed ROP gadgets, etc, etc.
 *
 * @return TRUE if success or FALSE in case of error.
 */
BOOL KfInit(void);

/**
 * Uninitialize Kernel Forge library when you don't need to use its API anymore.
 *
 * @return TRUE if success and FALSE in case of error.
 */
BOOL KfUninit(void);

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

/**
 * Call an arbitrary function by its address.
 *
 * @param ProcAddr Address of the function to call.
 * @param Args Array with its arguments.
 * @param dwArgsCount Number of the arguments.
 * @param pRetVal Pointer to the variable that receives return value of the function.
 * @return TRUE if success or FALSE in case of error.
 */
BOOL KfCallAddr(PVOID ProcAddr, PVOID *Args, DWORD dwArgsCount, PVOID *pRetVal);

/**
 * Get system call number by appropriate native API function name.
 *
 * @param lpszProcName Name of the function.
 * @param pdwRet Pointer to the variable that receives system call number.
 * @return TRUE if success or FALSE in case of error.
 */
BOOL KfGetSyscallNumber(char *lpszProcName, PDWORD pdwRet);

/**
 * Get an actual address of the function exported by ntoskrnl.exe image.
 *
 * @param lpszProcName Name of exported function.
 * @return Address of the function or NULL in case of error.
 */
PVOID KfGetKernelProcAddress(char *lpszProcName);

/**
 * Get an actual address of not exported Zw function of ntoskrnl.exe image
 * using signature based search.
 *
 * @param lpszProcName Name of Zw function.
 * @return Address of the function or NULL in case of error.
 */
PVOID KfGetKernelZwProcAddress(char *lpszProcName);

/**
 * Wrapper that uses KfCall() to execute nt!ExAllocatePool() function to allocate
 * specified amount of non paged kernel heap memory.
 *
 * @param Size Number of bytes to allocate.
 * @return Kernel address of allocated memory or NULL in case of error.
 */
PVOID KfHeapAlloc(SIZE_T Size);

/**
 * Wrapper that uses KfCall() to execute nt!ExAllocatePool() function to allocate
 * specified amount of non paged kernel heap memory and copy spcified data from
 * the user mode into the allocated memory.
 *
 * @param Size Number of bytes to allocate.
 * @param Data Data to copy into the allocated memory.
 * @return Kernel address of allocated memory or NULL in case of error.
 */
PVOID KfHeapAllocData(SIZE_T Size, PVOID Data);

/**
 * Wrapper that uses KfCall() to execute nt!ExFreePool() function to free the memory
 * that was allocated by KfHeapAlloc() or KfHeapAllocData() functions.
 *
 * @param Addr Address of the memory to free.
 */
void KfHeapFree(PVOID Addr);

/**
 * Wrapper that uses KfCall() to execute nt!memcpy() function to copy arbitrary data
 * between kernel mode and user mode or vice versa.
 *
 * @param Dst Address of the destination memory.
 * @param Src Address of the source memory.
 * @param Size Number of bytes to copy.
 * @return Destination memory address if success or NULL in case of error.
 */
PVOID KfMemCopy(PVOID Dst, PVOID Src, SIZE_T Size);

#ifdef __cplusplus

}

#endif
#endif
