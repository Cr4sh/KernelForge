#include "stdafx.h"
//--------------------------------------------------------------------------------------
BOOL DllInject(HANDLE ProcessId, PVOID Data, DWORD dwDataSize)
{
    BOOL bRet = FALSE;

    PVOID Image = NULL;
    DWORD dwImageSize = 0;
    
    DWORD_PTR Status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess = NULL, hThread = NULL;
    PVOID ImageAddr = NULL, ShellcodeAddr = NULL;
    SIZE_T ImageSize = 0, ShellcodeSize = 0;

    // map image sections to the memory
    if (!LdrMapImage(Data, dwDataSize, &Image, &dwImageSize))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: LdrMapImage() fails\n");
        return FALSE;
    }

    // calculate shellcode and DLL_INJECT_STRUCT size
    DWORD dwShellcodeSize = (DWORD)((DWORD_PTR)&dll_inject_End - (DWORD_PTR)&dll_inject_Entry);
    DWORD dwInjectStructSize = sizeof(DLL_INJECT_STRUCT) + dwShellcodeSize;

    DbgMsg(__FILE__, __LINE__, "DLL inject shellcode size is %d bytes\n", dwInjectStructSize);

    PDLL_INJECT_STRUCT InjectStruct = (PDLL_INJECT_STRUCT)M_ALLOC(dwInjectStructSize);
    if (InjectStruct == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n\n", GetLastError());
        goto _end;
    }

    CopyMemory(InjectStruct->Shellcode, &dll_inject_Entry, dwShellcodeSize);

    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES ObjAttr;
    
    ImageSize = dwImageSize;
    ShellcodeSize = dwInjectStructSize;

    InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    ClientId.UniqueProcess = ProcessId;
    ClientId.UniqueThread = NULL;

    PVOID Args_1[] = { KF_ARG(&hProcess),                   // ProcessHandle
                       KF_ARG(PROCESS_ALL_ACCESS),          // DesiredAccess
                       KF_ARG(&ObjAttr),                    // ObjectAttributes
                       KF_ARG(&ClientId) };                 // ClientId

    // open the target process
    if (!KfCall("ZwOpenProcess", Args_1, 4, KF_RET(&Status)))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        goto _end;
    }

    if (NT_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ZwOpenProcess() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    PVOID Args_2[] = { KF_ARG(hProcess),                    // ProcessHandle    
                       KF_ARG(&ImageAddr),                  // BaseAddress
                       KF_ARG(0),                           // ZeroBits
                       KF_ARG(&ImageSize),                  // RegionSize
                       KF_ARG(MEM_COMMIT | MEM_RESERVE),    // AllocationType
                       KF_ARG(PAGE_EXECUTE_READWRITE) };    // Protect

    // allocate memory for the DLL image
    if (!KfCall("ZwAllocateVirtualMemory", Args_2, 6, KF_RET(&Status)))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        goto _end;
    }

    if (NT_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ZwAllocateVirtualMemory() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    DbgMsg(__FILE__, __LINE__, "DLL image memory was allocated at "IFMT"\n", ImageAddr);

    // relocate DLL image file to the new base address
    if (!LdrProcessRelocs(Image, ImageAddr))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: LdrProcessRelocs() fails\n");
        goto _end;
    }

    InjectStruct->ModuleBase = ImageAddr;

    PVOID Args_3[] = { KF_ARG(hProcess),                    // ProcessHandle    
                       KF_ARG(ImageAddr),                   // BaseAddress
                       KF_ARG(Image),                       // Buffer
                       KF_ARG(ImageSize),                   // NumberOfBytesToWrite
                       KF_ARG(NULL) };                      // NumberOfBytesWritten

    // write DLL image into the process memory
    if (!KfCall("ZwWriteVirtualMemory", Args_3, 5, KF_RET(&Status)))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        goto _end;
    }

    if (NT_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ZwWriteVirtualMemory() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    PVOID Args_4[] = { KF_ARG(hProcess),                    // ProcessHandle    
                       KF_ARG(&ShellcodeAddr),              // BaseAddress
                       KF_ARG(0),                           // ZeroBits
                       KF_ARG(&ShellcodeSize),              // RegionSize
                       KF_ARG(MEM_COMMIT | MEM_RESERVE),    // AllocationType
                       KF_ARG(PAGE_EXECUTE_READWRITE) };    // Protect

    // allocate memory for the shellcode
    if (!KfCall("ZwAllocateVirtualMemory", Args_4, 6, KF_RET(&Status)))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        goto _end;
    }

    if (NT_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ZwAllocateVirtualMemory() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    DbgMsg(__FILE__, __LINE__, "Shellcode memory was allocated at "IFMT"\n", ShellcodeAddr);

    PVOID Args_5[] = { KF_ARG(hProcess),                    // ProcessHandle    
                       KF_ARG(ShellcodeAddr),               // BaseAddress
                       KF_ARG(InjectStruct),                // Buffer
                       KF_ARG(ShellcodeSize),               // NumberOfBytesToWrite
                       KF_ARG(NULL) };                      // NumberOfBytesWritten

    // write shellcode into the process memory
    if (!KfCall("ZwWriteVirtualMemory", Args_5, 5, KF_RET(&Status)))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        goto _end;
    }

    if (NT_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ZwWriteVirtualMemory() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    PVOID StartAddress = RVATOVA(ShellcodeAddr, FIELD_OFFSET(DLL_INJECT_STRUCT, Shellcode));

    PVOID Args_6[] = { KF_ARG(hProcess),                    // ProcessHandle
                       KF_ARG(NULL),                        // SecurityDescriptor
                       KF_ARG(FALSE),                       // CreateSuspended
                       KF_ARG(0),                           // StackZeroBits
                       KF_ARG(NULL),                        // StackReserved
                       KF_ARG(NULL),                        // StackCommit
                       KF_ARG(StartAddress),                // StartAddress 
                       KF_ARG(ShellcodeAddr),               // StartParameter
                       KF_ARG(&hThread),                    // ThreadHandle
                       KF_ARG(&ClientId) };                 // ClientId

    // create new thread to execute DLL load shellcode
    if (!KfCall("RtlCreateUserThread", Args_6, 10, KF_RET(&Status)))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        goto _end;
    }

    if (NT_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "RtlCreateUserThread() ERROR 0x%.8x\n", Status);
        goto _end;
    }

    if (hThread)
    {
        PVOID Args[] = { KF_ARG(hThread) };

        // close created thread handle
        if (KfCall("ZwClose", Args, 1, KF_RET(&Status)))
        {
            if (NT_ERROR(Status))
            {
                DbgMsg(__FILE__, __LINE__, "ZwClose() ERROR 0x%.8x\n", Status);
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        }
    }

    bRet = TRUE;

_end:

    if (hProcess)
    {
        PVOID Args[] = { KF_ARG(hProcess) }; 

        // close target process handle
        if (KfCall("ZwClose", Args, 1, KF_RET(&Status)))
        {
            if (NT_ERROR(Status))
            {
                DbgMsg(__FILE__, __LINE__, "ZwClose() ERROR 0x%.8x\n", Status);
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
        }
    }

    if (NT_ERROR(Status))
    {
        // perform cleanup on error
        if (ShellcodeAddr)
        {
            PVOID Args[] = { KF_ARG(hProcess),              // ProcessHandle
                             KF_ARG(&ShellcodeAddr),        // BaseAddress
                             KF_ARG(&ShellcodeSize),        // RegionSize
                             KF_ARG(MEM_RELEASE) };         // FreeType

            // free shellcode memory
            if (KfCall("ZwFreeVirtualMemory", Args, 4, KF_RET(&Status)))
            {
                if (NT_ERROR(Status))
                {
                    DbgMsg(__FILE__, __LINE__, "ZwFreeVirtualMemory() ERROR 0x%.8x\n", Status);
                }
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
            }
        }

        if (ImageAddr)
        {
            PVOID Args[] = { KF_ARG(hProcess),              // ProcessHandle
                             KF_ARG(&ImageAddr),            // BaseAddress
                             KF_ARG(&ImageSize),            // RegionSize
                             KF_ARG(MEM_RELEASE) };         // FreeType

            // free DLL image memory
            if (KfCall("ZwFreeVirtualMemory", Args, 4, KF_RET(&Status)))
            {
                if (NT_ERROR(Status))
                {
                    DbgMsg(__FILE__, __LINE__, "ZwFreeVirtualMemory() ERROR 0x%.8x\n", Status);
                }
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: KfCall() fails\n");
            }
        }        
    }

    if (InjectStruct)
    {
        M_FREE(InjectStruct);
    }

    if (Image)
    {
        M_FREE(Image);
    }    

    return bRet;
}
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{   
    int Ret = -1;

    if (argc < 3)
    {
        printf("USAGE: kforge_example.exe <PID> <DLL_path>\n");
        return -1;
    }

    HANDLE ProcessId = 0;
    char *lpszPath = argv[2];

    // read target process id
    if (!StrToIntEx(argv[1], 0, (int *)&ProcessId))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Invalid PID\n");
        return -1;
    }

    DbgMsg(__FILE__, __LINE__, "Target process PID = %I64d\n", ProcessId);

    PVOID Data = NULL;
    DWORD dwDataSize = 0;

    // read DLL image file contents
    if (!ReadFromFile(lpszPath, &Data, &dwDataSize))
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't read DLL image file\n");
        return -1;
    }

    DbgMsg(__FILE__, __LINE__, "%d bytes of DLL image read from %s\n", dwDataSize, lpszPath);    

    // initialize kernel forge library
    if (KfInit())
    {
        // perform DLL injection
        if (DllInject(ProcessId, Data, dwDataSize))
        {
            DbgMsg(__FILE__, __LINE__, "DLL was successfully injected!\n");

            Ret = 0;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: DllInject() fails\n");
        }

        // uninitialize the library
        KfUninit();
    }

    M_FREE(Data);    

    return Ret;
}
//--------------------------------------------------------------------------------------
// EoF
