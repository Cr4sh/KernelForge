#include "stdafx.h"
//--------------------------------------------------------------------------------------
char *GetNameFromFullPath(char *lpszPath)
{
    char *lpszName = lpszPath;

    for (size_t i = 0; i < strlen(lpszPath); i++)
    {
        if (lpszPath[i] == '\\' || lpszPath[i] == '/')
        {
            lpszName = lpszPath + i + 1;
        }
    }

    return lpszName;
}
//--------------------------------------------------------------------------------------
BOOL ReadFromFile(HANDLE hFile, PVOID *pData, PDWORD pdwDataSize)
{
    BOOL bRet = FALSE;

    DWORD dwDataSizeHigh = 0;
    DWORD dwDataSize = GetFileSize(hFile, &dwDataSizeHigh);
    if (dwDataSize > 0)
    {
        if (dwDataSizeHigh != 0)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: File is too large\n");
            return FALSE;
        }

        PVOID Data = M_ALLOC(dwDataSize);
        if (Data)
        {
            DWORD dwReaded = 0;

            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

            if (ReadFile(hFile, Data, dwDataSize, &dwReaded, NULL))
            {
                *pData = Data;
                *pdwDataSize = dwDataSize;

                bRet = TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ReadFile() ERROR %d\n", GetLastError());
                
                M_FREE(Data);
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): File is empty\n");
    }

    return bRet;
}

BOOL ReadFromFile(LPCTSTR lpszFileName, PVOID *pData, PDWORD pdwDataSize)
{
    BOOL bRet = FALSE;

    // open file for reading
    HANDLE hFile = CreateFile(
        lpszFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, OPEN_EXISTING, 0, NULL
    );
    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (pData == NULL || pdwDataSize == NULL)
        {
            // just check for existing file
            bRet = TRUE;
        }
        else
        {
            // read data from the file
            bRet = ReadFromFile(hFile, pData, pdwDataSize);
        }

        CloseHandle(hFile);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CreateFile() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL DumpToFile(HANDLE hFile, PVOID Data, DWORD dwDataSize)
{
    BOOL bRet = FALSE;
    DWORD dwWritten = 0;

    // write starting from the beginning of the file
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    if (WriteFile(hFile, Data, dwDataSize, &dwWritten, NULL))
    {
        SetEndOfFile(hFile);
        bRet = TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "WriteFile() ERROR %d\n", GetLastError());
    }

    return bRet;
}

BOOL DumpToFile(char *lpszFileName, PVOID Data, DWORD dwDataSize)
{
    BOOL bRet = FALSE;

    // open file for writing
    HANDLE hFile = CreateFile(lpszFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        // write data to the file
        bRet = DumpToFile(hFile, Data, dwDataSize);
        CloseHandle(hFile);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CreateFile() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
int LoadPrivileges(char *lpszName)
{
    BOOL bRet = FALSE;
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES Privs;
    LUID Luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        DbgMsg(__FILE__, __LINE__, "OpenProcessToken() ERROR %d\n", GetLastError());
        goto _end;
    }

    if (!LookupPrivilegeValueA(NULL, lpszName, &Luid))
    {
        DbgMsg(__FILE__, __LINE__, "LookupPrivilegeValue() ERROR %d\n", GetLastError());
        goto _end;
    }

    Privs.PrivilegeCount = 1;
    Privs.Privileges[0].Luid = Luid;
    Privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &Privs, sizeof (Privs), NULL, NULL))
    {
        DbgMsg(__FILE__, __LINE__, "AdjustTokenPrivileges() ERROR %d\n", GetLastError());
        goto _end;
    }

    bRet = TRUE;

_end:

    if (hToken)
    {
        CloseHandle(hToken);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass)
{
    NTSTATUS Status = 0;
    ULONG RetSize = 0, Size = 0x100;
    PVOID Info = NULL;

    GET_NATIVE(NtQuerySystemInformation);

    if (f_NtQuerySystemInformation == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Unable to obtain needed functions\n");
        return NULL;
    }

    while (true)
    {
        RetSize = 0;

        // allocate memory for system information
        if ((Info = M_ALLOC(Size)) == NULL)
        {
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
            return NULL;
        }

        // query information        
        if ((Status = f_NtQuerySystemInformation(InfoClass, Info, Size, &RetSize)) == STATUS_INFO_LENGTH_MISMATCH)
        {
            // buffer is too small
            M_FREE(Info);

            // allocate more memory and try again
            Size = RetSize + 0x100;            
        }
        else
        {
            break;
        }
    }

    if (!NT_SUCCESS(Status))
    {
        DbgMsg(__FILE__, __LINE__, "NtQuerySystemInformation() ERROR 0x%.8x\n", Status);

        if (Info)
        {
            // cleanup
            M_FREE(Info);
        }

        return NULL;
    }

    return Info;
}
//--------------------------------------------------------------------------------------
DWORD GetThreadState(DWORD dwProcessId, DWORD dwThreadId)
{
    DWORD Ret = -1;

    // query processes and threads information
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = 
        (PSYSTEM_PROCESS_INFORMATION)GetSystemInformation(SystemProcessInformation);

    if (ProcessInfo)
    {
        PSYSTEM_PROCESS_INFORMATION Info = ProcessInfo;

        while (true)
        {
            // check for desired process
            if (Info->UniqueProcessId == (HANDLE)dwProcessId)
            {
                // enumerate treads
                for (DWORD i = 0; i < Info->NumberOfThreads; i += 1)
                {
                    // check for desired thread
                    if (Info->Threads[i].ClientId.UniqueThread == (HANDLE)dwThreadId)
                    {
                        Ret = Info->Threads[i].ThreadState;
                        goto _end;
                    }
                }

                break;
            }

            if (Info->NextEntryOffset == 0)
            {
                // end of the list
                break;
            }

            // go to the next process info entry
            Info = (PSYSTEM_PROCESS_INFORMATION)RVATOVA(Info, Info->NextEntryOffset);
        }
_end:
        M_FREE(ProcessInfo);
    }

    return Ret;
}
//--------------------------------------------------------------------------------------
PVOID GetObjectAddress(HANDLE hObject)
{
    PVOID Ret = NULL;

    // query all system handles information
    PSYSTEM_HANDLE_INFORMATION HandleInfo = 
        (PSYSTEM_HANDLE_INFORMATION)GetSystemInformation(SystemHandleInformation);

    if (HandleInfo)
    {
        for (DWORD i = 0; i < HandleInfo->NumberOfHandles; i += 1)
        {
            // lookup for pointer to the our object
            if (HandleInfo->Handles[i].UniqueProcessId == GetCurrentProcessId() &&
                HandleInfo->Handles[i].HandleValue == (USHORT)hObject)
            {
                Ret = HandleInfo->Handles[i].Object;
                break;
            }
        }

        M_FREE(HandleInfo);
    }

    return Ret;
}
//--------------------------------------------------------------------------------------
// EoF
