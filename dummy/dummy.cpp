#include "stdafx.h"
//--------------------------------------------------------------------------------------
DWORD WINAPI DllThread(LPVOID lpParam)
{
    char szPath[MAX_PATH];
    char szText[MAX_PATH + 0x100];

    // obtain process executable path
    GetModuleFileName(GetModuleHandle(NULL), szPath, MAX_PATH);

    sprintf(szText, "Running in \"%s\", PID = %d", szPath, GetCurrentProcessId());

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): %s\n", szText);

    MessageBox(0, szText, __FUNCTION__"()", MB_ICONINFORMATION);

    return 0;
}
//--------------------------------------------------------------------------------------
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // show message in separate thread to avoid loader locks
        HANDLE hThread = CreateThread(NULL, 0, DllThread, NULL, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "CreateThread() ERROR %d\n", GetLastError());
        }

        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:

        break;
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
// EoF
