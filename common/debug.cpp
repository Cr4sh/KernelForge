#include "stdafx.h"
//--------------------------------------------------------------------------------------
#ifdef DBG

void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    va_list arg_list;
    va_start(arg_list, lpszMsg);

    int Len = _vscprintf(lpszMsg, arg_list) + MAX_PATH;

    char *lpszBuff = (char *)M_ALLOC(Len);
    if (lpszBuff == NULL)
    {
        va_end(arg_list);
        return;
    }

    char *lpszOutBuff = (char *)M_ALLOC(Len);
    if (lpszOutBuff == NULL)
    {
        M_FREE(lpszBuff);
        va_end(arg_list);
        return;
    }

    vsprintf(lpszBuff, lpszMsg, arg_list);
    va_end(arg_list);

    sprintf(lpszOutBuff, "%s(%d) : %s", GetNameFromFullPath(lpszFile), Line, lpszBuff);

    // write message into the debug output
    OutputDebugStringA(lpszOutBuff);

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;

        // write message into the console
        WriteFile(hStd, lpszOutBuff, lstrlen(lpszOutBuff), &dwWritten, NULL);
    }

    M_FREE(lpszBuff);
    M_FREE(lpszOutBuff);
}

#endif // DBG
//--------------------------------------------------------------------------------------
// EoF
