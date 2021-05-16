#include "stdafx.h"
//--------------------------------------------------------------------------------------
BOOL ServiceStart(char *lpszName, char *lpszPath, BOOL bCreate)
{
    BOOL bRet = FALSE;

    SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hManager)
    {
        SC_HANDLE hService = NULL;

        if (bCreate)
        {
            // create service for kernel-mode driver
            hService = CreateService(
                hManager, lpszName, lpszName, SERVICE_START | DELETE | SERVICE_STOP,
                SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_IGNORE,
                lpszPath, NULL, NULL, NULL, NULL, NULL
            );
            if (hService == NULL)
            {
                if (GetLastError() == ERROR_SERVICE_EXISTS)
                {
                    // open existing service
                    if ((hService = OpenService(hManager, lpszName, SERVICE_START | DELETE | SERVICE_STOP)) == NULL)
                    {
                        DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
                    }
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "CreateService() ERROR %d\n", GetLastError());
                }
            }
        }        
        else
        {
            // open existing service
            hService = OpenService(hManager, lpszName, SERVICE_START | DELETE | SERVICE_STOP);
        }

        if (hService)
        {
            // start service
            if (StartService(hService, 0, NULL))
            {
                bRet = TRUE;
            }
            else
            {
                if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                {
                    // service is already started
                    bRet = TRUE;
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "StartService() ERROR %d\n", GetLastError());
                }
            }

            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hManager);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL ServiceStop(char *lpszName)
{
    BOOL bRet = FALSE;

    SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hManager)
    {
        // open existing service
        SC_HANDLE hService = OpenService(hManager, lpszName, SERVICE_ALL_ACCESS);
        if (hService)
        {
            SERVICE_STATUS Status;

            // stop service
            if (ControlService(hService, SERVICE_CONTROL_STOP, &Status))
            {
                bRet = TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "ControlService() ERROR %d\n", GetLastError());
            }

            CloseServiceHandle(hService);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
        }

        CloseServiceHandle(hManager);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL ServiceRemove(char *lpszName)
{
    BOOL bRet = FALSE;

    SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hManager)
    {
        // open existing service
        SC_HANDLE hService = OpenService(hManager, lpszName, SERVICE_ALL_ACCESS);
        if (hService)
        {
            // delete service
            if (DeleteService(hService))
            {
                bRet = TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "DeleteService() ERROR %d\n", GetLastError());
            }

            CloseServiceHandle(hService);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
        }

        CloseServiceHandle(hManager);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
// EoF
