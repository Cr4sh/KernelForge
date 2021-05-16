#include "stdafx.h"
//--------------------------------------------------------------------------------------
static BOOL WinioPhysMap(
    HANDLE hDevice, DWORD_PTR Addr, DWORD_PTR Size,
    HANDLE *phSection, PVOID *pSectionAddr, PVOID *pObjectAddr)
{
    DWORD dwSize = 0;
    WINIO_PHYS_MEM Request;    

    ZeroMemory(&Request, sizeof(Request));

    Request.Size = Size;
    Request.Addr = Addr;

    // send physical memory map request
    if (DeviceIoControl(
        hDevice, IOCTL_WINIO_PHYS_MEM_MAP,
        &Request, sizeof(Request), &Request, sizeof(Request), &dwSize, NULL))
    {
        *phSection = Request.hSection;
        *pObjectAddr = Request.ObjectAddr;
        *pSectionAddr = Request.SectionAddr;               

        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
static BOOL WinioPhysUnmap(HANDLE hDevice, HANDLE hSection, PVOID SectionAddr, PVOID ObjectAddr)
{
    DWORD dwSize = 0;
    WINIO_PHYS_MEM Request;

    ZeroMemory(&Request, sizeof(Request));

    Request.hSection = hSection;
    Request.SectionAddr = SectionAddr;
    Request.ObjectAddr = ObjectAddr;

    // send physical memory unmap request
    if (DeviceIoControl(
        hDevice, IOCTL_WINIO_PHYS_MEM_UNMAP,
        &Request, sizeof(Request), &Request, sizeof(Request), &dwSize, NULL))
    {
        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL WinioPhysRead(HANDLE hDevice, DWORD_PTR Addr, DWORD_PTR Size, PVOID Data)
{
    BOOL bRet = FALSE;
    HANDLE hSection = NULL;
    PVOID SectionAddr = NULL, ObjectAddr = NULL;

    // map physical memory region
    if (!WinioPhysMap(hDevice, Addr, Size, &hSection, &SectionAddr, &ObjectAddr))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: WinioPhysMemMap() fails\n");
        return FALSE;
    }

    __try
    {
        // perform memory read operation
        bRet = memcpy(Data, SectionAddr, Size) != NULL;
    }
    __finally
    {
        // unmap physical memory region
        WinioPhysUnmap(hDevice, hSection, SectionAddr, ObjectAddr);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL WinioPhysWrite(HANDLE hDevice, DWORD_PTR Addr, DWORD_PTR Size, PVOID Data)
{
    BOOL bRet = FALSE;
    HANDLE hSection = NULL;
    PVOID SectionAddr = NULL, ObjectAddr = NULL;

    // map physical memory region
    if (!WinioPhysMap(hDevice, Addr, Size, &hSection, &SectionAddr, &ObjectAddr) != 0)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: WinioPhysMemMap() fails\n");
        return FALSE;
    }

    __try
    {
        // perform memory write operation
        bRet = memcpy(SectionAddr, Data, Size) != NULL;
    }
    __finally
    {
        // unmap physical memory region
        WinioPhysUnmap(hDevice, hSection, SectionAddr, ObjectAddr);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
// EoF
