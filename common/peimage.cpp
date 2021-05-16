#include "stdafx.h"
//--------------------------------------------------------------------------------------
DWORD LdrGetProcAddress(PVOID Image, char *lpszName)
{
    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
        Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);    

    DWORD Addr = 0;
    DWORD ExportAddr = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD ExportSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (ExportAddr != 0)
    {
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(Image, ExportAddr);

        if (pExport->AddressOfFunctions == 0 ||
            pExport->AddressOfNameOrdinals == 0 ||
            pExport->AddressOfNames == 0)
        {
            // no exports by name
            return 0;
        }

        // parse module exports
        PDWORD AddrOfFunctions = (PDWORD)RVATOVA(Image, pExport->AddressOfFunctions);
        PWORD AddrOfOrdinals = (PWORD)RVATOVA(Image, pExport->AddressOfNameOrdinals);
        PDWORD AddrOfNames = (PDWORD)RVATOVA(Image, pExport->AddressOfNames);

        for (DWORD i = 0; i < pExport->NumberOfNames; i += 1)
        {
            char *lpszExport = (char *)RVATOVA(Image, AddrOfNames[i]);

            // calculate and compare hash of function
            if (!strcmp(lpszExport, lpszName))
            {
                // get exported function RVA
                Addr = AddrOfFunctions[AddrOfOrdinals[i]];
                break;
            }
        }
    }
    else
    {
        // no export table present
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Export table is not found\n");
        return 0;
    }    

    if (Addr != 0)
    {
        // check for the forwarded export
        if (Addr > ExportAddr &&
            Addr < ExportAddr + ExportSize)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Forwarded export\n");
            return 0;
        }

        return Addr;
    }

    return 0;
}
//--------------------------------------------------------------------------------------
BOOL LdrProcessRelocs(PVOID Image, PVOID NewBase)
{
    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
        Image, ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

    DWORD_PTR OldBase = pHeaders->OptionalHeader.ImageBase;
    DWORD RelocAddr = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD RelocSize = pHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;    

    if (RelocAddr == 0)
    {
        // no image relocations are present but it's ok
        return TRUE;
    }

    DWORD Size = 0;
    PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(Image, RelocAddr);    
        
    while (RelocSize > Size && pRelocation->SizeOfBlock)
    {            
        DWORD Num = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD Rel = (PWORD)RVATOVA(pRelocation, sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < Num; i += 1)
        {
            if (Rel[i] > 0)
            {
                WORD Type = (Rel[i] & 0xF000) >> 12;

                // check for supporting type
                if (Type != IMAGE_REL_BASED_DIR64 &&
                    Type != IMAGE_REL_BASED_ABSOLUTE)
                {
                    DbgMsg(__FILE__, __LINE__, __FUNCTION__ "() ERROR: Unknown relocation type %d\n", Type);
                    return FALSE;
                }
                
                if (Type == IMAGE_REL_BASED_DIR64)
                {
                    // fix relocation value
                    *(PDWORD64)(RVATOVA(
                        Image, 
                        pRelocation->VirtualAddress + (Rel[i] & 0x0FFF))) += (DWORD64)NewBase - OldBase;
                }                
            }
        }

        // go to the next block
        pRelocation = (PIMAGE_BASE_RELOCATION)RVATOVA(pRelocation, pRelocation->SizeOfBlock);
        Size += pRelocation->SizeOfBlock;            
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
BOOL LdrMapImage(PVOID Data, DWORD dwDataSize, PVOID *pImage, PDWORD pdwImageSize)
{    
    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)RVATOVA(
        Data, ((PIMAGE_DOS_HEADER)Data)->e_lfanew);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)RVATOVA(
        &pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

    DWORD dwImageSize = pHeaders->OptionalHeader.SizeOfImage;    

    // allocate image memory
    PVOID Image = M_ALLOC(dwImageSize);
    if (Image)
    {          
        // copy image headers
        ZeroMemory(Image, dwImageSize);
        CopyMemory(Image, Data, pHeaders->OptionalHeader.SizeOfHeaders);

        // copy image sections        
        for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i += 1)
        {
            memcpy(
                RVATOVA(Image, pSection->VirtualAddress),
                RVATOVA(Data, pSection->PointerToRawData),
                min(pSection->SizeOfRawData, pSection->Misc.VirtualSize)
            );

            pSection += 1;
        }    

        *pImage = Image;
        *pdwImageSize = dwImageSize;

        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n\n", GetLastError());
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
// EoF
