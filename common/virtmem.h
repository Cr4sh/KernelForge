
#pragma pack(1)

//
// Page Map Level 4 Offset (PML4) and
// Page Directory Pointer Table (PDPE) entries 4K & 2M
//
typedef union 
{
    struct 
    {
        DWORD64 Present : 1;                // 0 = Not present in memory, 1 = Present in memory
        DWORD64 ReadWrite : 1;              // 0 = Read-Only, 1= Read/Write
        DWORD64 UserSupervisor : 1;         // 0 = Supervisor, 1=User
        DWORD64 WriteThrough : 1;           // 0 = Write-Back caching, 1=Write-Through caching
        DWORD64 CacheDisabled : 1;          // 0 = Cached, 1=Non-Cached
        DWORD64 Accessed : 1;               // 0 = Not accessed, 1 = Accessed (set by CPU)
        DWORD64 Reserved : 1;               // Reserved
        DWORD64 MustBeZero : 2;             // Must Be Zero
        DWORD64 Available : 3;              // Available for use by system software
        DWORD64 PageTableBaseAddress : 40;  // Page Table Base Address
        DWORD64 AvabilableHigh : 11;        // Available for use by system software
        DWORD64 Nx : 1;                     // No Execute bit

    } Bits;

    DWORD64 Uint64;

} X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K;

//
// Page Directory Entry 4K
//
typedef union 
{
    struct 
    {
        DWORD64 Present : 1;                // 0 = Not present in memory, 1 = Present in memory
        DWORD64 ReadWrite : 1;              // 0 = Read-Only, 1= Read/Write
        DWORD64 UserSupervisor : 1;         // 0 = Supervisor, 1=User
        DWORD64 WriteThrough : 1;           // 0 = Write-Back caching, 1=Write-Through caching
        DWORD64 CacheDisabled : 1;          // 0 = Cached, 1=Non-Cached
        DWORD64 Accessed : 1;               // 0 = Not accessed, 1 = Accessed (set by CPU)
        DWORD64 MustBeZero : 3;             // Must Be Zero
        DWORD64 Available : 3;              // Available for use by system software
        DWORD64 PageTableBaseAddress : 40;  // Page Table Base Address
        DWORD64 AvabilableHigh : 11;        // Available for use by system software
        DWORD64 Nx : 1;                     // No Execute bit

    } Bits;

    DWORD64 Uint64;

} X64_PAGE_DIRECTORY_ENTRY_4K;

//
// Page Table Entry 4K
//
typedef union 
{
    struct 
    {
        DWORD64 Present : 1;                // 0 = Not present in memory, 1 = Present in memory
        DWORD64 ReadWrite : 1;              // 0 = Read-Only, 1= Read/Write
        DWORD64 UserSupervisor : 1;         // 0 = Supervisor, 1=User
        DWORD64 WriteThrough : 1;           // 0 = Write-Back caching, 1=Write-Through caching
        DWORD64 CacheDisabled : 1;          // 0 = Cached, 1=Non-Cached
        DWORD64 Accessed : 1;               // 0 = Not accessed, 1 = Accessed (set by CPU)
        DWORD64 Dirty : 1;                  // 0 = Not Dirty, 1 = written by processor on access to page
        DWORD64 PAT : 1;                    // 0 = Ignore Page Attribute Table 
        DWORD64 Global : 1;                 // 0 = Not global page, 1 = global page TLB not cleared on CR3 write
        DWORD64 Available : 3;              // Available for use by system software
        DWORD64 PageTableBaseAddress : 40;  // Page Table Base Address
        DWORD64 AvabilableHigh : 11;        // Available for use by system software
        DWORD64 Nx : 1;                     // 0 = Execute Code, 1 = No Code Execution

    } Bits;
    
    DWORD64 Uint64;

} X64_PAGE_TABLE_ENTRY_4K;

//
// Page Table Entry 2M
//
typedef union 
{
    struct 
    {
        DWORD64 Present : 1;                // 0 = Not present in memory, 1 = Present in memory
        DWORD64 ReadWrite : 1;              // 0 = Read-Only, 1= Read/Write
        DWORD64 UserSupervisor : 1;         // 0 = Supervisor, 1=User
        DWORD64 WriteThrough : 1;           // 0 = Write-Back caching, 1=Write-Through caching
        DWORD64 CacheDisabled : 1;          // 0 = Cached, 1=Non-Cached
        DWORD64 Accessed : 1;               // 0 = Not accessed, 1 = Accessed (set by CPU)
        DWORD64 Dirty : 1;                  // 0 = Not Dirty, 1 = written by processor on access to page
        DWORD64 MustBe1 : 1;                // Must be 1 
        DWORD64 Global : 1;                 // 0 = Not global page, 1 = global page TLB not cleared on CR3 write
        DWORD64 Available : 3;              // Available for use by system software
        DWORD64 PAT : 1;                    //
        DWORD64 MustBeZero : 8;             // Must be zero;
        DWORD64 PageTableBaseAddress : 31;  // Page Table Base Address
        DWORD64 AvabilableHigh : 11;        // Available for use by system software
        DWORD64 Nx : 1;                     // 0 = Execute Code, 1 = No Code Execution

    } Bits;
    
    DWORD64 Uint64;

} X64_PAGE_TABLE_ENTRY_2M;

#pragma pack()

#define PFN_TO_PAGE(_val_) (((DWORD64)(_val_)) << PAGE_SHIFT)
#define PAGE_TO_PFN(_val_) (((DWORD64)(_val_)) >> PAGE_SHIFT)

// get MPL4 address from CR3 register value
#define PML4_ADDRESS(_val_) ((_val_) & 0xfffffffffffff000)

// get address translation indexes from virtual address
#define PML4_INDEX(_addr_) (((DWORD64)(_addr_) >> 39) & 0x1ff)
#define PDPT_INDEX(_addr_) (((DWORD64)(_addr_) >> 30) & 0x1ff)
#define PDE_INDEX(_addr_) (((DWORD64)(_addr_) >> 21) & 0x1ff)
#define PTE_INDEX(_addr_) (((DWORD64)(_addr_) >> 12) & 0x1ff)

// get address translation indexes to virtual address
#define PML4_ADDR(_index_) ((_index_) << 39)
#define PDPT_ADDR(_index_) ((_index_) << 30)
#define PDE_ADDR(_index_) ((_index_) << 21)
#define PTE_ADDR(_index_) ((_index_) << 12)

#define PAGE_OFFSET_4K(_addr_) ((DWORD64)(_addr_) & 0xfff)
#define PAGE_OFFSET_2M(_addr_) ((DWORD64)(_addr_) & 0x1fffff)
#define PAGE_OFFSET_1G(_addr_) ((DWORD64)(_addr_) & 0x3fffffff)

// PS flag of PDPTE and PDE
#define PDPTE_PDE_PS 0x80

// EPT present bit
#define EPT_PRESENT(_val_) (((_val_) & 7) != 0)

// PTE bits
#define PTE_PRESENT 0x1
#define PTE_RW      0x2
#define PTE_GLOBAL  0x100

// EPT permission flags
#define EPT_R(_val_) (((_val_) & 1) == 1)
#define EPT_W(_val_) (((_val_) & 2) == 2)
#define EPT_X(_val_) (((_val_) & 4) == 4)
