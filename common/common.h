
#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))

// numeric values alignment
#define _ALIGN_DOWN(_val_, _align_) ((_val_) & ~((_align_) - 1))
#define _ALIGN_UP(_val_, _align_) (((_val_) & ((_align_) - 1)) ? _ALIGN_DOWN((_val_), (_align_)) + (_align_) : (_val_))

#define _HI_DWORD(_qw_) ((ULONG)(((ULONG64)(_qw_) >> 32) & 0xffffffff))
#define _LO_DWORD(_qw_) ((ULONG)(ULONG64)(_qw_))

#define _LO_WORD(_dw_) ((USHORT)(((ULONG)(_dw_)) & 0xffff))
#define _HI_WORD(_dw_) ((USHORT)((((ULONG)(_dw_)) >> 16) & 0xffff))

#define _LO_BYTE(_w_) ((UCHAR)(((ULONG)(_w_)) & 0xff))
#define _HI_BYTE(_w_) ((UCHAR)((((ULONG)(_w_)) >> 8) & 0xff))

// heap allocation functions
#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (_size_))
#define M_FREE(_addr_) LocalFree((_addr_))

#define TIME_ABSOLUTE(_t_) (_t_)
#define TIME_RELATIVE(_t_) (-(_t_))

// waitable timers macro definitions
#define TIME_NANOSECONDS(_t_)   (((signed __int64)(_t_)) / 100L)
#define TIME_MICROSECONDS(_t_)  (((signed __int64)(_t_)) * TIME_NANOSECONDS(1000L))
#define TIME_MILLISECONDS(_t_)  (((signed __int64)(_t_)) * TIME_MICROSECONDS(1000L))
#define TIME_SECONDS(_t_)       (((signed __int64)(_t_)) * TIME_MILLISECONDS(1000L))

// atomic access wrappers
#define INTERLOCKED_INC(_addr_) InterlockedIncrement((LONG *)(_addr_))
#define INTERLOCKED_GET(_addr_) InterlockedExchangeAdd((LONG *)(_addr_), 0)
#define INTERLOCKED_SET(_addr_, _val_) InterlockedExchange((LONG *)(_addr_), (LONG)(_val_))

#ifdef _X86_

#define INTERLOCKED_PTR_GET(_addr_) INTERLOCKED_GET(_addr_)
#define INTERLOCKED_PTR_SET(_addr_, _val_) INTERLOCKED_PTR_SET(_addr_, _val_)

#else _AMD64_

#define INTERLOCKED_PTR_GET(_addr_) InterlockedExchangeAdd64((LONGLONG *)(_addr_), 0)
#define INTERLOCKED_PTR_SET(_addr_, _val_) InterlockedExchangeAdd64((LONGLONG *)(_addr_), (LONGLONG)(_val_))

#endif


#define PAGE_SHIFT 12
#define PAGE_SIZE 0x1000

#define IFMT32 "0x%.8x"
#define IFMT64 "0x%.16I64x"

#define IFMT32_W L"0x%.8x"
#define IFMT64_W L"0x%.16I64x"

#ifdef _X86_

// 32-bit pointers format string
#define IFMT IFMT32
#define IFMT_W IFMT32_W

#else _AMD64_

// 64-bit pointers format string
#define IFMT IFMT64
#define IFMT_W IFMT64_W

#endif


#define GET_IMPORT(_lib_, _name_)                               \
                                                                \
    func_##_name_ f_##_name_ = (func_##_name_)GetProcAddress(   \
        LoadLibrary((_lib_)), #_name_);


#define GET_NATIVE(_name_) GET_IMPORT("ntdll.dll", _name_)


char *GetNameFromFullPath(char *lpszPath);

BOOL ReadFromFile(HANDLE hFile, PVOID *pData, PDWORD pdwDataSize);
BOOL ReadFromFile(LPCTSTR lpszFileName, PVOID *pData, PDWORD pdwDataSize);

BOOL DumpToFile(HANDLE hFile, PVOID Data, DWORD dwDataSize);
BOOL DumpToFile(char *lpszFileName, PVOID Data, DWORD dwDataSize);

BOOL LoadPrivileges(char *lpszName);

PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass);
DWORD GetThreadState(DWORD dwProcessId, DWORD dwThreadId);
PVOID GetObjectAddress(HANDLE hObject);
