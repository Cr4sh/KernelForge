
// vulnerable driver device name
#define WINIO_DEVICE_PATH "\\\\.\\Global\\EneIo"

// vulnerable driver service and file name
#define WINIO_DRIVER_NAME  "winio.sys"
#define WINIO_SERVICE_NAME "winio"

#define FILE_DEVICE_WINIO 0x00008010

// map physical memory region
#define IOCTL_WINIO_PHYS_MEM_MAP CTL_CODE(FILE_DEVICE_WINIO, 0x00000810, METHOD_BUFFERED, FILE_ANY_ACCESS)

// unmap physical memory region
#define IOCTL_WINIO_PHYS_MEM_UNMAP CTL_CODE(FILE_DEVICE_WINIO, 0x00000811, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _WINIO_PHYS_MEM
{
    DWORD_PTR Size;
    DWORD_PTR Addr;
    HANDLE hSection;
    PVOID SectionAddr;
    PVOID ObjectAddr;

} WINIO_PHYS_MEM,
*PWINIO_PHYS_MEM;


BOOL WinioPhysRead(HANDLE hDevice, DWORD_PTR Addr, DWORD_PTR Size, PVOID Data);
BOOL WinioPhysWrite(HANDLE hDevice, DWORD_PTR Addr, DWORD_PTR Size, PVOID Data);
