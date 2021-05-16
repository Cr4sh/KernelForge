
typedef LONG NTSTATUS; 

typedef struct _IO_STATUS_BLOCK 
{
    union 
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    
    ULONG_PTR Information;

} IO_STATUS_BLOCK, 
*PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;

} CLIENT_ID, 
*PCLIENT_ID;

#ifndef _NTSECAPI_

typedef struct _UNICODE_STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;

} UNICODE_STRING, 
*PUNICODE_STRING;

#endif

typedef struct _STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;

} ANSI_STRING, 
*PANSI_STRING;

#define OBJ_INHERIT                     0x00000002
#define OBJ_PERMANENT                   0x00000010
#define OBJ_EXCLUSIVE                   0x00000020
#define OBJ_CASE_INSENSITIVE            0x00000040
#define OBJ_OPENIF                      0x00000080
#define OBJ_OPENLINK                    0x00000100
#define OBJ_VALID_ATTRIBUTES            0x000001F2
#define OBJ_KERNEL_HANDLE               0x00000200

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;

} OBJECT_ATTRIBUTES, 
*POBJECT_ATTRIBUTES;


#define InitializeObjectAttributes(_ptr_, _name_, _attr_, _root_, _sd_)     \
                                                                            \
    {                                                                       \
        (_ptr_)->Length = sizeof(OBJECT_ATTRIBUTES);                        \
        (_ptr_)->RootDirectory = (_root_);                                  \
        (_ptr_)->Attributes = (_attr_);                                     \
        (_ptr_)->ObjectName = (_name_);                                     \
        (_ptr_)->SecurityDescriptor = (_sd_);                               \
        (_ptr_)->SecurityQualityOfService = NULL;                           \
    }


#define NT_SUCCESS(Status) ((LONG)(Status) >= 0)
#define NT_ERROR(Status)  ((ULONG)(Status) >> 30 == 3)

#define NtCurrentProcess() ((HANDLE)-1)
#define NtCurrentThread()  ((HANDLE)-2)

#define STATUS_BUFFER_OVERFLOW          0x80000005L
#define STATUS_NO_MORE_FILES            0x80000006L
#define STATUS_INFO_LENGTH_MISMATCH     0xC0000004L
#define STATUS_BUFFER_TOO_SMALL         0xC0000023L
#define STATUS_UNSUCCESSFUL             0xC0000001L
#define STATUS_IMAGE_ALREADY_LOADED     0xC000010EL
