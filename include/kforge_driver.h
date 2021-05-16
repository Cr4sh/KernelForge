#ifndef _KFORGE_DRIVER_H_
#define _KFORGE_DRIVER_H_

#ifdef __cplusplus

extern "C"
{

#endif

BOOL DriverInit(void);
BOOL DriverUninit(void);

BOOL DriverMemWritePtr(PVOID Addr, PVOID Value);
BOOL DriverMemWrite(PVOID Addr, PVOID Data, DWORD_PTR DataSize);

BOOL DriverMemReadPtr(PVOID Addr, PVOID *Value);
BOOL DriverMemRead(PVOID Addr, PVOID Data, DWORD_PTR DataSize);

#ifdef __cplusplus

}

#endif
#endif
