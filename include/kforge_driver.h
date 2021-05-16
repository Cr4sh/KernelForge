
BOOL DriverInit(void);
BOOL DriverUninit(void);

BOOL DriverMemWritePtr(PVOID Addr, PVOID Value);
BOOL DriverMemWrite(PVOID Addr, PVOID Data, DWORD_PTR DataSize);

BOOL DriverMemReadPtr(PVOID Addr, PVOID *Value);
BOOL DriverMemRead(PVOID Addr, PVOID Data, DWORD_PTR DataSize);
