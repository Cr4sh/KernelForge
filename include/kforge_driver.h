#ifndef _KFORGE_DRIVER_H_
#define _KFORGE_DRIVER_H_

#ifdef __cplusplus

extern "C"
{

#endif

/**
 * Initialize kernel driver or local exploit that provies arbitrary 
 * memory read write primitives.
 *
 * @return TRUE if success or FALSE in case of error.
 */
BOOL DriverInit(void);

/**
 * Uninitialize kernel driver or local exploit.
 *
 * @return TRUE if success or FALSE in case of error.
 */
BOOL DriverUninit(void);

/**
 * Read kernel virtual address space memory.
 *
 * @param Addr Source address to read from.
 * @param Data Destination buffer to store read data.
 * @param DataSize Number of bytes to read.
 * @return TRUE if success or FALSE in case of error.
 */
BOOL DriverMemRead(PVOID Addr, PVOID Data, DWORD_PTR DataSize);

/**
 * Write kernel virtual address space memory.
 *
 * @param Addr Destination address to write into.
 * @param Data Source buffer with data to write.
 * @param DataSize Number of bytes to write.
 * @return TRUE if success or FALSE in case of error.
 */
BOOL DriverMemWrite(PVOID Addr, PVOID Data, DWORD_PTR DataSize);

#ifdef __cplusplus

}

#endif
#endif
