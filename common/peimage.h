
DWORD LdrGetProcAddress(PVOID Image, char *lpszName);
BOOL LdrProcessRelocs(PVOID Image, PVOID NewBase);
BOOL LdrMapImage(PVOID Data, DWORD dwDataSize, PVOID *Image, PDWORD pdwImageSize);
