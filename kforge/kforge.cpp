#include "stdafx.h"

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    
        // initialize kforge library
        return KfInit();

    case DLL_PROCESS_DETACH:
        
        // uninitialize kforge library
        return KfUninit();
    }

    return TRUE;
}
