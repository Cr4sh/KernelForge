#pragma once
#pragma warning(disable: 4200)
#pragma warning(disable: 4996)

#include "targetver.h"

// exclude rarely-used stuff from Windows headers
#define WIN32_LEAN_AND_MEAN             

#include <stdio.h>
#include <windows.h>
#include <sddl.h>

#include "common/ntdll_defs.h"
#include "common/ntdll_undocnt.h"
#include "common/common.h"
#include "common/debug.h"
