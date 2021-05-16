#pragma once
#pragma warning(disable: 4200)
#pragma warning(disable: 4996)

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <conio.h>

#include <Windows.h>
#include <sddl.h>
#include <Shlwapi.h>

#include "common/ntdll_defs.h"
#include "common/ntdll_undocnt.h"
#include "common/common.h"
#include "common/debug.h"
#include "common/peimage.h"

#include "include/kforge_library.h"

#include "dll_inject_shellcode.h"
