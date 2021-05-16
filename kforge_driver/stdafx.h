#pragma warning(disable: 4996)

#include <Windows.h>
#include <sddl.h>

#include "common/ntdll_defs.h"
#include "common/ntdll_undocnt.h"
#include "common/common.h"
#include "common/debug.h"
#include "common/virtmem.h"
#include "common/service.h"

#include "include/kforge_driver.h"

#include "winio.h"
