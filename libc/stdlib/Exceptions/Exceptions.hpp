#pragma once

#include <excpt.h>

extern "C" {
	EXCEPTION_DISPOSITION ExCxxFrameHandler3(
		__in void *,
		__in uintptr_t*,
		__in void*,
		__in void*);
}