#pragma once

#include <sal.h>

extern "C" {
	void *__cdecl malloc(__in size_t size);
	void  __cdecl free(__inout void *pointer);
	void *__cdecl realloc(__inout_opt void *pointer, __in size_t size);
	void *__cdecl calloc(__in size_t count, __in size_t size);
}