#include "Exceptions.hpp"

#include <ntddk.h>

EXCEPTION_DISPOSITION ExCxxFrameHandler3(void*, uintptr_t*, void*, void*) {
	DbgBreakPoint();
	return ExceptionNestedException;
}

#if defined(DEBUG_BUILD)
extern "C" int _CrtDbgReport(
	int reportType,
	const char* filename,
	int linenumber,
	const char* moduleName,
	const char* format, ...
) {
	DbgBreakPoint();
	return 0;
}
#endif

extern "C"
_ACRTIMP int __cdecl raise(_In_ int _Signal) {
	DbgBreakPoint();
	return 0;
}

__declspec(noreturn)
_ACRTIMP void __cdecl _invoke_watson(
    _In_opt_z_ wchar_t const* _Expression,
    _In_opt_z_ wchar_t const* _FunctionName,
    _In_opt_z_ wchar_t const* _FileName,
    _In_       unsigned int _LineNo,
    _In_       uintptr_t _Reserved) {
	DbgBreakPoint();
}
