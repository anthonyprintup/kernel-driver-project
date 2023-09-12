#include <vcruntime.h>
#include <ntifs.h>

#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../../../Configuration.hpp"
#include "../../../Miscellaneous/Globals.hpp"

extern "C"
void __cdecl _wassert(__in_z const wchar_t *message,
					  __in_z const wchar_t *file,
					  __in   const unsigned line) {
	VM_MEDIUM_BEGIN
	namespace nt = KM::Miscellaneous::Globals::NT;
	nt::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_INFO_LEVEL, xorstr_("%ws:%ws %u"), file, message, line);
	VM_MEDIUM_END
}
