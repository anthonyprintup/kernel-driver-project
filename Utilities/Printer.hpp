#pragma once

#include <Framework/Utilities/Strings/Fnv1A.hpp>
#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../Configuration.hpp"
#include "../Miscellaneous/Globals.hpp"

#include <intrin.h>
namespace KM::Utilities::Printer {
	template<class ...Arguments>
	void print(const char *format, Arguments &&...arguments) {
		if constexpr (::Configuration::print) {
			VM_SIZE_BEGIN
			namespace nt = Miscellaneous::Globals::NT;
			nt::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), std::forward<Arguments>(arguments)...);
			VM_SIZE_END
			__nop(); // Prevent tailcall optimizations
		}
	}
}
#define PRINT_IF_DEBUG(...) if constexpr (::Configuration::debug) KM::Utilities::Printer::print(__VA_ARGS__);
