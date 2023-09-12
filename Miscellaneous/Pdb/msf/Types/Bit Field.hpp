#pragma once

#include "../Record.hpp"

namespace msf::types {
	struct BitField {
		// Underlying type identifier e.g. `VOID`, `INT64`, `STRUCTURE`
		UnderlyingType underlyingType {};
		// Type index of the underlying type
		std::size_t typeIndex {};
		// Size in bits
		std::size_t size {};
		// Offset from the base
		std::ptrdiff_t offset {};
	};
}
