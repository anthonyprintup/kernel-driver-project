#pragma once

#include "../Types.hpp"

namespace msf::types {
	struct Variable {
		// Unique name inside of the parent
		HashType name {};
		// Offset from the parent
		std::size_t offset {};
		// Attributes (e.g. access modifier, is virtual, is static, ...)
		FieldAttributes attributes {};
		// Underlying type identifier e.g. `VOID`, `INT64`, `STRUCTURE`
		UnderlyingType type {};
		// Type index of the underlying type
		std::size_t typeIndex {};
	};
}
