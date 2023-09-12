#pragma once

#include <type_traits>

#include "Types.hpp"

namespace msf {
	// Represents commonly used values from `SYM_ENUM_e`
	enum struct SymbolType: UInt16 {
		USER_DEFINED_TYPE = 0x1108,
		LDATA32 = 0x110C, // Module-local symbol
		GDATA32, // Global data symbol
		PUB32, // Public symbol
	};
	inline bool operator <(const UInt16 lhs, const SymbolType rhs) noexcept {
		return lhs < static_cast<std::underlying_type_t<SymbolType>>(rhs);
	}
}
