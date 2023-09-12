#pragma once

#include <type_traits>

#include "Types.hpp"

namespace msf {
	// Represents commonly used values from `LEAF_ENUM_e`
	enum struct LeafType: UInt16 {
		MODIFIER = 0x1001,
		POINTER,
		PROCEDURE = 0x1008,

		FIELD_LIST = 0x1203,
		DERIVED,
		BIT_FIELD,
		METHOD_LIST,

		BASE_CLASS = 0x1400,
		VIRTUAL_BASE_CLASS,
		INTERFACE_VIRTUAL_BASE_CLASS,

		VIRTUAL_FUNCTION_OFFSET = 0x140C,

		ENUMERATE = 0x1502,
		ARRAY,
		CLASS,
		STRUCTURE,
		UNION,
		ENUM,

		MEMBER = 0x150D,
		STATIC_MEMBER,

		STRIDED_ARRAY = 0x1516,
		INTERFACE = 0x1519,

		VFTABLE = 0x151D,

		STRUCTURE2 = 0x1609,

		NUMERIC = 0x8000,
		CHAR = 0x8000,
		SHORT,
		USHORT,
		LONG,
		ULONG,
		REAL32,
		REAL64,
		REAL80,
		REAL128,
		QUADWORD,
		UQUADWORD,
		REAL48,
		COMPLEX32,
		COMPLEX64,
		COMPLEX80,
		COMPLEX128,
		VARSTRING,

		OCTWORD = 0x8017,
		UOCTWORD,

		DECIMAL,
		DATE,
		UTF8_STRING,

		REAL16,

		PAD0 = 0xF0,
		PAD1,
		PAD2,
		PAD3,
		PAD4,
		PAD5,
		PAD6,
		PAD7,
		PAD8,
		PAD9,
		PAD10,
		PAD11,
		PAD12,
		PAD13,
		PAD14,
		PAD15
	};
	inline bool operator <(const UInt16 lhs, const LeafType rhs) noexcept {
		return lhs < static_cast<std::underlying_type_t<LeafType>>(rhs);
	}
}
