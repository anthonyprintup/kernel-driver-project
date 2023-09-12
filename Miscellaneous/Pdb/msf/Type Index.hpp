// ReSharper disable CommentTypo
// ReSharper disable IdentifierTypo
#pragma once

#include <cstdint>

namespace msf {
	enum struct SimpleType {
		NONE = 0x0000,           // uncharacterized type (no type)
		VOID_ = 0x0003,          // void
		NOT_TRANSLATED = 0x0007, // type not translated by cvpack
		HRESULT = 0x0008,        // OLE/COM HRESULT

		SIGNED_CHARACTER = 0x0010,   // 8 bit signed
		UNSIGNED_CHARACTER = 0x0020, // 8 bit unsigned
		NARROW_CHARACTER = 0x0070,   // really a char
		WIDE_CHARACTER = 0x0071,     // wide char
		CHARACTER16 = 0x007a,        // char16_t
		CHARACTER32 = 0x007b,        // char32_t

		SBYTE = 0x0068,        // 8 bit signed int
		BYTE = 0x0069,         // 8 bit unsigned int
		INT16_SHORT = 0x0011,  // 16 bit signed
		UINT16_SHORT = 0x0021, // 16 bit unsigned
		INT16 = 0x0072,        // 16 bit signed int
		UINT16 = 0x0073,       // 16 bit unsigned int
		INT32_LONG = 0x0012,   // 32 bit signed
		UINT32_LONG = 0x0022,  // 32 bit unsigned
		INT32 = 0x0074,        // 32 bit signed int
		UINT32 = 0x0075,       // 32 bit unsigned int
		INT64_QUAD = 0x0013,   // 64 bit signed
		UINT64_QUAD = 0x0023,  // 64 bit unsigned
		INT64 = 0x0076,        // 64 bit signed int
		UINT64 = 0x0077,       // 64 bit unsigned int
		INT128_OCT = 0x0014,   // 128 bit signed int
		UINT128_OCT = 0x0024,  // 128 bit unsigned int
		INT128 = 0x0078,       // 128 bit signed int
		UINT128 = 0x0079,      // 128 bit unsigned int

		FLOAT16 = 0x0046,                   // 16 bit real
		FLOAT32 = 0x0040,                   // 32 bit real
		FLOAT32_PARTIAL_PRECISION = 0x0045, // 32 bit PP real
		FLOAT48 = 0x0044,                   // 48 bit real
		FLOAT64 = 0x0041,                   // 64 bit real
		FLOAT80 = 0x0042,                   // 80 bit real
		FLOAT128 = 0x0043,                  // 128 bit real

		COMPLEX16 = 0x0056,                   // 16 bit complex
		COMPLEX32 = 0x0050,                   // 32 bit complex
		COMPLEX32_PARTIAL_PRECISION = 0x0055, // 32 bit PP complex
		COMPLEX48 = 0x0054,                   // 48 bit complex
		COMPLEX64 = 0x0051,                   // 64 bit complex
		COMPLEX80 = 0x0052,                   // 80 bit complex
		COMPLEX128 = 0x0053,                  // 128 bit complex

		BOOLEAN8 = 0x0030,   // 8 bit boolean
		BOOLEAN16 = 0x0031,  // 16 bit boolean
		BOOLEAN32 = 0x0032,  // 32 bit boolean
		BOOLEAN64 = 0x0033,  // 64 bit boolean
		BOOLEAN128 = 0x0034, // 128 bit boolean
	};
	enum struct SimpleTypeMode: std::uint32_t {
		DIRECT = 0x00000000,         // Not a pointer
		NEAR_POINTER = 0x00000100,   // Near pointer
		FAR_POINTER = 0x00000200,    // Far pointer
		HUGE_POINTER = 0x00000300,   // Huge pointer
		NEAR_POINTER32 = 0x00000400, // 32 bit near pointer
		FAR_POINTER32 = 0x00000500,  // 32 bit far pointer
		NEAR_POINTER64 = 0x00000600, // 64 bit near pointer
		NEAR_POINTER128 = 0x00000700 // 128 bit near pointer
	};
}
