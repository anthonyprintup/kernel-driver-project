#pragma once

#include "../Types.hpp"

#include <vector>

namespace msf::types {
	struct Enumerator {
		HashType name {};
		union {
			Int8   int8;
			UInt8  uint8;
			Int16  int16;
			UInt16 uint16;
			Int32  int32;
			UInt32 uint32;
			Int64  int64;
			UInt64 uint64;
		} value {};
	};
	struct Enum {
		HashType name {};
		UnderlyingType type {};
		std::vector<Enumerator> values {};
	};
}
