#pragma once

#include "Types.hpp"

namespace msf::codeview {
	struct Record {
		UInt16 length {2}; // Record length, not including this 2 byte field
		UInt16 kind {};    // Record kind enum
	};
}
