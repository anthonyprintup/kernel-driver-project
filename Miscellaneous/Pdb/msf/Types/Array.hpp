#pragma once

#include <cstdint>

namespace msf::types {
	struct Array {
		// Type index of the element type
		std::size_t elementTypeIndex {};
		// Type index of the index type
		std::size_t indexTypeIndex {};
		// Number of elements in the array
		std::size_t numberOfElements {};
	};
}
