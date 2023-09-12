#pragma once

#include "Variable.hpp"

#include <vector>

namespace msf::types {
	struct Union {
		HashType name {};
		std::size_t size {};
		std::vector<Variable> variables {};
	};
}
