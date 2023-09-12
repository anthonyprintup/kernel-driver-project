#pragma once

#include "../Types.hpp"
#include "Variable.hpp"

#include <vector>

namespace msf::types {
	struct Properties {
		[[nodiscard]] bool uniqueName() const noexcept;
		[[nodiscard]] bool forwardReference() const noexcept;
	private:
		UInt16 properties {};
	};
	struct Structure {
		HashType name {};
		std::size_t size {};
		std::vector<Variable> variables {};
		
		[[nodiscard]] const Variable *variable(HashType hash) const noexcept;
	};
}
