#pragma once

#include "../Record.hpp"

namespace msf::types {
	struct PublicSymbol32: codeview::Record {
		UInt32 flags {};
		UInt32 offset {};
		UInt16 segment {};
		UInt8  _name[1] {};

		[[nodiscard]] std::string_view name() const noexcept;
	};
}
