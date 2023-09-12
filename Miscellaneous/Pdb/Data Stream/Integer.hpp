#pragma once

#include "Stream.hpp"

namespace stream {
	struct ArbitraryPrecisionInteger {
		SpanType data {};
		std::size_t numberOfBits {};
		bool isSigned {};
	};
	struct SignAwareInteger: ArbitraryPrecisionInteger {
		bool isUnsigned {};

		[[nodiscard]] explicit operator std::size_t() const noexcept;
	};
}
