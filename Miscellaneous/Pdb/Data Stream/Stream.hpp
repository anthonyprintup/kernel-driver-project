#pragma once

#include <span>
#include <string_view>

namespace stream {
	using UnderlyingDataType = std::uint8_t;
	using SpanType = std::span<const UnderlyingDataType>;
	using DifferenceType = SpanType::difference_type;
}
