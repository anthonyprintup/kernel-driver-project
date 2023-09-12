#pragma once

#include <cstdint>
#include <cstddef>

namespace KM::Utilities::Scanner {
	std::uintptr_t scan(std::uint8_t *base, std::size_t length, std::uint8_t *pattern, std::uint8_t *mask, std::ptrdiff_t offset = 0);
}
