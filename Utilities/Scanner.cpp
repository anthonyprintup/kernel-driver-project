#include "Scanner.hpp"

#include <cstring>

#include "../Configuration.hpp"

using namespace KM::Utilities;

std::uintptr_t Scanner::scan(std::uint8_t *base, const std::size_t length, std::uint8_t *pattern, std::uint8_t *mask, const std::ptrdiff_t offset) {
	VM_MINIMUM_BEGIN
	const auto firstByte = pattern[0];
	const auto end = base + length - std::strlen(reinterpret_cast<const char*>(mask));

	for (; base < end; ++base) {
		if (*base != firstByte)
			continue;

		if ([](std::uint8_t *base, std::uint8_t *pattern, std::uint8_t *mask) {
			for (; *mask; ++base, ++pattern, ++mask) {
				if (*mask == '.')
					continue;

				if (*base != *pattern)
					return false;
			}
			return true;
		}(base, pattern, mask))
			return reinterpret_cast<std::uintptr_t>(base) + offset;
	}
	VM_MINIMUM_END
	return {};
}
