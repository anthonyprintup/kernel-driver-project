#pragma once

#include "../Types.hpp"

#include <vector>

namespace msf::streams {
	struct MsfLayout {
		const SuperBlock    *superBlock {};
		std::vector<UInt8>   freePageMap {};
		std::vector<UInt32>  directoryBlocks {};
		std::vector<UInt32>  streamSizes {};
		std::vector<std::vector<UInt32>> streamMap {};

		[[nodiscard]] UInt32 mainFpmBlock() const noexcept;
		[[nodiscard]] UInt32 alternateFpmBlock() const noexcept;

		[[nodiscard]] UInt64 blockMapOffset() const noexcept;
		[[nodiscard]] UInt32 numberOfDirectoryBlocks() const noexcept;
	};
	struct MsfStreamLayout {
		std::size_t length {};
		// Array of ordered block ids
		std::vector<UInt32> blocks {};
	};
}
