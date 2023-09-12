#pragma once

#include "Data Stream/Stream.hpp"
#include "msf/Types.hpp"

namespace pdb {
	[[nodiscard]] bool verifyMagic(stream::SpanType bytes) noexcept;
	[[nodiscard]] bool validBlockSize(std::size_t size) noexcept;
	[[nodiscard]] msf::UInt64 alignTo(msf::UInt64 value, msf::UInt64 align, msf::UInt64 skew = 0) noexcept;
	[[nodiscard]] msf::UInt64 divideCeil(msf::UInt64 numerator, msf::UInt64 denominator) noexcept;
	[[nodiscard]] msf::UInt64 bytesToBlocks(msf::UInt64 numberOfBytes, msf::UInt64 blockSize) noexcept;
	[[nodiscard]] msf::UInt64 blockToOffset(msf::UInt64 blockNumber, msf::UInt64 blockSize) noexcept;
	[[nodiscard]] bool verifySuperBlock(const msf::SuperBlock &superBlock) noexcept;
}
