#include "Helpers.hpp"

#include <array>

using namespace msf;

#include <Framework/Utilities/Strings/XorStr.hpp>
#include "../../Configuration.hpp"

bool pdb::verifyMagic(const stream::SpanType bytes) noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto magicValue = xorstr_("Microsoft C/C++ MSF 7.00\r\n");
	volatile const auto result = std::memcmp(bytes.data(), magicValue, 26) == 0;
	VM_SIZE_SPEED_END
	return result;
}

bool pdb::validBlockSize(const std::size_t size) noexcept {
	return size == 512 || size == 1024 || size == 2048 || size == 4096;
}

UInt64 pdb::alignTo(const UInt64 value, const UInt64 align, UInt64 skew) noexcept {
	skew %= align;
	return (value + align - 1 - skew) / align * align + skew;
}

UInt64 pdb::divideCeil(const UInt64 numerator, const UInt64 denominator) noexcept {
	return alignTo(numerator, denominator) / denominator;
}

UInt64 pdb::bytesToBlocks(const UInt64 numberOfBytes, const UInt64 blockSize) noexcept {
	return divideCeil(numberOfBytes, blockSize);
}

UInt64 pdb::blockToOffset(const UInt64 blockNumber, const UInt64 blockSize) noexcept {
	return blockNumber * blockSize;
}

bool pdb::verifySuperBlock(const SuperBlock &superBlock) noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto superBlockMagicValue = xorstr_("Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0\0");
	if (std::memcmp(superBlock.magicBytes, superBlockMagicValue, 32) != 0) // MSF magic header doesn't match
		return false;
	if (!validBlockSize(superBlock.blockSize)) // Unsupported block size
		return false;
	if (superBlock.numberOfDirectoryBytes % sizeof(UInt32) != 0) // Directory size is not multiple of 4
		return false;
	if (const auto numberOfDirectoryBlocks = bytesToBlocks(superBlock.numberOfDirectoryBytes, superBlock.blockSize);
		numberOfDirectoryBlocks > superBlock.blockSize / sizeof(UInt32)) // Too many directory blocks
		return false;
	if (superBlock.blockMapAddress == 0) // Block 0 is reserved
		return false;
	if (superBlock.blockMapAddress >= superBlock.numberOfBlocks) // Block map address is invalid
		return false;
	if (superBlock.freeBlockMapBlock != 1 && superBlock.freeBlockMapBlock != 2) // The free block map isn't at block 1 or block 2
		return false;

	volatile auto result {true};
	VM_SIZE_SPEED_END
	return result;
}

