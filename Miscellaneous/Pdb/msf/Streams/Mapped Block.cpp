#include "Mapped Block.hpp"

#include "../../Helpers.hpp"

using namespace msf::streams;

#include "../../../../Configuration.hpp"

void MappedBlockStream::readBlocks(const MsfLayout &msf, const stream::SpanType bytes) {
	VM_SIZE_SPEED_BEGIN
	this->bytes.resize(this->streamLayout.length);
	for (std::size_t offset {}, remainingLength {this->streamLayout.length};
		auto &&blockNumber : this->streamLayout.blocks) {
		const auto blockOffset = pdb::blockToOffset(blockNumber, msf.superBlock->blockSize);
		const auto blockBegin = bytes.data() + blockOffset;

		const auto copiedLength = std::min(remainingLength, static_cast<std::size_t>(msf.superBlock->blockSize));
		std::memcpy(this->bytes.data() + offset, blockBegin, copiedLength);
		remainingLength -= copiedLength;
		offset += copiedLength;
	}
	VM_SIZE_SPEED_END
}
