#include "Msf Layouts.hpp"

#include "../../Helpers.hpp"

using namespace msf;
using namespace streams;

UInt32 MsfLayout::mainFpmBlock() const noexcept {
	return this->superBlock->freeBlockMapBlock;
}

UInt32 MsfLayout::alternateFpmBlock() const noexcept {
	return 3U - this->mainFpmBlock();
}

UInt64 MsfLayout::blockMapOffset() const noexcept {
	return static_cast<UInt64>(this->superBlock->blockMapAddress) * this->superBlock->blockSize;
}

UInt32 MsfLayout::numberOfDirectoryBlocks() const noexcept {
	return static_cast<UInt32>(pdb::bytesToBlocks(this->superBlock->numberOfDirectoryBytes, this->superBlock->blockSize));
}
