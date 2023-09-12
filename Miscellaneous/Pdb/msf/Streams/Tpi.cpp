#include "Tpi.hpp"

using namespace msf::streams;

#include "../../../../Configuration.hpp"

Tpi::Tpi(std::unique_ptr<MappedBlockStream> stream) noexcept:
	Stream {std::move(stream)} {}

bool Tpi::reload() {
	VM_SIZE_SPEED_BEGIN
	if (this->reader.size() < sizeof(*this->header))
		return false;

	// Read the Type Info header
	this->header = this->reader.read<decltype(this->header)>();

	// Unsupported TPI stream version
	if (static_cast<TpiImplementationVersion>(this->header->version) != TpiImplementationVersion::V80)
		return false;

	// Corrupted TPI header
	if (this->header->headerSize != sizeof(*this->header))
		return false;

	// TPI stream expected 4 byte hash key size
	if (this->header->hashKeySize != sizeof(UInt32))
		return false;

	// TPI stream invalid number of hash buckets
	if (this->header->numberOfHashBuckets < TpiStreamHeader::tpiMinimumBucketCount || this->header->numberOfHashBuckets > TpiStreamHeader::tpiMaximumBucketCount)
		return false;

	// The actual type records themselves come from this stream
	this->typeRecordsReader = this->reader.slice(0, this->header->typeRecordBytes);
	this->reader.skip(this->header->typeRecordBytes);

	// Verify that the whole stream has been read
	if (!this->reader.empty())
		return false;
	VM_SIZE_SPEED_END
	return true;
}

std::pair<std::size_t, std::size_t> Tpi::typeIndexRange() const noexcept {
	return std::make_pair(static_cast<std::size_t>(this->header->typeIndexBegin), static_cast<std::size_t>(this->header->typeIndexEnd));
}
