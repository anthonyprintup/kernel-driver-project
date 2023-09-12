#include "Info.hpp"

using namespace msf;
using namespace streams;

#include "../../../../Configuration.hpp"

bool Info::NamedStreamsMap::read(stream::Reader &reader) {
	VM_SIZE_SPEED_BEGIN
	const auto stringBufferSize = reader.read<UInt32>();
	for (std::size_t i {}; i < stringBufferSize;) {
		const auto namedStreamString = reader.read<std::string_view>();

		this->streams.push_back(namedStreamString);
		i += namedStreamString.length() + sizeof('\0');
	}

	// Read the hash table
	const auto hashTableHeader = reader.read<const HashTable*>();
	if (hashTableHeader->capacity == 0) // Invalid capacity
		return false;
	if (hashTableHeader->size > hashTableHeader->capacity * 2 / 3 + 1) // invalid size
		return false;

	// Read the entries
	const auto presentBitVectorSize = reader.read<UInt32>();
	reader.skip(presentBitVectorSize * sizeof(UInt32));
	const auto deletedBitVectorSize = reader.read<UInt32>();
	reader.skip(deletedBitVectorSize * sizeof(UInt32));

	// Read the bucket entries/hashes
	reader.skip((presentBitVectorSize + 1ull) * (sizeof(UInt32) + sizeof(UInt32)));

	volatile auto result {true};
	VM_SIZE_SPEED_END
	return result;
}

Info::Info(std::unique_ptr<MappedBlockStream> stream) noexcept:
	Stream {std::move(stream)} {}

const InfoStreamHeader *Info::header() const noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto result = this->_header;
	VM_SIZE_SPEED_END
	return result;
}

bool Info::reload() {
	VM_SIZE_SPEED_BEGIN
	if (this->reader.size() < sizeof(*this->_header))
		return false;

	// Read the Info/PDB header
	this->_header = this->reader.read<decltype(this->_header)>();

	// Unsupported PDB stream version
	if (const auto implementationVersion = static_cast<PdbImplementationVersion>(this->_header->version);
		implementationVersion != PdbImplementationVersion::VC70  && implementationVersion != PdbImplementationVersion::VC80 &&
		implementationVersion != PdbImplementationVersion::VC110 && implementationVersion != PdbImplementationVersion::VC140)
		return false;

	// Read the named streams
	if (!this->namedStreams.read(this->reader))
		return false;

	// Read the feature signature
	while (!this->reader.empty()) {
		const auto featureSignature = this->reader.read<FeatureSignature>();
		if (featureSignature == FeatureSignature::VC110)
			break;
		if (featureSignature == FeatureSignature::VC140)
			this->features |= featureFlags::containsIdStream;
		else if (featureSignature == FeatureSignature::NO_TYPE_MERGE)
			this->features |= featureFlags::noTypeMerging;
		else if (featureSignature == FeatureSignature::MINIMAL_DEBUG_INFO)
			this->features |= featureFlags::minimalDebugInfo;
	}

	volatile auto result {true};
	VM_SIZE_SPEED_END
	return result;
}
