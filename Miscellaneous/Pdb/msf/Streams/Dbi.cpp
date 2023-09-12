#include "Dbi.hpp"

#include "Layouts.hpp"

using namespace msf;
using namespace streams;

#include "../../../../Configuration.hpp"

Dbi::Dbi(std::unique_ptr<MappedBlockStream> stream) noexcept:
	Stream {std::move(stream)} {}

bool Dbi::reload(const MsfLayout &layout, const stream::SpanType bytes) {
	VM_SIZE_SPEED_BEGIN
	if (this->reader.size() < sizeof(*this->header))
		return false;

	// Read the Debug Info header
	this->header = this->reader.read<decltype(this->header)>();

	// Invalid DBI version signature
	if (this->header->versionSignature != -1)
		return false;

	// DBI length does not equal to sum of substreams
	if (this->reader.size() != sizeof(*this->header) + this->header->moduleInfoSubstreamSize +
		this->header->sectionContributionSubstreamSize + this->header->sectionMapSize +
		this->header->fileInfoSize + this->header->typeServerSize + this->header->optionalDbgHeaderSize +
		this->header->ecSubstreamSize)
		return false;

	// Only certain substreams are guaranteed to be aligned
	if (this->header->moduleInfoSubstreamSize % sizeof(UInt32) != 0)
		return false;
	if (this->header->sectionContributionSubstreamSize % sizeof(UInt32) != 0)
		return false;
	if (this->header->sectionMapSize % sizeof(UInt32) != 0)
		return false;
	if (this->header->fileInfoSize % sizeof(UInt32) != 0)
		return false;
	if (this->header->typeServerSize % sizeof(UInt32) != 0)
		return false;

	// Skip the Module Info substream
	if (this->header->moduleInfoSubstreamSize)
		this->reader.skip(this->header->moduleInfoSubstreamSize);

	// Parse the section contribution data
	if (this->header->sectionContributionSubstreamSize) {
		const auto version = this->reader.read<SectionContributionVersion>();

		const auto bytesRemaining = this->header->sectionContributionSubstreamSize - sizeof(SectionContributionVersion);
		if (version == SectionContributionVersion::VERSION_60 && bytesRemaining % sizeof(SectionContribution) == 0)
			for (std::size_t i {}; i < bytesRemaining / sizeof(SectionContribution); ++i)
				this->sectionContributions.emplace_back<const SectionContribution*>(this->reader.read<const SectionContribution*>());
		else if (version == SectionContributionVersion::VERSION_2 && bytesRemaining % sizeof(SectionContribution2) == 0)
			for (std::size_t i {}; i < bytesRemaining / sizeof(SectionContribution2); ++i)
				this->sectionContributions.emplace_back<const SectionContribution2*>(this->reader.read<const SectionContribution2*>());
		else
			return false;
	}

	// Skip the section map substream
	if (this->header->sectionMapSize)
		this->reader.skip(this->header->sectionMapSize);

	// Skip the file info substream
	if (this->header->fileInfoSize)
		this->reader.skip(this->header->fileInfoSize);

	// Skip the file type server map substream
	if (this->header->typeServerSize)
		this->reader.skip(this->header->typeServerSize);

	// Skip the EC substream
	if (this->header->ecSubstreamSize)
		this->reader.skip(this->header->ecSubstreamSize);

	// Parse the optional debug streams
	if (this->header->optionalDbgHeaderSize) {
		for (std::size_t i {}; i < this->header->optionalDbgHeaderSize / sizeof(UInt16); ++i)
			this->debugStreams.emplace_back(this->reader.read<UInt16>());
	}

	// Verify that the whole stream has been read
	if (!this->reader.empty())
		return false;

	// Parse the section headers
	if (const auto sectionHeadersStream = this->createIndexedStreamForHeaderType(layout, DbgHeaderType::SECTION_HEADER)) {
		sectionHeadersStream->readBlocks(layout, bytes);
		stream::Reader sectionHeadersReader {sectionHeadersStream->bytes};
		if (sectionHeadersReader.size() % sizeof(coff::SectionHeader) != 0)
			return false;

		// Copy the section header into our own vector (the indexed stream gets freed when we leave this scope)
		// TODO: create our own structure from this (we only need the name, virtual address, and characteristics)?
		while (!sectionHeadersReader.empty())
			this->_sectionHeaders.emplace_back(*sectionHeadersReader.read<coff::SectionHeader*>());
	}
	VM_SIZE_SPEED_END
	return true;
}

const std::vector<coff::SectionHeader> &Dbi::sectionHeaders() const noexcept {
	return this->_sectionHeaders;
}

UInt16 Dbi::publicSymbolStreamIndex() const noexcept {
	return this->header->publicSymbolStreamIndex;
}
UInt16 Dbi::symbolRecordStreamIndex() const noexcept {
	return this->header->symbolRecordStreamIndex;
}
UInt16 Dbi::debugStreamIndex(DbgHeaderType type) const {
	VM_SIZE_SPEED_BEGIN
	const auto index = static_cast<std::size_t>(static_cast<std::underlying_type_t<decltype(type)>>(type));
	if (this->debugStreams.empty() || index >= this->debugStreams.size())
		return invalidStreamIndex;
	volatile const auto result = this->debugStreams[index];
	VM_SIZE_SPEED_END
	return result;
}

std::unique_ptr<MappedBlockStream> Dbi::createIndexedStreamForHeaderType(const MsfLayout &msf, const DbgHeaderType type) const {
	VM_SIZE_SPEED_BEGIN
	const auto streamIndex = this->debugStreamIndex(type);
	if (streamIndex == invalidStreamIndex)
		return nullptr;
	auto result = createIndexedStream(msf, streamIndex);
	VM_SIZE_SPEED_END
	return std::move(result);
}
