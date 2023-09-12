#pragma once

#include "Stream.hpp"

#include <variant>

namespace msf::streams {
	struct Dbi: Stream {
		explicit Dbi(std::unique_ptr<MappedBlockStream> stream) noexcept;

		[[nodiscard]] bool reload(const MsfLayout &layout, stream::SpanType bytes);

		[[nodiscard]] const std::vector<coff::SectionHeader> &sectionHeaders() const noexcept;
		[[nodiscard]] UInt16 publicSymbolStreamIndex() const noexcept;
		[[nodiscard]] UInt16 symbolRecordStreamIndex() const noexcept;
		[[nodiscard]] UInt16 debugStreamIndex(DbgHeaderType type) const;
		[[nodiscard]] std::unique_ptr<MappedBlockStream> createIndexedStreamForHeaderType(const MsfLayout &msf, DbgHeaderType type) const;
	private:
		using SectionContributionVariant = std::variant<const SectionContribution*, const SectionContribution2*>;

		const DbiStreamHeader *header {};
		std::vector<SectionContributionVariant> sectionContributions {};
		std::vector<UInt16> debugStreams {};
		std::vector<coff::SectionHeader> _sectionHeaders {};
	};
}
