#pragma once

#include "Streams/Info.hpp"
#include "Streams/Tpi.hpp"
#include "Streams/Dbi.hpp"
#include "Streams/Symbol Records.hpp"

#include <optional>

namespace msf {
	struct Pdb {
		Pdb(const SuperBlock *superBlock, stream::SpanType bytes);

		[[nodiscard]] const streams::Info *infoStream();
		[[nodiscard]] const streams::Info *infoStream() const noexcept;
		[[nodiscard]] const streams::Tpi *tpiStream();
		[[nodiscard]] const streams::Tpi *tpiStream() const noexcept;
		[[nodiscard]] std::pair<std::size_t, std::size_t> typeIndexRange() const noexcept;
		[[nodiscard]] const streams::Dbi *debugInformationStream();
		[[nodiscard]] const streams::Dbi *debugInformationStream() const noexcept;
		[[nodiscard]] const streams::SymbolRecords *symbolRecords();
		[[nodiscard]] const streams::SymbolRecords *symbolRecords() const noexcept;
	private:
		streams::MsfLayout msfLayout {};
		const stream::SpanType bytes {};
		
		std::unique_ptr<streams::Info> info {};
		std::unique_ptr<streams::Tpi> tpi {};
		std::unique_ptr<streams::Dbi> dbi {};
		std::unique_ptr<streams::SymbolRecords> symbols {};
		std::unique_ptr<streams::MappedBlockStream> directoryStream {};

		void parseFileHeaders();
		void parseStreamData();

		[[nodiscard]] std::size_t numberOfStreams() const noexcept;
	};

	std::optional<const Pdb> load(stream::SpanType bytes);
	std::vector<const codeview::Record*> typeRecords(const Pdb &pdb);
}
