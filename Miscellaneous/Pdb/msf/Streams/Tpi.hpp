#pragma once

#include "Stream.hpp"
#include "../Record.hpp"

namespace msf::streams {
	struct Tpi: Stream {
		explicit Tpi(std::unique_ptr<MappedBlockStream> stream) noexcept;

		[[nodiscard]] bool reload();
		[[nodiscard]] std::pair<std::size_t, std::size_t> typeIndexRange() const noexcept;

		template<class T, class RecordArgumentType = const codeview::Record*, class ReturnType = std::invoke_result_t<T, RecordArgumentType>>
		requires std::is_invocable_v<T, RecordArgumentType> && (std::is_same_v<ReturnType, void> || std::is_same_v<ReturnType, bool>)
		void iterate(T &&visitor) const noexcept(std::is_nothrow_invocable_v<T, RecordArgumentType>) {
			stream::Reader reader {this->typeRecordsReader};
			while (!reader.empty()) {
				const auto symbolRecord = reader.read<const codeview::Record*>();
				if constexpr (std::is_same_v<ReturnType, bool>) {
					if (!visitor(symbolRecord)) // The visitor has notified us that it's received all the information required, break
						break;
				} else
					visitor(symbolRecord);
				reader.skip(symbolRecord->length - sizeof(decltype(codeview::Record::kind)));
			}
		}
	private:
		const TpiStreamHeader *header {};
		stream::Reader typeRecordsReader {};
	};
}
