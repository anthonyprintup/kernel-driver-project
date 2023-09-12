#pragma once

#include "Stream.hpp"
#include "../Record.hpp"
#include "../Types/Public Symbol.hpp"
#include "../Symbol Type.hpp"

namespace msf::streams {
	struct SymbolRecords: Stream {
		explicit SymbolRecords(std::unique_ptr<MappedBlockStream> stream) noexcept;

		template<class T, class ArgumentType = const codeview::Record*, class ReturnType = std::invoke_result_t<T, ArgumentType>>
		requires std::is_invocable_v<T, const codeview::Record*> && (std::is_same_v<ReturnType, void> || std::is_same_v<ReturnType, bool>)
		void iterate(T &&visitor) const noexcept(std::is_nothrow_invocable_v<T, ArgumentType>) {
			stream::Reader reader {this->reader};
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
		template<class T, class ArgumentType = const types::PublicSymbol32&, class ReturnType = std::invoke_result_t<T, ArgumentType>>
		requires std::is_invocable_v<T, const types::PublicSymbol32&> && (std::is_same_v<ReturnType, void> || std::is_same_v<ReturnType, bool>)
		void iterate(T &&visitor) const noexcept(std::is_nothrow_invocable_v<T, ArgumentType>) {
			stream::Reader reader {this->reader};
			while (!reader.empty()) {
				const auto symbolRecord = reader.read<const codeview::Record*>();
				if (static_cast<SymbolType>(symbolRecord->kind) == SymbolType::PUB32) {
					const auto &publicSymbol32 = *reinterpret_cast<const types::PublicSymbol32*>(symbolRecord);
					if constexpr (std::is_same_v<ReturnType, bool>) {
						if (!visitor(publicSymbol32)) // The visitor has notified us that it's received all the information required, break
							break;
					} else
						visitor(publicSymbol32);
				}
				reader.skip(symbolRecord->length - sizeof(decltype(codeview::Record::kind)));
			}
		}
	};
}
