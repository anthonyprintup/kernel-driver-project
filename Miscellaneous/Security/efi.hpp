#pragma once

#include "../../Utilities/NT/NT.hpp"

namespace KM::Miscellaneous::efi {
	struct RawQueryType {
		NTSTATUS status {};
		std::size_t size {};
	};
	struct QueryType: RawQueryType {
		std::unique_ptr<std::uint8_t[]> buffer {};
	};
	struct VariableEntry {
		std::uint32_t next {};
		GUID          guid {};
		wchar_t       name[1] {};
	};

	std::pair<std::unique_ptr<std::uint8_t[]>, std::size_t> variables() noexcept;
	RawQueryType variable(std::wstring_view variable, PGUID guid, void *outputBuffer, std::size_t outputBufferSize) noexcept;
	QueryType variable(std::wstring_view variable, PGUID guid) noexcept;

	[[nodiscard]] bool supported() noexcept;
}
