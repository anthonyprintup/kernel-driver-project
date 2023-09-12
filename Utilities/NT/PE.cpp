#include "NT.hpp"

#include <Framework/Utilities/Strings/Fnv1A.hpp>
#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../../Miscellaneous/Globals.hpp"
namespace nt = KM::Miscellaneous::Globals::NT;

using namespace KM::Utilities::NT;

namespace detail {
	PIMAGE_NT_HEADERS64 ntHeaders(const std::uintptr_t base) noexcept {
		VM_SIZE_BEGIN
		const auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		VM_SIZE_END

		return ntHeaders;
	}

	PIMAGE_SECTION_HEADER sectionHeader(const std::uintptr_t base, const Hash hash) noexcept {
		VM_SIZE_BEGIN
		const auto ntHeader = ntHeaders(base);
		if (!ntHeader)
			return nullptr;

		const auto fileHeader = ntHeader->FileHeader;
		const auto sectionCount = fileHeader.NumberOfSections;

		auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
		for (std::size_t i {}; i < sectionCount; ++i, ++sectionHeader)
			if (Hash {reinterpret_cast<const char*>(sectionHeader->Name)} == hash)
				return sectionHeader;
		VM_SIZE_END
		
		return nullptr;
	}
}

std::uintptr_t PE::exported(const std::uintptr_t base, const Hash hash) noexcept {
	constexpr std::size_t exportDirectoryIndex {0};
	
	VM_MINIMUM_BEGIN
	const auto ntHeader = detail::ntHeaders(base);
	if (!ntHeader)
		return {};
	const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + ntHeader->OptionalHeader.DataDirectory[exportDirectoryIndex].VirtualAddress);
	if (!exportDirectory)
		return {};

	const auto exportedFunctions    = reinterpret_cast<std::uint32_t*>(base + exportDirectory->AddressOfFunctions);
	const auto exportedNames        = reinterpret_cast<std::uint32_t*>(base + exportDirectory->AddressOfNames);
	const auto exportedNameOrdinals = reinterpret_cast<std::uint16_t*>(base + exportDirectory->AddressOfNameOrdinals);

	std::uintptr_t result {};
	for (std::size_t i {}; i < exportDirectory->NumberOfNames; ++i) {
		const Hash exportedFunctionNameHash {reinterpret_cast<const char*>(base + exportedNames[i])};
		if (exportedFunctionNameHash == hash) {
			result = base + exportedFunctions[exportedNameOrdinals[i]];
			break;
		}
	}
	VM_MINIMUM_END

	return result;
}

std::pair<std::uintptr_t, std::size_t> PE::section(const std::uintptr_t base, const Hash hash) noexcept {
	VM_MINIMUM_BEGIN
	const auto imageSectionHeader = detail::sectionHeader(base, hash);
	if (imageSectionHeader)
		return {base + imageSectionHeader->VirtualAddress, imageSectionHeader->SizeOfRawData};
	VM_MINIMUM_END

	return {};
}

const PE::CodeViewInformation *PE::codeViewDebugInformation(const std::uintptr_t base) noexcept {
	constexpr std::size_t debugDirectoryIndex {6};
	constexpr auto debugTypeCodeView {2};
	
	VM_MINIMUM_BEGIN
	const auto ntHeader = detail::ntHeaders(base);
	if (!ntHeader)
		return {};
	
	const auto debugDirectory = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(base + ntHeader->OptionalHeader.DataDirectory[debugDirectoryIndex].VirtualAddress);
	const auto debugDirectorySize = ntHeader->OptionalHeader.DataDirectory[debugDirectoryIndex].Size;
	if (!debugDirectory || !debugDirectorySize)
		return {};

	for (std::size_t i {}; i < debugDirectorySize / sizeof(IMAGE_DEBUG_DIRECTORY); ++i)
		if (const auto entry = debugDirectory + i;
			entry->Type == debugTypeCodeView)
			return reinterpret_cast<const CodeViewInformation*>(base + entry->AddressOfRawData);
	VM_MINIMUM_END
	return {};
}

std::optional<std::string> PE::generatePdbUrlPath(const CodeViewInformation *codeViewDebugInformation) {
	VM_MINIMUM_BEGIN
	if (codeViewDebugInformation->signature != 'SDSR') // RSDS
		return std::nullopt;

	const auto &guid = codeViewDebugInformation->guid;
	
	char guidBuffer[sizeof(GUID) * 2 + sizeof(std::uint32_t) * 2 + 1] {};
	const auto guidFormat = xorstr_("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X");
	nt::_snprintf_s(guidBuffer, sizeof(guidBuffer), _TRUNCATE, guidFormat,
				guid.Data1,    guid.Data2,    guid.Data3,
				guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
				guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7],
		codeViewDebugInformation->age);

	std::string urlBuffer {};
	{
		const auto microsoftSymbolServerUrlFormat = xorstr_("/download/symbols/%s/%s/%s");
		// ReSharper disable once CppDeprecatedEntity
		const auto requiredSize = nt::_snprintf(
			nullptr, 0, microsoftSymbolServerUrlFormat,
			codeViewDebugInformation->name, guidBuffer, codeViewDebugInformation->name) + 1;

		urlBuffer.resize(requiredSize);
		nt::_snprintf_s(urlBuffer.data(), requiredSize, _TRUNCATE, microsoftSymbolServerUrlFormat,
			codeViewDebugInformation->name, guidBuffer, codeViewDebugInformation->name);
	}
	VM_MINIMUM_END
	return urlBuffer;
}
