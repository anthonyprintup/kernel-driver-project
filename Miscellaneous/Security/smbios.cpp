// ReSharper disable CppTooWideScope
// ReSharper disable CppClangTidyPerformanceNoIntToPtr
// ReSharper disable CppInitializedValueIsAlwaysRewritten
// ReSharper disable CppClangTidyClangDiagnosticDeprecatedVolatile
#include "smbios.hpp"

#include <Framework/Utilities/Strings/XorStr.hpp>
#include <Framework/Utilities/Strings/Fnv1A.hpp>

#include "../Globals.hpp"
namespace symbols = KM::Miscellaneous::Globals::Symbols;
#include "efi.hpp"

using namespace KM::Miscellaneous;

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments ...arguments) {
	if constexpr (Configuration::print) {
		VM_SIZE_BEGIN
		using namespace Globals;
		NT::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), arguments...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

smbios::structures::Type smbios::parser::Structure::type() const noexcept {
	VM_SIZE_BEGIN
	const auto result = static_cast<structures::Type>(this->header->type);
	VM_SIZE_END
	return result;
}

std::string_view smbios::parser::Structure::string(std::size_t index) const noexcept {
	VM_MINIMUM_BEGIN
	if (!index)
		return {};

	auto data = reinterpret_cast<const std::uint8_t*>(this->header) + this->header->length;
	if (!*data)
		return {};

	while (--index) {
		if (const auto length = std::strlen(reinterpret_cast<const char*>(data)))
			data += length + 1;
		else return {};
	}
	VM_MINIMUM_END

	return reinterpret_cast<const char*>(data);
}

std::size_t smbios::parser::parse(std::uint8_t *data, const std::size_t size, std::function<void(Structure&&)> &&callback) noexcept {
	VM_MAXIMUM_BEGIN
	std::size_t calculatedSize {};
	const auto end = data + size;
	for (auto previous {data}; data < end; calculatedSize += data - previous, previous = data) {
		const auto header = reinterpret_cast<structures::Header*>(data);
		callback(Structure {header});

		data += header->length;
		if (!*data)
			data += 2;
		else
			while (true) {
				const auto length = std::strlen(reinterpret_cast<const char*>(data));
				data += length + 1;
				if (!length)
					break;
			}

		if (static_cast<structures::Type>(header->type) == structures::Type::EndOfTable && header->length == sizeof(structures::Header)) {
			calculatedSize += sizeof(structures::Header) + 2;
			break;
		}
	}
	VM_MAXIMUM_END
	return calculatedSize;
}

PHYSICAL_ADDRESS smbios::physicalAddress() noexcept {
	VM_MAXIMUM_BEGIN
	if (efi::supported()) {
		struct Entry {
			PGUID guid {};
			const wchar_t *name {};

			explicit operator bool() const noexcept {
				return this->name != nullptr;
			}
		};

		// Priority list:
		//   SmbiosV3EntryPointTable
		//   SmbiosEntryPointTable
		//   AmiEntryS3Addr
		//   SMBIOS_ENTRY_ADDR
		std::array<Entry, 4> entries {};

		const auto [buffer, size] = efi::variables();
		for (auto entry {reinterpret_cast<efi::VariableEntry*>(buffer.get())};
			 entry->next; entry = reinterpret_cast<decltype(entry)>(reinterpret_cast<std::uintptr_t>(entry) + entry->next)) {
			// We're comparing against short strings because it doesn't matter, the (interesting) variables shouldn't contain wide characters
			if (const Hash nameHash {reinterpret_cast<const wchar_t*>(entry->name)};
				nameHash == Fnv1A(L"SmbiosV3EntryPointTable"))
				entries[0] = {&entry->guid, entry->name};
			else if (nameHash == Fnv1A(L"SmbiosEntryPointTable"))
				entries[1] = {&entry->guid, entry->name};
			else if (nameHash == Fnv1A(L"AmiEntryS3Addr"))
				entries[2] = {&entry->guid, entry->name};
			else if (nameHash == Fnv1A(L"SMBIOS_ENTRY_ADDR"))
				entries[3] = {&entry->guid, entry->name};
		}

		// Resolve the physical address using efi calls
		std::intptr_t addressBuffer {};
		// ReSharper disable once CppUseStructuredBinding
		if (const auto &smbiosV3EntryPointTable = entries[0]) {
			if (const auto [status, size] = efi::variable(smbiosV3EntryPointTable.name, smbiosV3EntryPointTable.guid, &addressBuffer, sizeof(addressBuffer));
				status != STATUS_SUCCESS || size != sizeof(addressBuffer)) return {};
		}
		if (const auto &smbiosEntryPointTable = entries[1]) {
			if (const auto [status, size] = efi::variable(smbiosEntryPointTable.name, smbiosEntryPointTable.guid, &addressBuffer, sizeof(addressBuffer));
				status != STATUS_SUCCESS || size != sizeof(addressBuffer)) return {};
		}
		if (const auto &amiEntryS3Addr = entries[2]) {
			if (const auto [status, size] = efi::variable(amiEntryS3Addr.name, amiEntryS3Addr.guid, &addressBuffer, sizeof(addressBuffer));
				status != STATUS_SUCCESS || size != sizeof(addressBuffer)) return {};
		}
		if (const auto &smbiosEntryAddr = entries[3]) {
			if (const auto [status, size] = efi::variable(smbiosEntryAddr.name, smbiosEntryAddr.guid, &addressBuffer, sizeof(addressBuffer));
				status != STATUS_SUCCESS || size != sizeof(addressBuffer)) return {};
		}
		
		return {.QuadPart = addressBuffer};
	}

	// Scan for the SMBIOS entry point
	namespace nt = Globals::NT;
	
	constexpr auto low    {0xF0000};
	constexpr auto length {0x10000};
	const PHYSICAL_ADDRESS physicalAddress {.QuadPart = low};
	PHYSICAL_ADDRESS entryPoint {};
	if (const auto virtualAddress = static_cast<std::uint8_t*>(nt::MmMapIoSpace(physicalAddress, length, MmNonCached))) {
		const auto max {virtualAddress + length};
		for (auto address {virtualAddress}; address <= max; address += 0x10) {
			if (smbios::valid(address, versions::v21) ||
				smbios::valid(address, versions::v30)) {
				entryPoint = nt::MmGetPhysicalAddress(address);
				break;
			}
		}
		nt::MmUnmapIoSpace(virtualAddress, length);
	}
	VM_MAXIMUM_END
	
	return entryPoint;
}

PHYSICAL_ADDRESS smbios::wmipSmBiosTablePhysicalAddress() noexcept {
	VM_MAXIMUM_BEGIN
	const auto wmipSmBiosTablePhysicalAddress = reinterpret_cast<PPHYSICAL_ADDRESS>(**symbols::ntoskrnl::wmipSMBiosTablePhysicalAddress);
	if (wmipSmBiosTablePhysicalAddress) return *wmipSmBiosTablePhysicalAddress;
	VM_MAXIMUM_END
	return {};
}
std::uint16_t smbios::wmipSmBiosTableLength() noexcept {
	VM_MAXIMUM_BEGIN
	const auto wmipSmBiosTableLength = **symbols::ntoskrnl::wmipSMBiosTableLength;
	if (wmipSmBiosTableLength) return wmipSmBiosTableLength;
	VM_MAXIMUM_END

	return {};
}
std::uint32_t smbios::wmipSmBiosVersionInfo() noexcept {
	VM_MAXIMUM_BEGIN
	volatile std::uint32_t result {};

	const auto wmipSmBiosVersionInfo = reinterpret_cast<std::uint8_t*>(&**symbols::ntoskrnl::wmipSMBiosVersionInfo);
	if (wmipSmBiosVersionInfo) {
		const auto majorVersion = wmipSmBiosVersionInfo[1];
		const auto minorVersion = wmipSmBiosVersionInfo[2];
		const auto revision     = wmipSmBiosVersionInfo[3];

		result = majorVersion << 16 | minorVersion << 8 | revision;
	}
	VM_MAXIMUM_END
	return result;
}

bool smbios::valid(void *virtualAddress, const std::uint32_t version) noexcept {
	VM_MAXIMUM_BEGIN
	volatile bool result {};
	if (version < versions::v30) {
		constexpr std::uint8_t smbios21[] {'_', 'S', 'M', '_'};
		constexpr std::uint8_t dmi[]      {'_', 'D', 'M', 'I', '_'};
		
		const auto entryPoint = static_cast<structures::EntryPoint32*>(virtualAddress);
		if (std::memcmp(virtualAddress, smbios21, sizeof(smbios21))  != 0 ||
			std::memcmp(&entryPoint->intermediate, dmi, sizeof(dmi)) != 0)
			return result = false;
		if (entryPoint->length > 32)
			return result = false;
		std::uint8_t checksum {};
		for (std::size_t i {}; i < entryPoint->length; ++i)
			checksum += static_cast<std::uint8_t*>(virtualAddress)[i];
		if (checksum)
			return result = false;
		
		result = true;
	} else if (version >= versions::v30) {
		constexpr std::uint8_t smbios3[] {'_', 'S', 'M', '3', '_'};
		const auto entryPoint = static_cast<structures::EntryPoint64*>(virtualAddress);
		if (std::memcmp(virtualAddress, smbios3, sizeof(smbios3)) != 0)
			return result = false;
		if (entryPoint->length > 32)
			return result = false;
		std::uint8_t checksum {};
		for (std::size_t i {}; i < entryPoint->length; ++i)
			checksum += static_cast<std::uint8_t*>(virtualAddress)[i];
		if (checksum)
			return result = false;
		
		result = true;
	} else
		return result = false;
	VM_MAXIMUM_END;

	return result;
}
