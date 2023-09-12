// ReSharper disable CppClangTidyPerformanceNoIntToPtr
#include "Hardware Id.hpp"

using namespace KM::Miscellaneous;

#include <Framework/Utilities/Strings/Fnv1A.hpp>
#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../Globals.hpp"

#include "efi.hpp"
#include "smbios.hpp"

namespace libtomcrypt {
	#include <tomcrypt.h>
}

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments &&...arguments) {
	if constexpr (Configuration::print) {
		VM_SIZE_BEGIN
		using namespace Globals;
		NT::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), std::forward<Arguments>(arguments)...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

__declspec(noinline) bool hash(libtomcrypt::hash_state &state, const std::wstring_view variable, const PGUID guid) noexcept {
	VM_MAXIMUM_BEGIN
	volatile bool result {};
	if (const auto query = efi::variable(variable, guid);
		query.status == STATUS_SUCCESS) {
		libtomcrypt::sha512_process(&state, query.buffer.get(), static_cast<unsigned long>(query.size));
		result = true;
	}

	VM_MAXIMUM_END
	return result;
}
__declspec(noinline) void hash(libtomcrypt::hash_state &state, const std::string_view string) noexcept {
	VM_MAXIMUM_BEGIN
	if (!string.empty())
		libtomcrypt::sha512_process(&state, reinterpret_cast<const unsigned char*>(string.data()), static_cast<unsigned long>(string.length()));
	VM_MAXIMUM_END
	__nop(); // Prevent tail call optimizations
}
__declspec(noinline) void hash(libtomcrypt::hash_state &state, const void *buffer, const std::size_t length) noexcept {
	VM_MAXIMUM_BEGIN
	libtomcrypt::sha512_process(&state, static_cast<const unsigned char*>(buffer), static_cast<unsigned long>(length));
	VM_MAXIMUM_END
	__nop(); // Prevent tail call optimizations
}

hwid::HardwareId::HardwareId() {
	VM_MAXIMUM_BEGIN
	namespace nt = Globals::NT;

	libtomcrypt::hash_state
		genericSmbiosState {},
		biosInformationState {}, systemInformationState {},
		systemEnclosureState {}, processorInformationState {},
		cacheInformationState {}, systemSlotsState {}, memoryDeviceState {};
	// Initialize the hash states
	{
		libtomcrypt::sha512_init(&genericSmbiosState);
		libtomcrypt::sha512_init(&biosInformationState);
		libtomcrypt::sha512_init(&systemInformationState);
		libtomcrypt::sha512_init(&systemEnclosureState);
		libtomcrypt::sha512_init(&processorInformationState);
		libtomcrypt::sha512_init(&cacheInformationState);
		libtomcrypt::sha512_init(&systemSlotsState);
		libtomcrypt::sha512_init(&memoryDeviceState);
	}

	// TODO: write this flag to global variable
	bool smbiosSpoofed {};
	do {
		const auto entrypointPhysicalAddress = smbios::physicalAddress();
		const auto wmipSmBiosTableLength = smbios::wmipSmBiosTableLength();
		const auto wmipSmBiosTablePhysicalAddress = smbios::wmipSmBiosTablePhysicalAddress();
		const auto wmipSmBiosVersionInfo = smbios::wmipSmBiosVersionInfo();

		PHYSICAL_ADDRESS tablePhysicalAddress {};
		std::uint32_t tableLength {}, structureCount {}, version {};

		if (!entrypointPhysicalAddress.QuadPart) {
			if constexpr (Configuration::print)
				print(xorstr_("[!] Failed to locate the smbios entrypoint physical address!"));

			// TODO: send a log/request to the server
			// TODO: the entrypoint physical address should ALWAYS be valid on real systems
			if constexpr (!Configuration::debug)
				break;

			// Resolve using ntoskrnl values
			tablePhysicalAddress.QuadPart = wmipSmBiosTablePhysicalAddress.QuadPart;
			tableLength = wmipSmBiosTableLength;
			version = wmipSmBiosVersionInfo;
		} else {
			constexpr auto size = sizeof(smbios::structures::EntryPoint64);
			if (const auto virtualAddress = nt::MmMapIoSpace(entrypointPhysicalAddress, size, MmNonCached)) {
				if (const auto entryPoint32 = static_cast<smbios::structures::EntryPoint32*>(virtualAddress);
					smbios::valid(virtualAddress, smbios::versions::v21)) {
					tablePhysicalAddress.QuadPart = entryPoint32->structureTable.address;
					tableLength = entryPoint32->structureTable.length;
					structureCount = entryPoint32->structures;
					version = entryPoint32->version.major << 16 | entryPoint32->version.minor << 8;
				} else if (const auto entryPoint64 = static_cast<smbios::structures::EntryPoint64*>(virtualAddress);
					smbios::valid(virtualAddress, smbios::versions::v30)) {
					tablePhysicalAddress.QuadPart = entryPoint64->structureTable.address;
					tableLength = entryPoint64->structureTable.maximumSize;
					version = entryPoint64->version.major << 16 | entryPoint64->version.minor << 8 | entryPoint64->revision.document;
				} else {
					if constexpr (Configuration::print)
						print(xorstr_("[!] Invalid smbios entry point. %p"), entrypointPhysicalAddress.QuadPart);
					smbiosSpoofed = true;
				}

				nt::MmUnmapIoSpace(virtualAddress, size);
			} else {
				if (Configuration::print)
					print(xorstr_("[!] Unable to map the smbios entrypoint. %p"), entrypointPhysicalAddress.QuadPart);
				break;
			}

			if (smbiosSpoofed)
				break;
		}
		if (!tablePhysicalAddress.QuadPart) {
			if constexpr (Configuration::print)
				print(xorstr_("[!] Unable to find smbios table physical address."));
			break;
		}

		// TODO: additional backup check to make sure the structure hasn't been tampered with?
		// TODO: smbios2: Maximum Structure Size (WORD) (Size of the largest SMBIOS structure, in bytes, and encompasses the structure's formatted area and text strings)

		if (tablePhysicalAddress.QuadPart != wmipSmBiosTablePhysicalAddress.QuadPart) {
			if constexpr (Configuration::print)
				print(xorstr_("[!] smbios spoofing detected (physical address mismatch)."));
			// TODO: spoofed, send ban request
			smbiosSpoofed = true;
			break;
		}
		if (version != wmipSmBiosVersionInfo) {
			if constexpr (Configuration::print)
				print(xorstr_("[!] smbios spoofing detected (version mismatch): 0x%X 0x%X"), version, wmipSmBiosVersionInfo);

			// TODO: spoofed, send ban request
			smbiosSpoofed = true;
			break;
		}

		// TODO: we can detect virtual machines with the smbios structure (e.g. VMware, etc.) by parsing the strings or checking things like expected cores vs actual
		std::size_t calculatedSize {}, calculatedStructureCount {};
		if (const auto virtualAddress = static_cast<std::uint8_t*>(nt::MmMapIoSpace(tablePhysicalAddress, tableLength, MmNonCached))) {
			calculatedSize = smbios::parser::parse(virtualAddress, tableLength, 
				[&](smbios::parser::Structure &&structure) {
					VM_MAXIMUM_BEGIN
					using namespace smbios::structures;
					
					const auto headerType = structure.type();
					if (headerType == Type::BiosInformation) {
						const auto biosInformation = reinterpret_cast<const BiosInformation*>(structure.header);

						hash(genericSmbiosState, structure[biosInformation->vendor]);
						hash(biosInformationState, structure[biosInformation->vendor]);
						hash(genericSmbiosState, structure[biosInformation->bios.version]);
						hash(biosInformationState, structure[biosInformation->bios.version]);
						hash(genericSmbiosState, structure[biosInformation->bios.releaseDate]);
						hash(biosInformationState, structure[biosInformation->bios.releaseDate]);
						if (version >= smbios::versions::v24) {
							hash(genericSmbiosState, &biosInformation->bios.release, sizeof(std::uint8_t) * 2);
							hash(biosInformationState, &biosInformation->bios.release, sizeof(std::uint8_t) * 2);
							hash(genericSmbiosState, &biosInformation->bios.embeddedControllerFirmwareRelease, sizeof(std::uint8_t) * 2);
							hash(biosInformationState, &biosInformation->bios.embeddedControllerFirmwareRelease, sizeof(std::uint8_t) * 2);
						}
						if (version >= smbios::versions::v31) {
							hash(genericSmbiosState, &biosInformation->bios.extendedRomSize, sizeof(std::uint16_t));
							hash(biosInformationState, &biosInformation->bios.extendedRomSize, sizeof(std::uint16_t));
						}
					} else if (headerType == Type::SystemInformation) {
						const auto systemInformation = reinterpret_cast<const SystemInformation*>(structure.header);

						hash(genericSmbiosState, structure[systemInformation->manufacturer]);
						hash(systemInformationState, structure[systemInformation->manufacturer]);
						hash(genericSmbiosState, structure[systemInformation->productName]);
						hash(systemInformationState, structure[systemInformation->productName]);
						hash(genericSmbiosState, structure[systemInformation->version]);
						hash(systemInformationState, structure[systemInformation->version]);
						hash(genericSmbiosState, structure[systemInformation->serialNumber]);
						hash(systemInformationState, structure[systemInformation->serialNumber]);
						if (version >= smbios::versions::v21) {
							hash(genericSmbiosState, &systemInformation->uuid, sizeof(SystemInformation::uuid));
							hash(systemInformationState, &systemInformation->uuid, sizeof(SystemInformation::uuid));
						}
						if (version >= smbios::versions::v24) {
							hash(genericSmbiosState, structure[systemInformation->skuNumber]);
							hash(systemInformationState, structure[systemInformation->skuNumber]);
							hash(genericSmbiosState, structure[systemInformation->family]);
							hash(systemInformationState, structure[systemInformation->family]);
						}
					} else if (headerType == Type::SystemEnclosure) {
						const auto systemEnclosure = reinterpret_cast<const SystemEnclosure*>(structure.header);

						hash(genericSmbiosState, structure[systemEnclosure->manufacturer]);
						hash(systemEnclosureState, structure[systemEnclosure->manufacturer]);
						hash(genericSmbiosState, structure[systemEnclosure->version]);
						hash(systemEnclosureState, structure[systemEnclosure->version]);
						hash(genericSmbiosState, structure[systemEnclosure->serialNumber]);
						hash(systemEnclosureState, structure[systemEnclosure->serialNumber]);
						hash(genericSmbiosState, structure[systemEnclosure->assetTagNumber]);
						hash(systemEnclosureState, structure[systemEnclosure->assetTagNumber]);
					} else if (headerType == Type::ProcessorInformation) {
						const auto processorInformation = reinterpret_cast<const ProcessorInformation*>(structure.header);

						hash(genericSmbiosState, structure[processorInformation->socketDesignation]);
						hash(processorInformationState, structure[processorInformation->socketDesignation]);
						hash(genericSmbiosState, structure[processorInformation->processor.version]);
						hash(processorInformationState, structure[processorInformation->processor.version]);
						hash(genericSmbiosState, &processorInformation->processor.id, sizeof(std::uint64_t));
						hash(processorInformationState, &processorInformation->processor.id, sizeof(std::uint64_t));
						if (version >= smbios::versions::v23) {
							hash(genericSmbiosState, structure[processorInformation->serialNumber]);
							hash(processorInformationState, structure[processorInformation->serialNumber]);
							hash(genericSmbiosState, structure[processorInformation->assetTag]);
							hash(processorInformationState, structure[processorInformation->assetTag]);
							hash(genericSmbiosState, structure[processorInformation->partNumber]);
							hash(processorInformationState, structure[processorInformation->partNumber]);
						}
						if (version >= smbios::versions::v25) {
							hash(genericSmbiosState, &processorInformation->counts, sizeof(ProcessorInformation::counts));
							hash(processorInformationState, &processorInformation->counts, sizeof(ProcessorInformation::counts));
						}
						if (version >= smbios::versions::v30) {
							hash(genericSmbiosState, &processorInformation->counts2, sizeof(ProcessorInformation::counts2));
							hash(processorInformationState, &processorInformation->counts2, sizeof(ProcessorInformation::counts2));
						}
					} else if (headerType == Type::CacheInformation) {
						const auto cacheInformation = reinterpret_cast<const CacheInformation*>(structure.header);
						hash(genericSmbiosState, structure[cacheInformation->socketDesignation]);
						hash(cacheInformationState, structure[cacheInformation->socketDesignation]);
					} else if (headerType == Type::SystemSlots) {
						const auto systemSlots = reinterpret_cast<const SystemSlots*>(structure.header);
						hash(genericSmbiosState, structure[systemSlots->slot.designation]);
						hash(systemSlotsState, structure[systemSlots->slot.designation]);
					} else if (headerType == Type::MemoryDevice && version >= smbios::versions::v21) {
						const auto memoryDevice = reinterpret_cast<const MemoryDevice*>(structure.header);
						
						hash(genericSmbiosState, structure[memoryDevice->deviceLocator]);
						hash(memoryDeviceState, structure[memoryDevice->deviceLocator]);
						hash(genericSmbiosState, structure[memoryDevice->bankLocator]);
						hash(memoryDeviceState, structure[memoryDevice->bankLocator]);
						if (version >= smbios::versions::v23) {
							hash(genericSmbiosState, structure[memoryDevice->manufacturer]);
							hash(memoryDeviceState, structure[memoryDevice->manufacturer]);
							hash(genericSmbiosState, structure[memoryDevice->serialNumber]);
							hash(memoryDeviceState, structure[memoryDevice->serialNumber]);
							hash(genericSmbiosState, structure[memoryDevice->assetTag]);
							hash(memoryDeviceState, structure[memoryDevice->assetTag]);
							hash(genericSmbiosState, structure[memoryDevice->partNumber]);
							hash(memoryDeviceState, structure[memoryDevice->partNumber]);
						}
						if (version >= smbios::versions::v32) {
							hash(genericSmbiosState, structure[memoryDevice->firmwareVersion]);
							hash(memoryDeviceState, structure[memoryDevice->firmwareVersion]);
						}
					}
					++calculatedStructureCount;
					VM_MAXIMUM_END
					__nop(); // Prevent tail call optimizations
				});
			nt::MmUnmapIoSpace(virtualAddress, tableLength);
		} else {
			if (Configuration::print)
				print(xorstr_("[!] Unable to map the smbios table. %p"), tablePhysicalAddress.QuadPart);
			smbiosSpoofed = true;
			break;
		}
		if (structureCount && calculatedStructureCount != structureCount) {
			if (Configuration::print)
				print(xorstr_("[!] smbios structure count mismatch %i %i"), structureCount, calculatedStructureCount);
			break;
		}
		if (!calculatedSize ||
			version <  smbios::versions::v30 && calculatedSize != tableLength ||
			version >= smbios::versions::v30 && calculatedSize >  tableLength) {
			if (Configuration::print)
				print(xorstr_("[!] smbios table size mismatch. %p %i %i"), tablePhysicalAddress.QuadPart, calculatedSize, tableLength);
			// TODO: smbios tampered, send ban request
			smbiosSpoofed = true;
			break;
		}
	} while (false);

	{
		auto smbiosSalt = xorstr(
			"\xcc\x04\x21\xd0\x2c\xb4\x2d\x18\x03\x89\x24\xcb\x1a\x01\x79\xc9"
			"\x25\x3d\x0a\x4d\xae\x46\xcc\x3b\xb4\x4e\xdc\x0b\x2a\x33\xec\x1d"
			"\x2d\x3c\xda\x61\x0d\x36\xdb\xe0\x10\x2b\xea\x19\xbf\x84\x2d\x66"
			"\xf9\x05\xce\x5c\x3b\x83\x86\x96\x48\x05\x31\x11\xc8\x2c\x28\x7c"
			"\xd5\x0d\xd8\x10\x69\x48\x04\x32\xbf\xda\xe0\x6b\x77\xcc\x09\xba"
			"\xfb\xe4\x88\x9e\x35\x4e\xdc\x08\x9c\x79\xc2\x2b\xb8\x9f\x1d\x5f"
			"\x9e\x69\x54\x70\x21\xae\xda\x6a\x28\x72\x99\xde\xcc\x36\x7e\x76"
			"\x2e\x41\x11\x6f\x3e\xf5\x8e\x22\x7e\x37\x4f\x58\x8d\x54\x9a\x1a"
			"\x63\x91\x99\x36\x67\xf0\x71\x24\x67\xb1\xb1\x6c\x16\x5b\x3e\x0f"
			"\x77\xbe\xff\x74\xe5\xd6\xe1\x7a\xdc\xaf\xed\x22\xa8\x71\xa7\x0f"
			"\x7d\x6c\x5d\x9d\xde\x8d\xc6\x85\x4c\xbf\xa4\xc3\x57\x2e\x8c\x73"
			"\x8d\x25\x72\xda\x60\x18\x0b\x49\x1e\x98\x8c\x52\xf4\x34\x5a\x31"
			"\xc5\x88\x32\x83\x20\x34\xdd\xb2\x16\xdf\x93\xd9\x57\xef\x45\xf2"
			"\xdd\x28\xc8\xdc\x00\x71\x73\x67\x63\xb8\x99\xde\x47\x53\x64\xff"
			"\x00\xc0\xc4\x06\xab\xa2\x45\x6d\xd0\x59\xdb\xf8\xd6\xb6\x43\xac"
			"\xdb\x19\x07\xf4\x86\xbe\x8a\xc1\xea\xe0\xa8\xd3\xe6\x26\xdd\x0f"
			"\xaf\xd3\x87\x58\x03\xab\xd1\x4f\xa8\x48\x4a\xe9\x73\xc0\xb1\x4e"
			"\x78\x3f\x5f\xd2\x89\x31\xdb\x22\x1a\x71\xd4\x97\x8e\x12\x1f\xa0"
			"\x69\x7d\x00\x78\x7d\xbc\x96\xac\xd9\xbb\x80\xfb\xe1\x1d\xe2\x76"
			"\x52\x8b\xd1\x4f\x46\x0b\x46\x99\xc7\x78\xa7\x3e\x2a\xad\x9e\x8b"
			"\xd4\xff\xbe\x33\xcb\xbb\x2d\xef\x0c\xbc\x34\xf7\x91\xee\x62\x07"
			"\xd0\x60\x1f\x9b\xd2\x1b\x66\x10\x8c\x12\xf3\x1b\xd4\x99\x77\xb6"
			"\x91\x0e\x0b\xad\x94\x54\x07\xd5\xdd\x66\xe4\x62\x0d\x93\x62\x26"
			"\x1b\x27\xc0\xe0\xcf\x52\x41\xce\x1d\x65\xad\x78\xb8\x8a\x78\xa5"
			"\x4f\x00\xa8\xd9\xcc\x5c\x56\x93\x48\x33\x66\xd8\x97\xc7\x47\x4d"
			"\xed\xd6\xfb\x8f\x34\x6d\x55\x55\x4f\xea\x92\x77\xcc\x1b\x41\x22"
			"\xe8\xe9\xf0\xb5\xf7\x8b\x4b\x44\xdd\x87\xfe\xe5\x64\x3c\xbb\xe7"
			"\x49\xae\xad\x35\x18\x6b\xf5\x0b\x57\x9b\x1d\x37\xf8\x4f\xcc\x9c"
			"\x40\x7c\x3a\xcf\xd6\xcf\x4a\xd2\x8b\xa9\xf3\x83\x51\x37\x7f\xbf"
			"\x13\x12\x2b\x4b\x8e\xee\x99\xc4\x0c\xc9\x05\x3c\x77\x1f\xe4\xc9"
			"\x2a\x38\x46\x23\xc3\xdb\xc4\x0d\x88\xc3\x48\x6d\x5e\xd4\x85\x6d"
			"\xc4\xc0\x73\x90\x76\xd0\xcb\xca\xaf\x98\x32\x5b\x29\xd9\xf5\xbc");
		smbiosSalt.crypt();
		libtomcrypt::sha512_process(&genericSmbiosState,        reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		libtomcrypt::sha512_process(&biosInformationState,      reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		libtomcrypt::sha512_process(&systemInformationState,    reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		libtomcrypt::sha512_process(&systemEnclosureState,      reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		libtomcrypt::sha512_process(&processorInformationState, reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		libtomcrypt::sha512_process(&cacheInformationState,     reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		libtomcrypt::sha512_process(&systemSlotsState,          reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		libtomcrypt::sha512_process(&memoryDeviceState,         reinterpret_cast<const std::uint8_t*>(smbiosSalt.get()), 512ul);
		smbiosSalt.crypt();
	}

	libtomcrypt::sha512_done(&genericSmbiosState,        this->genericSmbios.data());
	libtomcrypt::sha512_done(&biosInformationState,      this->biosInformation.data());
	libtomcrypt::sha512_done(&systemInformationState,    this->systemInformation.data());
	libtomcrypt::sha512_done(&systemEnclosureState,      this->systemEnclosure.data());
	libtomcrypt::sha512_done(&processorInformationState, this->processorInformation.data());
	libtomcrypt::sha512_done(&cacheInformationState,     this->cacheInformation.data());
	libtomcrypt::sha512_done(&systemSlotsState,          this->systemSlots.data());
	libtomcrypt::sha512_done(&memoryDeviceState,         this->memoryDevice.data());
	this->efi = hwid::efi();
	VM_MAXIMUM_END
}

hwid::HashBuffer hwid::efi() noexcept {
	VM_MAXIMUM_BEGIN
	tls::Array<sha512HashSize> efiHash {};

	libtomcrypt::hash_state efiState {};
	libtomcrypt::sha512_init(&efiState);

	if (efi::supported()) {
		const auto [buffer, size] = efi::variables();
		for (auto entry {reinterpret_cast<efi::VariableEntry*>(buffer.get())};
			entry->next; entry = reinterpret_cast<decltype(entry)>(reinterpret_cast<std::uintptr_t>(entry) + entry->next))
			if (const Hash nameHash {reinterpret_cast<const wchar_t*>(entry->name)};
				nameHash == Fnv1A(L"UnlockIDCopy") ||
				nameHash == Fnv1A(L"OfflineUniqueIDEKPub") ||
				nameHash == Fnv1A(L"OfflineUniqueIDEKPubCRC") ||
				nameHash == Fnv1A(L"OfflineUniqueIDRandomSeed") ||
				nameHash == Fnv1A(L"OfflineUniqueIDRandomSeedCRC") ||
				nameHash == Fnv1A(L"SignatureSupport"))
				hash(efiState, entry->name, &entry->guid);
	}
	{
		auto efiSalt = xorstr(
			"\x61\x83\x51\xf5\xe5\x2f\x90\x67\x0b\xae\x3c\x5b\x3d\x58\xcf\x6b"
			"\xc2\xea\x86\x01\xfe\xb8\x51\x3e\xb7\x0b\x12\xaf\xab\x84\x0c\x46"
			"\x8d\x01\x70\x30\x01\xca\x3f\x34\x2f\xdd\x00\x22\x96\xc2\x32\x4d"
			"\x4d\x88\x01\xbf\xe1\x91\x52\x5b\xba\x0d\xa3\x34\xab\x7f\xe2\x8c"
			"\xbe\xed\x02\xfc\x0f\xd5\x79\xc9\x21\x2c\x81\x36\x8f\xad\x56\xbe"
			"\xee\x73\x6d\x73\xb4\x7b\x9d\x6b\x3b\x6a\x65\xde\x21\x9b\x4d\x70"
			"\xf6\xf8\x37\x68\x77\xd2\x1d\xb3\x1a\x7f\x5b\x96\x43\xf4\xea\x3b"
			"\xd6\x39\xef\xfa\x57\x16\x2f\x0b\xad\x94\x5f\x14\x1d\x12\x3a\x17"
			"\x13\x7e\x2b\x0b\xfd\xc8\x15\xbe\x3c\x78\x06\x2c\xa3\x1e\x71\xa5"
			"\xef\x29\x3b\x0d\x80\x33\xa2\x79\xa2\x51\xdd\x05\xcd\x19\xfd\x1a"
			"\x7e\x98\x93\x93\xc8\xe6\x9d\x54\x06\x87\x1f\x4e\xad\x06\xc6\xd9"
			"\x6a\x32\xd7\x6e\x08\x7f\x0a\x1b\x83\x4a\xaf\x9d\xc4\x25\x09\x65"
			"\x45\xaa\xf6\xda\xb4\x84\x85\x41\x9b\x20\x63\x4b\xf0\xc3\x5a\x2e"
			"\xbf\xf6\x8b\x7e\xc5\x91\x69\x26\x79\x5d\x5b\x42\x7b\x53\x68\xa3"
			"\xc4\x2c\x1d\x44\x48\xbf\x68\x07\xaf\xcf\x1f\x02\x9e\xc8\x55\x9b"
			"\x27\x0a\xa6\x08\x25\xd2\xcc\x38\x3b\x61\x4a\x2c\xfb\x96\xc3\x11"
			"\xfe\x11\x7f\x97\xd7\x9c\x59\x19\x81\xf4\x30\x83\xc8\x6d\x7b\x4d"
			"\x2d\x7d\x16\xb2\x7f\x60\xae\x5c\x2e\xf5\xb7\xf8\xea\x55\x34\x75"
			"\x04\xdd\x28\x18\xd8\x41\xe1\x56\xa3\x74\xc5\x1e\x05\x56\x63\x58"
			"\xb7\x34\xa1\x72\x29\x7d\x6d\xb5\xe0\x98\xe3\x7d\x79\x9b\x95\x98"
			"\xf2\x08\xe9\xe5\x8d\x0a\xb5\x67\x97\x9f\xac\x4f\x03\xbd\x20\x01"
			"\x55\xdf\x29\xfe\x5f\xd5\xab\xdf\x75\xd6\x11\x59\xa7\x11\x0a\xa7"
			"\xea\x12\xf8\x88\x80\x3d\xea\x95\x30\xcd\x9b\x1e\xf7\x0c\x5a\x61"
			"\x8d\x9d\xb7\x6f\xc2\xf3\x5e\xda\xe3\x79\x71\x4e\x94\x4a\xd9\x8d"
			"\xed\x72\xc3\x1e\x4a\x7c\xf9\xba\xfe\x53\x5b\x98\xdf\x26\xa9\xe5"
			"\xdb\xd4\x96\xa4\xfc\x30\xeb\x64\x2a\x81\x11\x57\x4f\x03\x2b\x48"
			"\x37\xc6\x2d\x96\x8d\xbc\x35\x3a\xf6\x80\x1b\x99\x58\x92\xf9\xcd"
			"\x7f\xed\xa7\x9b\xa5\xc4\x1c\x21\x33\xb5\xff\x0f\x16\xe3\x78\x06"
			"\x91\x05\x42\x5e\xd6\x5e\x89\xca\x2a\xaf\x6d\x23\xff\x99\x97\x3e"
			"\x97\x12\x8e\x5d\xa1\x34\xfd\x95\x51\x20\xcb\x40\xac\x9c\x8a\x36"
			"\x5c\x28\x54\x58\x86\x6d\x36\x38\x9d\xb6\xf8\x8a\x30\xd5\xd4\xaa"
			"\x8d\xd8\xb4\x44\x3d\x07\xd4\xc8\x8c\x80\x16\x84\xd8\xbb\x4f\xa5");
		libtomcrypt::sha512_process(
			&efiState,
			reinterpret_cast<const std::uint8_t*>(efiSalt.crypt_get()),
			512ul);
		efiSalt.crypt();
	}
	libtomcrypt::sha512_done(&efiState, efiHash.data());
	VM_MAXIMUM_END
	return efiHash;
}
