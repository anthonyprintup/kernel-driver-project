// ReSharper disable CppInconsistentNaming
#include "NT.hpp"

#include <intrin.h>

#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../../Configuration.hpp"
#include "../Scanner.hpp"
#include "../../Miscellaneous/Globals.hpp"
using namespace KM::Utilities;

std::uintptr_t NT::Kernel::ntoskrnl() noexcept {
	VM_MAXIMUM_BEGIN
	constexpr auto LSTAR_MSR {0xC0000082};
	const auto kiSystemCall64 = __readmsr(LSTAR_MSR);
	std::uintptr_t rdataAddress {};
	if (*reinterpret_cast<std::uint32_t*>(kiSystemCall64 + 8) != 0x10) { // shadowing enabled
		auto kiSystemServiceUser = Scanner::scan(
			reinterpret_cast<std::uint8_t*>(kiSystemCall64), 0x300,
			reinterpret_cast<std::uint8_t*>(xorstr_("\x65\xC6\x04\x25\x00\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xC3")),
			reinterpret_cast<std::uint8_t*>(xorstr_("\xFF\xFF\xFF\xFF\x2E\x2E\x2E\x2E\x2E\xFF\x2E\x2E\x2E\x2E\xFF")), 10);
		kiSystemServiceUser += *reinterpret_cast<std::int32_t*>(kiSystemServiceUser) + sizeof(std::int32_t);

		auto mmUserProbeAddress = Scanner::scan(
			reinterpret_cast<std::uint8_t*>(kiSystemServiceUser), 0x200,
			reinterpret_cast<std::uint8_t*>(xorstr_("\xB9\x02\x01\x00\xC0\x0F\x32")),
			reinterpret_cast<std::uint8_t*>(xorstr_("\xFF\xFF\xFF\xFF\xFF\xFF\xFF")), 17);
		rdataAddress = mmUserProbeAddress += *reinterpret_cast<std::int32_t*>(mmUserProbeAddress) + sizeof(std::int32_t);
	} else {
		auto mmUserProbeAddress = Scanner::scan(
			reinterpret_cast<std::uint8_t*>(kiSystemCall64), 0xB00,
			reinterpret_cast<std::uint8_t*>(xorstr_("\xB9\x02\x01\x00\xC0\x0F\x32")),
			reinterpret_cast<std::uint8_t*>(xorstr_("\xFF\xFF\xFF\xFF\xFF\xFF\xFF")), 17);
		rdataAddress = mmUserProbeAddress += *reinterpret_cast<std::int32_t*>(mmUserProbeAddress) + sizeof(std::int32_t);
	}

	std::uintptr_t base {};
	for (auto address {rdataAddress & 0xFFFFFFFFFFFF0000};; address -= 0x1000) {
		const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(address);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			continue;
		
		base = address;
		break;
	}
	VM_MAXIMUM_END
	return base;
}

std::uintptr_t NT::Kernel::keServiceDescriptorTableShadow() noexcept {
	namespace nt = Miscellaneous::Globals::NT;
	constexpr auto LSTAR_MSR {0xC0000082};
	
	SYSTEM_KERNEL_VA_SHADOW_INFORMATION shadowInformation {};
	nt::ZwQuerySystemInformation(SystemKernelVaShadowInformation, &shadowInformation, sizeof(shadowInformation), nullptr);
	if (shadowInformation.KvaShadowFlags.KvaShadowEnabled) {
		const auto kiSystemCall64Shadow = __readmsr(LSTAR_MSR);

		const auto jmp = Scanner::scan(
			reinterpret_cast<std::uint8_t*>(kiSystemCall64Shadow), 0x300,
			reinterpret_cast<std::uint8_t*>(xorstr_("\x65\xC6\x04\x25\x00\x00\x00\x00\x00\xE9")),
			reinterpret_cast<std::uint8_t*>(xorstr_("xxxx....xx")), 10);
		if (!jmp)
			return {};

		const auto kiSystemServiceUser = jmp + sizeof(std::int32_t) + *reinterpret_cast<std::int32_t*>(jmp);
		const auto keServiceDescriptorTableShadow = Scanner::scan(
			reinterpret_cast<std::uint8_t*>(kiSystemServiceUser), 0x200,
			reinterpret_cast<std::uint8_t*>(xorstr_("\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F")),
			reinterpret_cast<std::uint8_t*>(xorstr_("xxxxxxxxx")), 21);
		if (!keServiceDescriptorTableShadow)
			return {};

		return keServiceDescriptorTableShadow + sizeof(std::int32_t) + *reinterpret_cast<std::int32_t*>(keServiceDescriptorTableShadow);
	}

	const auto kiSystemCall64 = __readmsr(LSTAR_MSR);
	const auto keServiceDescriptorTableShadow = Scanner::scan(
		reinterpret_cast<std::uint8_t*>(kiSystemCall64), 0xB00,
		reinterpret_cast<std::uint8_t*>(xorstr_("\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F")),
		reinterpret_cast<std::uint8_t*>(xorstr_("xxxxxxxxx")), 21);
	if (!keServiceDescriptorTableShadow)
		return {};

	return keServiceDescriptorTableShadow + sizeof(std::int32_t) + *reinterpret_cast<std::int32_t*>(keServiceDescriptorTableShadow);
}
