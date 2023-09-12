#include "efi.hpp"

#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../../Configuration.hpp"
#include "../Globals.hpp"

using namespace KM::Miscellaneous;

std::pair<std::unique_ptr<std::uint8_t[]>, std::size_t> efi::variables() noexcept {
	VM_MAXIMUM_BEGIN
	namespace nt = Globals::NT;

	ULONG size {};
	constexpr auto informationClass {1};
	auto status = nt::HalEnumerateEnvironmentVariablesEx(informationClass, nullptr, &size);
	if (status != STATUS_BUFFER_TOO_SMALL)
		return {};

	auto buffer = std::make_unique<std::uint8_t[]>(size);
	status = nt::HalEnumerateEnvironmentVariablesEx(informationClass, buffer.get(), &size);
	if (status != STATUS_SUCCESS)
		return {};
	VM_MAXIMUM_END

	return {std::move(buffer), static_cast<std::size_t>(size)};
}

efi::RawQueryType efi::variable(const std::wstring_view variable, const PGUID guid, void *outputBuffer, const std::size_t outputBufferSize) noexcept {
	VM_MAXIMUM_BEGIN
	namespace nt = Globals::NT;
	UNICODE_STRING string {
		static_cast<USHORT>(variable.length() * 2), static_cast<USHORT>(variable.length() * 2),
		const_cast<wchar_t*>(variable.data())};
	ULONG size {};
	if (!outputBuffer) {
		const auto status = nt::ExGetFirmwareEnvironmentVariable(&string, guid, nullptr, &size, nullptr);
		return {status, size};
	}

	size = static_cast<ULONG>(outputBufferSize);
	const auto status = nt::ExGetFirmwareEnvironmentVariable(&string, guid, outputBuffer, &size, nullptr);
	VM_MAXIMUM_END
	return {status, size};
}

efi::QueryType efi::variable(const std::wstring_view variable, const PGUID guid) noexcept {
	VM_MAXIMUM_BEGIN
	const auto query = efi::variable(variable, guid, nullptr, 0);
	if (query.status != STATUS_BUFFER_TOO_SMALL)
		return {{query.status, query.size}, nullptr};
	
	auto buffer = std::make_unique<std::uint8_t[]>(query.size);
	const auto result = efi::variable(variable, guid, buffer.get(), query.size);
	if (result.status == STATUS_SUCCESS)
		return {result, std::move(buffer)};
	VM_MAXIMUM_END

	return {result, nullptr};
}

bool efi::supported() noexcept {
	VM_MAXIMUM_BEGIN
	namespace nt = Globals::NT;

	GUID guid {};
	const auto efiSupported = efi::variable(xorstr_(L""), &guid).status != STATUS_NOT_IMPLEMENTED;
	
	ULONG size {};
	constexpr auto informationClass {1};
	const auto supported = nt::HalEnumerateEnvironmentVariablesEx(informationClass, nullptr, &size) == STATUS_BUFFER_TOO_SMALL;
	VM_MAXIMUM_END
	
	return supported && efiSupported;
}
