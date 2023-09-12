#include "Strings.hpp"

#include "../Configuration.hpp"
#include "../Miscellaneous/Globals.hpp"

using namespace KM::Utilities;

std::wstring Strings::unicode(const std::string_view asciiString) {
	VM_MINIMUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	if (asciiString.empty())
		return {};

	ULONG length {};
	if (const auto status = nt::RtlMultiByteToUnicodeSize(&length, asciiString.data(), static_cast<ULONG>(asciiString.length()));
		status != STATUS_SUCCESS)
		return {};

	std::wstring buffer {};
	buffer.resize(length / sizeof(wchar_t));

	ULONG bytes {};
	if (const auto status = nt::RtlMultiByteToUnicodeN(buffer.data(), length, &bytes, asciiString.data(), static_cast<ULONG>(asciiString.length()));
		status != STATUS_SUCCESS)
		return {};

	if (length != bytes)
		buffer.resize(bytes / sizeof(wchar_t));
	VM_MINIMUM_END
	return buffer;
}

std::string Strings::ascii(const std::wstring_view wideString) {
	VM_MINIMUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	if (wideString.empty())
		return {};

	ULONG length {};
	if (const auto status = nt::RtlUnicodeToMultiByteSize(&length, wideString.data(), wideString.length() * sizeof(wchar_t));
		status != STATUS_SUCCESS)
		return {};

	std::string buffer {};
	buffer.resize(length);

	ULONG bytes {};
	if (const auto status = nt::RtlUnicodeToMultiByteN(buffer.data(), length, &bytes, wideString.data(), wideString.length() * sizeof(wchar_t));
		status != STATUS_SUCCESS)
		return {};

	if (length != bytes)
		buffer.resize(bytes);
	VM_MINIMUM_END
	return buffer;
}
