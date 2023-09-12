#include "Address Information.hpp"

#include "../../Globals.hpp"
#include "../../../Utilities/Strings.hpp"
namespace strings = KM::Utilities::Strings;

using namespace KM::Miscellaneous::NetIo::WinsockKernel;

AddressInformation<ADDRINFOEXW> detail::convert(const addrinfo *information) {
	VM_MINIMUM_BEGIN
	if (!information)
		return {};

	AddressInformation<ADDRINFOEXW> converted {};
	if (information->ai_canonname) {
		const auto unicode = strings::unicode(information->ai_canonname);
		converted.name.length = unicode.length();
		converted.name.buffer = std::make_unique<decltype(converted)::UnderlyingStringType>((converted.name.length + 1) * sizeof(wchar_t));
		std::memcpy(converted.name.buffer.get(), unicode.data(), (converted.name.length + 1) * sizeof(wchar_t));
	}
	if (information->ai_next)
		converted.next = std::make_unique<decltype(converted)>(convert(information->ai_next));

	converted.base = std::make_unique<decltype(converted)::BaseType>();
	std::memset(converted.base.get(), 0, sizeof(decltype(converted)::BaseType));
	new (converted.base.get()) decltype(converted)::BaseType {
		.ai_flags     = information->ai_flags,
		.ai_family    = information->ai_family,
		.ai_socktype  = information->ai_socktype,
		.ai_protocol  = information->ai_protocol,
		.ai_addrlen   = information->ai_addrlen,
		.ai_canonname = converted.name.buffer.get(),
		.ai_addr      = information->ai_addr,
		.ai_next      = information->ai_next ? converted.next->base.get() : nullptr};
	VM_MINIMUM_END
	return converted;
}

AddressInformation<addrinfo> detail::convert(const ADDRINFOEXW *information) {
	VM_MINIMUM_BEGIN
	if (!information)
		return {};

	AddressInformation<addrinfo> converted {};
	if (information->ai_canonname) {
		const auto unicode = strings::ascii(information->ai_canonname);
		converted.name.length = unicode.length();
		converted.name.buffer = std::make_unique<decltype(converted)::UnderlyingStringType>(converted.name.length + 1);
		std::memcpy(converted.name.buffer.get(), unicode.data(), converted.name.length + 1);
	}
	if (information->ai_next)
		converted.next = std::make_unique<decltype(converted)>(convert(information->ai_next));
	converted.base = std::make_unique<decltype(converted)::BaseType>();
	std::memset(converted.base.get(), 0, sizeof(decltype(converted)::BaseType));
	new (converted.base.get()) decltype(converted)::BaseType {
		.ai_flags     = information->ai_flags,
		.ai_family    = information->ai_family,
		.ai_socktype  = information->ai_socktype,
		.ai_protocol  = information->ai_protocol,
		.ai_addrlen   = information->ai_addrlen,
		.ai_canonname = converted.name.buffer.get(),
		.ai_addr      = information->ai_addr,
		.ai_next      = information->ai_next ? converted.next->base.get() : nullptr};
	VM_MINIMUM_END
	return converted;
}
