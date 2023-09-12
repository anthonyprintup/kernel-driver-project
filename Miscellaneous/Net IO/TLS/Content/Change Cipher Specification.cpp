#include "Change Cipher Specification.hpp"

using namespace tls::handshakes;

#include "../../../../Configuration.hpp"

ChangeCipherSpecification::ChangeCipherSpecification(const ProtocolVersion protocolVersion) noexcept:
	TlsPlaintext {.contentType = ContentType::CHANGE_CIPHER_SPEC, .protocolVersion = protocolVersion} {}

tls::stream::Writer ChangeCipherSpecification::build() {
	VM_MEDIUM_BEGIN
	stream::Writer writer {};
	writer.write<std::uint8_t>(0x01); // Must be 0x01 by standard
	
	this->length = writer.size();
	const auto recordHeader = static_cast<const TlsPlaintext>(*this).build();
	auto result = recordHeader + writer;
	VM_MEDIUM_END
	return result;
}
