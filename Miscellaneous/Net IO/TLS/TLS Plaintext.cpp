#include "TLS Plaintext.hpp"

using namespace tls;

#include "../../../Configuration.hpp"

stream::Writer TlsPlaintext::build() const {
	VM_MEDIUM_BEGIN
	stream::Writer writer {};

	writer.write<std::uint8_t>(static_cast<std::uint8_t>(this->contentType));
	writer.write<std::uint16_t>(static_cast<std::uint16_t>(this->protocolVersion));
	writer.write<std::uint16_t>(static_cast<std::uint16_t>(this->length));
	VM_MEDIUM_END
	return writer;
}
