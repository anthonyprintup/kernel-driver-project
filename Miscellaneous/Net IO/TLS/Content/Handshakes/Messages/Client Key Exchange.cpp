#include "Client Key Exchange.hpp"

using namespace tls::handshakes;

#include "../../../../../../Configuration.hpp"

ClientKeyExchange::ClientKeyExchange(const ProtocolVersion protocolVersion, const SpanType publicKey) noexcept:
	TlsPlaintext {.contentType = ContentType::HANDSHAKE, .protocolVersion = protocolVersion},
	Handshake {.type = HandshakeType::CLIENT_KEY_EXCHANGE},
	publicKey {publicKey} {}

tls::stream::Writer ClientKeyExchange::build() {
	VM_MEDIUM_BEGIN
	stream::Writer writer {};
	writer.reserve(128);

	writer.write<std::uint8_t>(static_cast<std::uint8_t>(this->publicKey.size()));
	writer.write(this->publicKey);

	const auto streamSize = writer.size();
	static_cast<Handshake*>(this)->length = streamSize;
	const auto handshakeHeader = static_cast<const Handshake>(*this).build();

	static_cast<TlsPlaintext*>(this)->length = streamSize + handshakeHeader.size();
	const auto recordHeader = static_cast<const TlsPlaintext>(*this).build();
	
	auto result = recordHeader + handshakeHeader + writer;
	VM_MEDIUM_END
	return result;
}
