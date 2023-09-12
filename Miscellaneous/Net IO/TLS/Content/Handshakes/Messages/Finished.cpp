#include "Finished.hpp"

using namespace tls::handshakes;

#include "../../../../../../Configuration.hpp"

Finished::Finished(const ProtocolVersion protocolVersion, const SpanType handshake) noexcept:
	TlsPlaintext {.contentType = ContentType::HANDSHAKE, .protocolVersion = protocolVersion},
	Handshake {.type = HandshakeType::FINISHED},
	handshake {handshake} {}

tls::stream::Writer Finished::build() {
	VM_MEDIUM_BEGIN
	stream::Writer writer {};
	writer.reserve(48);

	writer.write(this->iv);
	writer.write(this->handshake);

	static_cast<TlsPlaintext*>(this)->length = writer.size();
	const auto recordHeader = static_cast<const TlsPlaintext>(*this).build();

	auto result = recordHeader + writer;
	VM_MEDIUM_END
	return result;
}
