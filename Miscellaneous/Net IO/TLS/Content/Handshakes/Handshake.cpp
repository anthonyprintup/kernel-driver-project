#include "Handshake.hpp"

using namespace tls::handshakes;

#include "../../../../../Configuration.hpp"

tls::stream::Writer Handshake::build() const {
	VM_MEDIUM_BEGIN
	stream::Writer writer {};

	writer.write<std::uint8_t>(static_cast<std::uint8_t>(this->type));
	writer.write<stream::UnsignedInt24>(static_cast<decltype(stream::UnsignedInt24::value)>(this->length));
	VM_MEDIUM_END
	return writer;
}
