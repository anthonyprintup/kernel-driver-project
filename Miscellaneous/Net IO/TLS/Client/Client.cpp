#include "Client.hpp"

using namespace tls::client;

#include "../../../Globals.hpp"
#include <Framework/Utilities/Strings/XorStr.hpp>

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments ...arguments) {
	if constexpr (Configuration::print) {
		VM_SIZE_BEGIN
		namespace nt = KM::Miscellaneous::Globals::NT;
		nt::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), arguments...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

Tls12Client::Tls12Client(const std::string_view hostname, const std::uint16_t port) {
	VM_SIZE_SPEED_BEGIN
	this->connect(hostname, port);
	VM_SIZE_SPEED_END
}

Tls12Client::~Tls12Client() noexcept {
	VM_SIZE_SPEED_BEGIN
	this->close();
	VM_SIZE_SPEED_END
}

void Tls12Client::connect(const std::string_view hostname, const std::uint16_t port) {
	VM_SIZE_SPEED_BEGIN
	if (this->socket.connect(hostname, port) != STATUS_SUCCESS) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Failed to connect to %.*s on port %i\n"), hostname.length(), hostname.data(), port);
		return;
	}

	this->tls12Handler.add<Aes256Sha384Secp256R1>();
	if (!this->tls12Handler.performHandshake(hostname)) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Failed to perform handshake when connection to %s on port %i\n"), hostname.data(), port);
		static_cast<void>(this->socket.close());
	}
	VM_SIZE_SPEED_END
}

void Tls12Client::close() const noexcept {
	static_cast<void>(this->socket.close());
}

tls::aes::DecryptedDataType Tls12Client::send(const SpanType data) {
	VM_SIZE_SPEED_BEGIN
	if (!this->tls12Handler.send(data)) {
		static_cast<void>(this->socket.close());
		return {};
	}

	auto response = this->tls12Handler.receive();
	if (response.empty())
		static_cast<void>(this->socket.close());
	VM_SIZE_SPEED_END
	return response;
}

tls::aes::DecryptedDataType Tls12Client::receive() {
	return this->tls12Handler.receive();
}
