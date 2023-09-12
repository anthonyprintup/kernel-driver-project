#pragma once

#include "Protocol Handler.hpp"

namespace tls::client {
	struct Tls12Client {
		Tls12Client() = default;
		Tls12Client(std::string_view hostname, std::uint16_t port);

		Tls12Client(const Tls12Client&) = delete;
		Tls12Client(Tls12Client&&)      = delete;
		~Tls12Client() noexcept;

		auto operator =(const Tls12Client&) = delete;
		auto operator =(Tls12Client&&)      = delete;

		void connect(std::string_view hostname, std::uint16_t port);
		void close() const noexcept;

		aes::DecryptedDataType send(SpanType data);
		aes::DecryptedDataType receive();
	private:
		KM::Miscellaneous::NetIo::Socket socket {AF_INET, SOCK_STREAM, IPPROTO_TCP};
		Tls12ProtocolHandler tls12Handler {socket, ProtocolVersion::VERSION_1_2};
	};
}
