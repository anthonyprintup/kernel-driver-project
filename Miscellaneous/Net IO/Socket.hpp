#pragma once

#include <cstdint>
#include <vector>
#include <functional>

#include "Winsock Kernel/Context.hpp"

namespace KM::Miscellaneous::NetIo {
	enum struct SocketType {
		BASIC      = WSK_FLAG_BASIC_SOCKET,
		LISTEN     = WSK_FLAG_LISTEN_SOCKET,
		CONNECTION = WSK_FLAG_CONNECTION_SOCKET,
		DATAGRAM   = WSK_FLAG_DATAGRAM_SOCKET,
		STREAM     = WSK_FLAG_STREAM_SOCKET
	};

	using SocketIdentifier = std::int32_t;
	constexpr SocketIdentifier invalidSocketIdentifier {-1};
	using ReceiveBufferType = std::vector<std::uint8_t>;
	struct Socket {
		SocketType type {SocketType::STREAM}; // the stream flag has most of the features
		WinsockKernel::Context context {};

		PWSK_SOCKET socket {};

		Socket(ADDRESS_FAMILY addressFamily, USHORT socketType, ULONG protocol, ULONG winsockKernelFlags = WSK_FLAG_STREAM_SOCKET);
		~Socket();
		
		NTSTATUS close() const noexcept;
		[[nodiscard]] NTSTATUS bind(sockaddr *address) const noexcept;
		[[nodiscard]] NTSTATUS connect(sockaddr *address) const noexcept;
		[[nodiscard]] NTSTATUS connect(std::string_view host, std::uint16_t port) const noexcept;
		[[nodiscard]] std::pair<NTSTATUS, std::size_t> receive(void *buffer, std::size_t length, int flags = 0) const noexcept;
		[[nodiscard]] ReceiveBufferType receive(int flags = 0) const;
		[[nodiscard]] ReceiveBufferType receive(std::function<bool(ReceiveBufferType &buffer)> &&callback, int flags = 0) const;
		[[nodiscard]] std::pair<NTSTATUS, std::size_t> send(const void *buffer, std::size_t length, int flags = 0) const noexcept;
		[[nodiscard]] std::size_t send(std::string_view buffer, int flags = 0) const noexcept;
	};
}
