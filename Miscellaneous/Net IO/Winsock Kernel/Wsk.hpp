#pragma once

#include <optional>
#include <string_view>

#include "../../../Utilities/NT/Definitions.hpp"
#include "Address Information.hpp"
#include "../Socket.hpp"

namespace KM::Miscellaneous::NetIo::WinsockKernel {
	NTSTATUS startup() noexcept;
	void     cleanup() noexcept;

	namespace Implementation {
		void freeAddressInformation(ADDRINFOEXW *addressInformation);
		std::pair<NTSTATUS, std::optional<AddressInformation<addrinfo>>>
		getAddressInformation(std::string_view node, std::string_view service, const addrinfo *hints);

		PWSK_SOCKET create(Socket &socket, ADDRESS_FAMILY addressFamily, USHORT socketType, ULONG protocol, ULONG winsockKernelFlags = WSK_FLAG_STREAM_SOCKET) noexcept;
		SocketIdentifier create(ADDRESS_FAMILY addressFamily, USHORT socketType, ULONG protocol, ULONG winsockKernelFlags = WSK_FLAG_STREAM_SOCKET);

		NTSTATUS close(const Socket &socket) noexcept;
		NTSTATUS close(SocketIdentifier identifier) noexcept;

		NTSTATUS bind(const Socket &socket, PSOCKADDR address) noexcept;
		NTSTATUS bind(SocketIdentifier identifier, sockaddr *address) noexcept;

		NTSTATUS connect(const Socket &socket, sockaddr *address);
		NTSTATUS connect(SocketIdentifier identifier, sockaddr *address) noexcept;

		std::pair<NTSTATUS, std::size_t> send(const Socket &socket, void *buffer, std::size_t length, int flags) noexcept;
		std::pair<NTSTATUS, std::size_t> send(SocketIdentifier identifier, void *buffer, std::size_t length, int flags) noexcept;
		
		std::pair<NTSTATUS, std::size_t> receive(const Socket &socket, void *buffer, std::size_t length, int flags) noexcept;
		std::pair<NTSTATUS, std::size_t> receive(SocketIdentifier identifier, void *buffer, std::size_t length, int flags) noexcept;
	}
}
