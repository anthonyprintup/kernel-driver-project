#include "Socket.hpp"

#include <charconv>

#include "../Globals.hpp"
#include "Winsock Kernel/Wsk.hpp"

using namespace KM::Miscellaneous::NetIo;

namespace impl = WinsockKernel::Implementation;

Socket::Socket(const ADDRESS_FAMILY addressFamily, const USHORT socketType, const ULONG protocol, const ULONG winsockKernelFlags) {
	VM_SIZE_SPEED_BEGIN
	this->socket = impl::create(*this, addressFamily, socketType, protocol, winsockKernelFlags);
	VM_SIZE_SPEED_END
}

Socket::~Socket() {
	MUTATE_BEGIN
	// ReSharper disable once CppExpressionWithoutSideEffects
	this->close();
	MUTATE_END
}

NTSTATUS Socket::close() const noexcept {
	VM_SIZE_SPEED_BEGIN
	auto volatile status {STATUS_NOT_CAPABLE};
	if (this->socket && this->socket->Dispatch)
		status = impl::close(*this);
	VM_SIZE_SPEED_END
	return status;
}

NTSTATUS Socket::bind(sockaddr *address) const noexcept {
	VM_SIZE_SPEED_BEGIN
	auto volatile status {STATUS_NOT_CAPABLE};
	if (this->socket && this->socket->Dispatch)
		status = impl::bind(*this, address);
	VM_SIZE_SPEED_END
	return status;
}

NTSTATUS Socket::connect(sockaddr *address) const noexcept {
	VM_SIZE_SPEED_BEGIN
	auto volatile status {STATUS_NOT_CAPABLE};
	if (this->socket && this->socket->Dispatch)
		status = impl::connect(*this, address);
	VM_SIZE_SPEED_END
	return status;
}

NTSTATUS Socket::connect(const std::string_view host, const std::uint16_t port) const noexcept {
	VM_SIZE_SPEED_BEGIN
	std::array<char, 6> buffer {}; // 5 + null terminator
	if (const auto [pointer, errorCode] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), port);
		errorCode != std::errc())
		return STATUS_UNSUCCESSFUL;
	
	const auto [errorCode, addressInformation] = impl::getAddressInformation(host, {buffer.data(), buffer.size() - 1}, nullptr);
	if (errorCode == STATUS_SUCCESS && addressInformation)
		return impl::connect(*this, addressInformation->base->ai_addr);

	const auto volatile status = STATUS_NOT_FOUND;
	VM_SIZE_SPEED_END
	return status;
}

std::pair<NTSTATUS, std::size_t> Socket::receive(void *buffer, const std::size_t length, const int flags) const noexcept {
	VM_SIZE_SPEED_BEGIN
	auto volatile status {STATUS_NOT_CAPABLE};
	std::size_t bytesReceived {};
	if (this->socket && this->socket->Dispatch) {
		auto remainingBytes = length;
		std::size_t offset {};
		while (true) {
			const auto [receiveStatus, receivedBytes] = impl::receive(*this, static_cast<std::uint8_t*>(buffer) + offset, remainingBytes, flags);
			if (receiveStatus != STATUS_SUCCESS)
				return {STATUS_UNSUCCESSFUL, 0};
			
			remainingBytes -= receivedBytes;
			offset += receivedBytes;
			if (!remainingBytes) {
				status = STATUS_SUCCESS;
				bytesReceived = length;
				break;
			}
		}
	}
	VM_SIZE_SPEED_END
	return {status, bytesReceived};
}

ReceiveBufferType Socket::receive(const int flags) const {
	VM_SIZE_SPEED_BEGIN
	ReceiveBufferType response {};
	
	std::array<char, 0x1000> buffer {};
	while (true) {
		const auto [status, receivedBytes] = impl::receive(*this, buffer.data(), buffer.size(), flags);
		if (receivedBytes > 0)
			response.insert(response.cend(), buffer.cbegin(), buffer.cbegin() + receivedBytes);
		else break;
	}
	VM_SIZE_SPEED_END
	return response;
}

ReceiveBufferType Socket::receive(std::function<bool(ReceiveBufferType &buffer)> &&callback, const int flags) const {
	VM_SIZE_SPEED_BEGIN
	ReceiveBufferType response {};

	std::array<char, 0x1000> buffer {};
	do {
		const auto [status, receivedBytes] = impl::receive(*this, buffer.data(), buffer.size(), flags);
		if (receivedBytes > 0)
			response.insert(response.cend(), buffer.cbegin(), buffer.cbegin() + receivedBytes);
		else break;
	} while (callback(response));
	VM_SIZE_SPEED_END
	return response;
}

std::pair<NTSTATUS, std::size_t> Socket::send(const void *buffer, const std::size_t length, const int flags) const noexcept {
	VM_SIZE_SPEED_BEGIN
	auto volatile status {STATUS_NOT_CAPABLE};
	std::size_t bytesSent {};
	if (this->socket && this->socket->Dispatch)
		return impl::send(*this, const_cast<void*>(buffer), length, flags);
	VM_SIZE_SPEED_END
	return {status, bytesSent};
}

std::size_t Socket::send(const std::string_view buffer, const int flags) const noexcept {
	VM_SIZE_SPEED_BEGIN
	if (this->socket && this->socket->Dispatch)
		return impl::send(*this, const_cast<char*>(buffer.data()), buffer.length(), flags).second;
	VM_SIZE_SPEED_END
	return {};
}
