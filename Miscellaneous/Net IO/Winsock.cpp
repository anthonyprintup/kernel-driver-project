#include "Winsock.hpp"

#include "../Globals.hpp"
#include "Winsock Kernel/Wsk.hpp"

using namespace KM::Miscellaneous::NetIo;
namespace impl = WinsockKernel::Implementation;

// ReSharper disable once CppInconsistentNaming
constexpr auto SOCKET_ERROR = -1;

int Winsock::bind(const int socket, const sockaddr *address, [[maybe_unused]] socklen_t addressLength) {
	MUTATE_BEGIN
	const auto volatile error = impl::bind(socket, const_cast<sockaddr*>(address)) == STATUS_SUCCESS ? 0 : SOCKET_ERROR;
	MUTATE_END
	return error;
}

int Winsock::connect(const int socket, const sockaddr *address, [[maybe_unused]] socklen_t addressLength) {
	MUTATE_BEGIN
	const auto volatile error = impl::connect(socket, const_cast<sockaddr*>(address)) == STATUS_SUCCESS ? 0 : SOCKET_ERROR;
	MUTATE_END
	return error;
}

Winsock::ssize_t Winsock::recv(const int socket, void *buffer, const size_t length, const int flags) {
	MUTATE_BEGIN
	const auto [status, bytesReceived] = impl::receive(socket, buffer, length, flags);
	if (status != STATUS_SUCCESS)
		return SOCKET_ERROR;
	MUTATE_END
	return bytesReceived;
}

Winsock::ssize_t Winsock::send(const int socket, const void *message, const size_t length, const int flags) {
	MUTATE_BEGIN
	const auto [status, bytesSent] = impl::send(socket, const_cast<void*>(message), length, flags);
	if (status != STATUS_SUCCESS)
		return SOCKET_ERROR;
	MUTATE_END
	return bytesSent;
}

int Winsock::closesocket(const int socket) {
	MUTATE_BEGIN
	const auto volatile error = impl::close(socket) == STATUS_SUCCESS ? 0 : SOCKET_ERROR;
	MUTATE_END
	return error;
}

int Winsock::socket(const int domain, const int type, const int protocol) {
	MUTATE_BEGIN
	const auto volatile identifier = impl::create(domain, type, protocol);
	MUTATE_END
	return identifier;
}

int Winsock::getaddrinfo(const char *node, const char *service, const addrinfo *hints, addrinfo **result) {
	VM_MINIMUM_BEGIN
	const auto nodeView    = node ? node : std::string_view {};
	const auto serviceView = service ? service : std::string_view {};
	
	auto [errorCode, addressInformation] = impl::getAddressInformation(nodeView, serviceView, hints);
	if (errorCode == STATUS_SUCCESS && addressInformation && result)
		*result = addressInformation->release();
	VM_MINIMUM_END
	return errorCode;
}

void Winsock::freeaddrinfo(addrinfo *result) {
	VM_MINIMUM_BEGIN
	if (!result)
		return;
	
	if (result->ai_next)
		freeaddrinfo(result->ai_next);
	if (result->ai_canonname)
		delete result->ai_canonname;
	delete result;
	VM_MINIMUM_END
}
