// ReSharper disable CppInconsistentNaming
#pragma once

#include <cstdint>

#include "../../Utilities/NT/Definitions.hpp"

namespace KM::Miscellaneous::NetIo::Winsock {
	// https://docs.microsoft.com/en-us/windows/win32/api/_winsock/
	using socklen_t = std::int32_t;
	using ssize_t   = std::intptr_t;
	using msghdr    = WSAMSG;

	int     accept     (int socket, sockaddr *address, socklen_t *addressLength);
	int     bind       (int socket, const sockaddr *address, socklen_t addressLength);
	int     connect    (int socket, const sockaddr *address, socklen_t addressLength);
	int     getpeername(int socket, sockaddr *address, socklen_t *addressLength);
	int     getsockname(int socket, sockaddr *address, socklen_t *addressLength);
	int     getsockopt (int socket, int level, int optionName, void *optionValue, socklen_t *optionLength);
	int     listen     (int socket, int backlog);
	ssize_t recv       (int socket, void *buffer, size_t length, int flags);
	ssize_t recvfrom   (int socket, void *buffer, size_t length, int flags, sockaddr *address, socklen_t *addressLength);
	ssize_t recvmsg    (int socket, msghdr *message, int flags);
	ssize_t send       (int socket, const void *message, size_t length, int flags);
	ssize_t sendmsg    (int socket, const msghdr *message, int flags);
	ssize_t sendto     (int socket, const void *message, size_t length, int flags, const sockaddr *destinationAddress, socklen_t destinationLength);
	int     setsockopt (int socket, int level, int optionName, const void *optionValue, socklen_t optionLength);
	int     closesocket(int socket);
	int     socket     (int domain, int type, int protocol);

	int     getaddrinfo (const char *node, const char *service, const addrinfo *hints, addrinfo **result);
	void    freeaddrinfo(addrinfo *result);
	
	/*
	htond
	htonf
	htonl
	htonll
	htons
	ntohd
	ntohf
	ntohl
	ntohll
	ntohs
	 */
}
