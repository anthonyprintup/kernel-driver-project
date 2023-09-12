#include "Wsk.hpp"

#include "../../Globals.hpp"
#include "../../../Utilities/Strings.hpp"

#include "Context.hpp"

#include <intrin.h>

using namespace KM::Miscellaneous::NetIo;
namespace nt = KM::Miscellaneous::Globals::NT;
namespace net = KM::Miscellaneous::Globals::NetIo;
namespace strings = KM::Utilities::Strings;
namespace impl = WinsockKernel::Implementation;

namespace detail {
	SocketIdentifier availableIdentifier() noexcept {
		VM_MINIMUM_BEGIN
		SocketIdentifier identifier {};
		for (auto iterator = net::sockets->cbegin(), end = net::sockets->cend();
			 iterator != end && iterator->first == identifier; ++iterator, ++identifier) {}
		VM_MINIMUM_END
		return identifier;
	}
}

NTSTATUS WinsockKernel::startup() noexcept {
	VM_MEDIUM_BEGIN
	auto volatile status {STATUS_UNSUCCESSFUL};
	WSK_CLIENT_NPI client {.Dispatch = &net::dispatch};
	if (status = nt::WskRegister(&client, &net::registration);
		status != STATUS_SUCCESS)
		return status;

	if (status = nt::WskCaptureProviderNPI(&net::registration, WSK_NO_WAIT, &net::provider);
		status != STATUS_SUCCESS) {
		nt::WskDeregister(&net::registration);
		return status;
	}
	VM_MEDIUM_END
	return status;
}

void WinsockKernel::cleanup() noexcept {
	VM_MEDIUM_BEGIN
	nt::WskReleaseProviderNPI(&net::registration);
	nt::WskDeregister(&net::registration);
	VM_MEDIUM_END
	__nop(); // Prevent tailcall optimizations
}

struct UnicodeString {
	UnicodeString(const std::wstring_view string):
		buffer {string} {}
	UnicodeString(const std::string_view string) {
		VM_MINIMUM_BEGIN
		this->buffer = strings::unicode(string);
		VM_MINIMUM_END
	}

	[[nodiscard]] UNICODE_STRING nt() const noexcept {
		const auto length = static_cast<USHORT>(this->buffer.length() * sizeof(wchar_t));
		const UNICODE_STRING string {length, length, const_cast<wchar_t*>(this->buffer.data())};
		return string;
	}
	explicit operator bool() const noexcept {
		return this->buffer.empty();
	}

	std::wstring buffer {};
};

__declspec(noinline) void impl::freeAddressInformation(ADDRINFOEXW *addressInformation) {
	VM_SIZE_SPEED_BEGIN
	if (!addressInformation)
		return;

	net::provider.Dispatch->WskFreeAddressInfo(net::provider.Client, addressInformation);
	addressInformation = nullptr;
	VM_SIZE_SPEED_END
}

std::pair<NTSTATUS, std::optional<WinsockKernel::AddressInformation<addrinfo>>>
impl::getAddressInformation(const std::string_view node, const std::string_view service, const addrinfo *hints) {
	VM_MINIMUM_BEGIN
	const auto context = WinsockKernel::create<Context>();
	if (!context)
		return {STATUS_NO_MEMORY, std::nullopt};

	const UnicodeString unicodeNode    {node};    auto unicodeNodeString    = unicodeNode.nt();
	const UnicodeString unicodeService {service}; auto unicodeServiceString = unicodeService.nt();
	const auto extendedHints = detail::convert(hints);

	PADDRINFOEXW extendedResult {};
	auto errorCode = net::provider.Dispatch->WskGetAddressInfo(
		net::provider.Client,
		&unicodeNodeString, &unicodeServiceString, 0,
		nullptr, extendedHints.base ? extendedHints.base.get() : nullptr, &extendedResult,
		nullptr, nullptr, context.irp.get());
	
	// Wait for the completion event
	if (errorCode == STATUS_PENDING)
		errorCode = context.wait();
	else if (errorCode != STATUS_SUCCESS)
		return {errorCode, std::nullopt};

	// If WskGetAddressInfo failed, the parameter will be nullptr, so this is safe
	auto result = detail::convert(extendedResult);
	freeAddressInformation(extendedResult);
	VM_MINIMUM_END
	return {errorCode, std::move(result)};
}

PWSK_SOCKET impl::create(Socket &socket, const ADDRESS_FAMILY addressFamily, const USHORT socketType, const ULONG protocol, const ULONG winsockKernelFlags) noexcept {
	VM_SIZE_SPEED_BEGIN
	socket.context.reuse();
	auto status = net::provider.Dispatch->WskSocket(
		net::provider.Client, addressFamily, socketType, protocol, winsockKernelFlags,
		nullptr, nullptr, nullptr, nullptr, nullptr, socket.context.irp.get());
	if (status == STATUS_PENDING) status = socket.context.wait();
	if (status != STATUS_SUCCESS) return {};

	const auto volatile wskSocket = reinterpret_cast<PWSK_SOCKET>(socket.context.irp->IoStatus.Information);
	socket.socket = wskSocket;
	VM_SIZE_SPEED_END
	return wskSocket;
}
SocketIdentifier impl::create(const ADDRESS_FAMILY addressFamily, const USHORT socketType, const ULONG protocol, const ULONG winsockKernelFlags) {
	VM_MINIMUM_BEGIN
	net::mutex->acquire();
	auto identifier = ::detail::availableIdentifier();
	const auto [iterator, inserted] = net::sockets->try_emplace(identifier, addressFamily, socketType, protocol, winsockKernelFlags);
	if (inserted && !iterator->second.socket) { // Error occurred
		net::sockets->erase(iterator);
		identifier = invalidSocketIdentifier;
	}
	net::mutex->release();
	VM_MINIMUM_END
	return identifier;
}

NTSTATUS impl::close(const Socket &socket) noexcept {
	VM_SIZE_SPEED_BEGIN
	socket.context.reuse();
	auto volatile status = static_cast<const WSK_PROVIDER_BASIC_DISPATCH*>(socket.socket->Dispatch)->WskCloseSocket(socket.socket, socket.context.irp.get());
	if (status == STATUS_PENDING)
		status = socket.context.wait();
	VM_SIZE_SPEED_END
	return status;
}
NTSTATUS impl::close(const SocketIdentifier identifier) noexcept {
	VM_MINIMUM_BEGIN
	net::mutex->acquire();
	const auto volatile erased = net::sockets->erase(identifier) == 1 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
	net::mutex->release();
	VM_MINIMUM_END
	return erased;
}


NTSTATUS impl::bind(const Socket &socket, const PSOCKADDR address) noexcept {
	VM_SIZE_SPEED_BEGIN
	if (socket.type == SocketType::BASIC)
		return STATUS_NOT_CAPABLE;

	socket.context.reuse();
	NTSTATUS status {};
	if (socket.type == SocketType::LISTEN)
		status = static_cast<const WSK_PROVIDER_LISTEN_DISPATCH*>(socket.socket->Dispatch)->WskBind(socket.socket, address, 0, socket.context.irp.get());
	else if (socket.type == SocketType::CONNECTION)
		status = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket.socket->Dispatch)->WskBind(socket.socket, address, 0, socket.context.irp.get());
	else if (socket.type == SocketType::DATAGRAM)
		status = static_cast<const WSK_PROVIDER_DATAGRAM_DISPATCH*>(socket.socket->Dispatch)->WskBind(socket.socket, address, 0, socket.context.irp.get());
	else if (socket.type == SocketType::STREAM)
		status = static_cast<const WSK_PROVIDER_STREAM_DISPATCH*>(socket.socket->Dispatch)->WskBind(socket.socket, address, 0, socket.context.irp.get());
	if (status == STATUS_PENDING)
		status = socket.context.wait();
	VM_SIZE_SPEED_END
	return status;
}
NTSTATUS impl::bind(const SocketIdentifier identifier, sockaddr *address) noexcept {
	VM_MINIMUM_BEGIN
	const auto iterator = net::sockets->find(identifier);
	if (iterator == net::sockets->cend())
		return STATUS_NOT_FOUND;

	const auto volatile status = iterator->second.bind(address);
	VM_MINIMUM_END
	return status;
}


NTSTATUS impl::connect(const Socket &socket, sockaddr *address) {
	VM_MINIMUM_BEGIN
	if (socket.type != SocketType::CONNECTION && socket.type != SocketType::STREAM)
		return STATUS_NOT_CAPABLE;
	
	SOCKADDR_IN localAddress {AF_INET, 0, INADDR_ANY};
	if (const auto status = socket.bind(reinterpret_cast<sockaddr*>(&localAddress));
		status != STATUS_SUCCESS)
		return status;

	socket.context.reuse();
	NTSTATUS status {};
	if (socket.type == SocketType::CONNECTION)
		status = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket.socket->Dispatch)->WskConnect(socket.socket, address, 0, socket.context.irp.get());
	else if (socket.type == SocketType::STREAM)
		status = static_cast<const WSK_PROVIDER_STREAM_DISPATCH*>(socket.socket->Dispatch)->WskConnect(socket.socket, address, 0, socket.context.irp.get());
	if (status == STATUS_PENDING)
		status = socket.context.wait();
	VM_MINIMUM_END
	return status;
}
NTSTATUS impl::connect(const SocketIdentifier identifier, sockaddr *address) noexcept {
	VM_MINIMUM_BEGIN
	const auto iterator = net::sockets->find(identifier);
	if (iterator == net::sockets->cend())
		return STATUS_NOT_FOUND;

	const auto volatile status = iterator->second.connect(address);
	VM_MINIMUM_END
	return status;
}

std::pair<NTSTATUS, std::size_t> impl::send(const Socket &socket, void *buffer, const std::size_t length, const int flags) noexcept {
	VM_MINIMUM_BEGIN
	if (socket.type != SocketType::CONNECTION && socket.type != SocketType::STREAM)
		return {STATUS_NOT_CAPABLE, 0};
	
	WSK_BUF wskBuffer {nt::IoAllocateMdl(buffer, length, false, false, nullptr), 0, length};
	nt::MmProbeAndLockProcessPages(wskBuffer.Mdl, nt::IoGetCurrentProcess(), KernelMode, IoWriteAccess);

	socket.context.reuse();
	NTSTATUS status {};
	if (socket.type == SocketType::CONNECTION)
		status = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket.socket->Dispatch)->WskSend(socket.socket, &wskBuffer, flags, socket.context.irp.get());
	else if (socket.type == SocketType::STREAM)
		status = static_cast<const WSK_PROVIDER_STREAM_DISPATCH*>(socket.socket->Dispatch)->WskSend(socket.socket, &wskBuffer, flags, socket.context.irp.get());
	if (status == STATUS_PENDING) status = socket.context.wait();
	
	nt::MmUnlockPages(wskBuffer.Mdl);
	nt::IoFreeMdl(wskBuffer.Mdl);

	if (status != STATUS_SUCCESS) return {status, 0};
	const auto bytesSent = static_cast<std::size_t>(static_cast<ULONG>(socket.context.irp->IoStatus.Information));
	VM_MINIMUM_END
	return {status, bytesSent};
}
std::pair<NTSTATUS, std::size_t> impl::send(const SocketIdentifier identifier, void *buffer, const std::size_t length, const int flags) noexcept {
	VM_MINIMUM_BEGIN
	const auto iterator = net::sockets->find(identifier);
	if (iterator == net::sockets->cend())
		return {STATUS_NOT_FOUND, 0};

	const auto result = iterator->second.send(buffer, length, flags);
	VM_MINIMUM_END
	return result;
}

std::pair<NTSTATUS, std::size_t> impl::receive(const Socket &socket, void *buffer, const std::size_t length, const int flags) noexcept {
	VM_MINIMUM_BEGIN
	if (socket.type != SocketType::CONNECTION && socket.type != SocketType::STREAM)
		return {STATUS_NOT_CAPABLE, 0};
	
	WSK_BUF wskBuffer {nt::IoAllocateMdl(buffer, length, false, false, nullptr), 0, length};
	nt::MmProbeAndLockProcessPages(wskBuffer.Mdl, nt::IoGetCurrentProcess(), KernelMode, IoWriteAccess);

	socket.context.reuse();
	NTSTATUS status {};
	if (socket.type == SocketType::CONNECTION)
		status = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket.socket->Dispatch)->WskReceive(socket.socket, &wskBuffer, flags, socket.context.irp.get());
	else if (socket.type == SocketType::STREAM)
		status = static_cast<const WSK_PROVIDER_STREAM_DISPATCH*>(socket.socket->Dispatch)->WskReceive(socket.socket, &wskBuffer, flags, socket.context.irp.get());
	if (status == STATUS_PENDING) status = socket.context.wait();
	
	nt::MmUnlockPages(wskBuffer.Mdl);
	nt::IoFreeMdl(wskBuffer.Mdl);

	if (status != STATUS_SUCCESS) return {status, 0};
	const auto bytesReceived = static_cast<std::size_t>(static_cast<ULONG>(socket.context.irp->IoStatus.Information));
	VM_MINIMUM_END
	return {status, bytesReceived};
}
std::pair<NTSTATUS, std::size_t> impl::receive(const SocketIdentifier identifier, void *buffer, const std::size_t length, const int flags) noexcept {
	VM_MINIMUM_BEGIN
	const auto iterator = net::sockets->find(identifier);
	if (iterator == net::sockets->cend())
		return {STATUS_NOT_FOUND, 0};

	const auto result = iterator->second.receive(buffer, length, flags);
	VM_MINIMUM_END
	return result;
}
