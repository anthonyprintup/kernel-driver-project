// ReSharper disable CppInconsistentNaming
// ReSharper disable CppDeprecatedEntity
#include <ntdef.h> // TODO: custom declarations
#include <ntddk.h> // TODO: custom declarations

#include <string>
#include <Framework/Utilities/Strings/Fnv1A.hpp>
#include <Framework/Utilities/Strings/XorStr.hpp>

#include "Miscellaneous/Globals.hpp"

#include "System Calls/Hook.hpp"

#include "Miscellaneous/Net IO/TLS/Client/Client.hpp"
#include "Miscellaneous/Net IO/Winsock Kernel/Wsk.hpp"

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments &&...arguments) {
	if constexpr (Configuration::print) {
		VM_SIZE_BEGIN
		using namespace KM::Miscellaneous::Globals;
		NT::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), std::forward<Arguments>(arguments)...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

// TODO: code virtualizer doesn't remove the vm signatures from the binary (.text section), strip them using post build events (or use imports/lib)
// TODO: add check to see who loaded us (add a way to identify our proprietary loader)
// TODO: null all strings/buffers after they're used to prevent getting reversed with mem dumps
// TODO: add command for clearing the socket buffers?

/*
 * Anti Debug:

when a debugger is attached on boot, KPP is disabled -> find a way to detect if KPP is disabled????

NtQuerySystemInformation SystemCodeIntegrityInformation SystemKernelDebuggerInformation
PsIsProcessBeingDebugged
PsIntegrityCheckEnabled

// Debug prevention methods:
Call KdDisableDebugger on driver entry,
  set KdBlockEnable to 1 (call KdChangeOption?)
 */

constexpr std::size_t base64Length(const std::size_t inputSize, const bool padding = true) noexcept {
	return (inputSize / 3ull) * 4ull + (((inputSize - (inputSize / 3ull) * 3ull) | ((inputSize - (inputSize / 3ull) * 3ull) >> 1)) & 1ull) * (4ull - (~((((padding ? 1ull : 3ull) & 2ull) >> 1) - 1ull) & (3ull - (inputSize - (inputSize / 3ull) * 3ull)))) + 1ull;
}

void unload(PDRIVER_OBJECT driverObject);
// TODO: in release mode the driver shouldn't be loadable by the nt loader


NTSTATUS DriverEntry([[maybe_unused]] const PDRIVER_OBJECT  driverObject,
					 [[maybe_unused]] const PUNICODE_STRING registryPath) {
	[](const wchar_t*) {

	}(L"epic");


	VM_MAXIMUM_BEGIN
	if constexpr (Configuration::unload)
		if (driverObject) driverObject->DriverUnload = &unload;
	
	//_disable();

	// Initialize the global structures & pointers
	using namespace KM::Miscellaneous;
	// TODO: error handling
	if (!Globals::initialize()) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Failed to initialize globals."));
		unload(driverObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	if constexpr (Configuration::print) {
		// Fetch the hardware id
		const auto smbiosHash = (*Globals::Hardware::hardwareId)->genericSmbios;
		const auto efiHash    = (*Globals::Hardware::hardwareId)->efi;
		
		char smbiosBuffer[base64Length(sizeof(smbiosHash))] {};
		char efiBuffer   [base64Length(sizeof(efiHash))] {};
		
		unsigned long smbiosBufferSize {sizeof(smbiosBuffer)};
		unsigned long efiBufferSize    {sizeof(efiBuffer)};
		libtomcrypt::base64_encode(smbiosHash.data(), static_cast<unsigned long>(smbiosHash.max_size()), smbiosBuffer, &smbiosBufferSize);
		libtomcrypt::base64_encode(efiHash.data(),    static_cast<unsigned long>(efiHash.max_size()),    efiBuffer,    &efiBufferSize);
		
		print(xorstr_("smbios hwid: %s"), smbiosBuffer);
		print(xorstr_("efi    hwid: %s"), efiBuffer);
	}

	//KM::Spoofer::hook();

	//KdDisableDebugger();

	// Hook NtSetCompositionSurfaceAnalogExclusive
	/*if (!KM::SystemCalls::hook()) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Failed to hook NtSetCompositionSurfaceAnalogExclusive."));
		return STATUS_FAILED_DRIVER_ENTRY;
	}*/
		
	if constexpr (Configuration::profiler)
		print(xorstr_("[+] Driver loaded successfully."));

	if (reinterpret_cast<std::uintptr_t>(Globals::NT::ObReferenceObjectByName) == 0x1337)
		KeBugCheckEx(0x1337, 0, 0, 0, 0);
	
	// TODO: download pdbs for offsets - this will force an internet connection
	constexpr auto enableConnection {false};
	if constexpr (enableConnection) {
		// Connect to Tor:
		/*const NetIo::Socket socket {AF_INET, SOCK_STREAM, IPPROTO_TCP};
		if (const auto status = socket.connect(xorstr_("127.0.0.1"), 9050);
			status == STATUS_SUCCESS) {
			do {
				{
					constexpr char data[] {0x05, 0x01, 0x00};
					if (const auto [status, bytesSent] = socket.send(data, sizeof(data)); status != STATUS_SUCCESS) break;

					char response[2] {};
					if (const auto [status, bytesReceived] = socket.receive(response, sizeof(response)); status != STATUS_SUCCESS || response[1] != 0x00) break;
				}

				{
					constexpr std::string_view host {"gamerhtc43jp76xqnpezkgvtga4ly4u5dwx3izsvpfpfgjojglpmkpid.onion"};
					constexpr char data[] {0x05, 0x01, 0x00, 0x03};
					std::array<char, sizeof(data) + 1 + host.length() + 2> request {};
					std::memcpy(request.data(), data, sizeof(data));
					request[sizeof(data)] = host.length();
					std::memcpy(request.data() + sizeof(data) + 1, host.data(), host.length());

					constexpr char port[] {0x00, 0x50}; // 80
					std::memcpy(request.data() + sizeof(data) + 1 + host.length(), port, sizeof(port));
					if (const auto [status, bytesSent] = socket.send(request.data(), request.size()); status != STATUS_SUCCESS) break;

					char response[10] {};
					if (const auto [status, bytesReceived] = socket.receive(response, sizeof(response)); status != STATUS_SUCCESS || response[1] != 0x00) break;
				}

				constexpr std::string_view message {
					"GET / HTTP/1.1\r\n"
					"Host: gamerhtc43jp76xqnpezkgvtga4ly4u5dwx3izsvpfpfgjojglpmkpid.onion\r\n"
					"Connection: close\r\n"
					"\r\n"};
				const auto bytesSent = socket.send(message); print("bytes sent: %i", bytesSent);
				const auto dataReceived = socket.receive(); print("received: %i", dataReceived.size());

				print("Response: %.*s", dataReceived.size(), dataReceived.data());
			} while (false);
		}*/
		//} else
		//	print("connect: 0x%X", status);
	}
	
	//_enable();
	VM_MAXIMUM_END
	return STATUS_SUCCESS;
}

void unload([[maybe_unused]] PDRIVER_OBJECT driverObject) {
	if constexpr (Configuration::unload) {
		VM_MINIMUM_BEGIN
		if constexpr (Configuration::profiler)
			print(xorstr_("[+] Driver unloaded."));

		// Unregister libtomcrypt and libtommath
		tls::client::unregisterCiphers();
		tls::client::unregisterHashes();
		tls::client::unregisterPrngs();

		using namespace KM::Miscellaneous;
		Globals::Syscalls::dxgkrnlTable.reset();
		KM::Spoofer::restore();
		
		namespace wsk = NetIo::WinsockKernel;
		Globals::NetIo::sockets.reset();
		Globals::NetIo::mutex.reset();
		Globals::Symbols::cleanup();
		wsk::cleanup();
		VM_MINIMUM_END
	}
}
