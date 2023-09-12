#include "NT.hpp"

#include <Framework/Utilities/Strings/XorStr.hpp>
#include <Framework/Utilities/Strings/Fnv1A.hpp>

#include "../../Configuration.hpp"
#include "../../Miscellaneous/Globals.hpp"

using namespace KM::Utilities::NT;

std::pair<std::uintptr_t, std::size_t> Kernel::module(const Hash hash) noexcept {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;

	std::uint32_t size {};
	constexpr auto systemModuleInformation = 0xB;
	if (const auto status = nt::ZwQuerySystemInformation(systemModuleInformation, nullptr, size, reinterpret_cast<PULONG>(&size));
		status != STATUS_INFO_LENGTH_MISMATCH)
		return {};

	size += 0x1000; // Between the two ZwQuerySystemInformation calls there's a possibility for a race condition to occur
	const std::unique_ptr<SYSTEM_MODULE_INFORMATION> moduleListHeader {reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(new std::uint8_t[size])};
	if (const auto status = nt::ZwQuerySystemInformation(systemModuleInformation, moduleListHeader.get(), size, reinterpret_cast<PULONG>(&size));
		status != STATUS_SUCCESS)
		return {};

	auto currentModule = moduleListHeader->Module;
	for (std::size_t i {}; i < moduleListHeader->Count; ++i, currentModule++) {
		const Hash moduleNameHash {reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName)};
		if (moduleNameHash == hash) {
			const auto moduleBase {reinterpret_cast<uintptr_t>(currentModule->ImageBase)};
			const auto moduleSize {currentModule->ImageSize};
			return {moduleBase, moduleSize};
		}
	}
	VM_MEDIUM_END
	
	return {};
}

Kernel::Referenced<PEPROCESS> Kernel::process(const Hash hash) noexcept {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	PEPROCESS process {};
	
	std::uint32_t size {};
	constexpr auto systemProcessInformation = 0x5;
	if (const auto status = nt::ZwQuerySystemInformation(systemProcessInformation, nullptr, size, reinterpret_cast<PULONG>(&size));
		status != STATUS_INFO_LENGTH_MISMATCH)
		return {};

	size += 0x1000; // Between the two ZwQuerySystemInformation calls there's a possibility for a race condition to occur
	const auto processArray = std::make_unique<std::uint8_t[]>(size);
	if (const auto status = nt::ZwQuerySystemInformation(systemProcessInformation, processArray.get(), size, reinterpret_cast<PULONG>(&size));
		status != STATUS_SUCCESS)
		return {};

	for (auto processInformation {reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processArray.get())};;
		 processInformation = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<std::uintptr_t>(processInformation) + processInformation->NextEntryOffset)) {
		const std::wstring_view imageName {processInformation->ImageName.Buffer, static_cast<std::wstring_view::size_type>(processInformation->ImageName.Length) / 2};
		if (Hash {imageName} == hash)
			if (const auto status = nt::PsLookupProcessByProcessId(processInformation->UniqueProcessId, &process);
				status == STATUS_SUCCESS)
				break;
		
		if (!processInformation->NextEntryOffset)
			break;
	}
	VM_MEDIUM_END

	return {process};
}
Kernel::Referenced<PEPROCESS> Kernel::process(std::uint32_t processId) noexcept {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	if (processId == static_cast<std::uint32_t>(-1))
		processId = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(nt::PsGetCurrentProcessId()));
	
	PEPROCESS process {};
	if (const auto status = nt::PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(processId), &process);
		status == STATUS_SUCCESS)
		return {process};
	process = nullptr;
	VM_MEDIUM_END
	
	return {process};
}

NTSTATUS Kernel::protectMemory(const PEPROCESS process, std::uintptr_t virtualAddress, std::size_t size,
							   const std::uint32_t newProtection, std::uint32_t &oldProtection) noexcept {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;

	KAPC_STATE_T state {};
	nt::KeStackAttachProcess(process, &state);

	ULONG protection {};
	const auto status = nt::ZwProtectVirtualMemory(
		NtCurrentProcess(), reinterpret_cast<PVOID*>(&virtualAddress), &size,
		newProtection, &protection);
	nt::KeUnstackDetachProcess(&state);
	oldProtection = protection;
	VM_MEDIUM_END

	return status;
}

void Kernel::iterateThreads(std::function<bool(PEPROCESS, PETHREAD)> &&callback) {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	
	std::uint32_t size {};
	constexpr auto systemProcessInformation = 0x5;
	if (const auto status = nt::ZwQuerySystemInformation(systemProcessInformation, nullptr, size, reinterpret_cast<PULONG>(&size));
		status != STATUS_INFO_LENGTH_MISMATCH)
		return;

	size += 0x1000; // Between the two ZwQuerySystemInformation calls there's a possibility for a race condition to occur
	const auto processArray = std::make_unique<std::uint8_t[]>(size);
	if (const auto status = nt::ZwQuerySystemInformation(systemProcessInformation, processArray.get(), size, reinterpret_cast<PULONG>(&size));
		status != STATUS_SUCCESS)
		return;

	for (auto processInformation {reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processArray.get())};;
		 processInformation = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<std::uintptr_t>(processInformation) + processInformation->NextEntryOffset)) {
		const auto finished = processInformation->NextEntryOffset == 0;

		Referenced<PEPROCESS> process {};
		if (nt::PsLookupProcessByProcessId(processInformation->UniqueProcessId, &process.object) == STATUS_SUCCESS)
			for (std::size_t i {}; i < processInformation->NumberOfThreads; ++i) {
				Referenced<PETHREAD> thread {};
				if (nt::PsLookupThreadByThreadId(processInformation->Threads[i].ClientId.UniqueThread, &thread.object) != STATUS_SUCCESS)
					continue;

				if (!callback(process.object, thread.object))
					return;
			}
		
		if (finished) break;
	}
	VM_MEDIUM_END
}

std::pair<NTSTATUS, std::vector<std::uint8_t>> Kernel::readFile(const std::wstring_view path) {
	VM_MINIMUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return {STATUS_INVALID_DEVICE_STATE, {}};

	UNICODE_STRING unicodeFilePath {
		.Length = static_cast<USHORT>(path.length()) * sizeof(wchar_t),
		.MaximumLength = static_cast<USHORT>(path.length()) * sizeof(wchar_t),
		.Buffer = const_cast<PWCH>(path.data())};
	OBJECT_ATTRIBUTES objectAttributes {};
	InitializeObjectAttributes(&objectAttributes, &unicodeFilePath, OBJ_KERNEL_HANDLE, nullptr, nullptr)

	// Open a handle to the file
	HANDLE fileHandle {};
	IO_STATUS_BLOCK ioStatusBlock {};
	if (const auto status = nt::ZwCreateFile(
		&fileHandle, FILE_GENERIC_READ, &objectAttributes, &ioStatusBlock, nullptr,
		FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
		!NT_SUCCESS(status))
		return {status, {}};

	// Determine the file size
	FILE_STANDARD_INFORMATION fileInformation {};
	if (const auto status = nt::ZwQueryInformationFile(
		fileHandle, &ioStatusBlock, &fileInformation,
		sizeof(fileInformation), FileStandardInformation);
		!NT_SUCCESS(status)) {
		nt::ZwClose(fileHandle);
		return {status, {}};
	}

	// Allocate the buffer
	std::vector<std::uint8_t> buffer {};
	buffer.resize(fileInformation.EndOfFile.QuadPart);

	// Read the file
	if (const auto status = nt::ZwReadFile(
		fileHandle, nullptr, nullptr, nullptr, &ioStatusBlock,
		buffer.data(), static_cast<ULONG>(buffer.size()), nullptr, nullptr);
		!NT_SUCCESS(status)) {
		nt::ZwClose(fileHandle);
		return {status, {}};
	}

	nt::ZwClose(fileHandle);
	VM_MINIMUM_END
	return {STATUS_SUCCESS, buffer};
}

NTSTATUS Kernel::writeFile(const std::wstring_view path, const std::span<const std::uint8_t> buffer, const bool append) {
	VM_MINIMUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	UNICODE_STRING unicodeFilePath {
		.Length = static_cast<USHORT>(path.length()) * sizeof(wchar_t),
		.MaximumLength = static_cast<USHORT>(path.length()) * sizeof(wchar_t),
		.Buffer = const_cast<PWCH>(path.data())};
	OBJECT_ATTRIBUTES objectAttributes {};
	InitializeObjectAttributes(&objectAttributes, &unicodeFilePath, OBJ_KERNEL_HANDLE, nullptr, nullptr)

	// Open a handle to the file
	HANDLE fileHandle {};
	IO_STATUS_BLOCK ioStatusBlock {};
	if (const auto status = nt::ZwCreateFile(
		&fileHandle, FILE_GENERIC_WRITE, &objectAttributes, &ioStatusBlock, nullptr,
		FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
		!NT_SUCCESS(status))
		return status;

	// Write to the file
	using PointerType = std::remove_const_t<decltype(buffer)::element_type>*;
	LARGE_INTEGER byteOffset {};
	byteOffset.LowPart  = FILE_WRITE_TO_END_OF_FILE;
	byteOffset.HighPart = -1;

	if (const auto status = nt::ZwWriteFile(
		fileHandle, nullptr, nullptr, nullptr, &ioStatusBlock,
		const_cast<PointerType>(buffer.data()), static_cast<ULONG>(buffer.size()), append ? &byteOffset : nullptr, nullptr);
		!NT_SUCCESS(status)) {
		nt::ZwClose(fileHandle);
		return status;
	}

	nt::ZwClose(fileHandle);
	VM_MINIMUM_END
	return {};
}

// Random Number Generator intended to be used by libraries such as libtomcrypt
extern "C" bool generateRandomData(void *buffer, const std::size_t size) {
	VM_SIZE_SPEED_BEGIN
	namespace nt = KM::Miscellaneous::Globals::NT;

	const auto status = nt::BCryptGenRandom(nullptr, static_cast<PUCHAR>(buffer), static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	VM_SIZE_SPEED_END
	return status == STATUS_SUCCESS;
}
