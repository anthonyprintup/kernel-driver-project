#include "NT.hpp"

#include <intrin.h>

#include "../../Configuration.hpp"
#include "../../Miscellaneous/Globals.hpp"

using namespace KM::Utilities::NT;

std::optional<MemoryBasicInformationType> User::memoryInformation(const PEPROCESS process, const std::uintptr_t virtualAddress) {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	KAPC_STATE_T state {};
	nt::KeStackAttachProcess(process, &state);
	constexpr auto memoryBasicInformation = 0x0;
	MemoryBasicInformationType memoryInformation {};
	const auto status = nt::ZwQueryVirtualMemory(
		NtCurrentProcess(), reinterpret_cast<PVOID>(virtualAddress), memoryBasicInformation, &memoryInformation, sizeof(memoryInformation), nullptr);
	nt::KeUnstackDetachProcess(&state);
	
	if (status != STATUS_SUCCESS)
		return std::nullopt;
	VM_MEDIUM_END
	return memoryInformation;
}

bool User::validMemory(const MemoryBasicInformationType &memoryInformation) noexcept {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	if (!(memoryInformation.State & MEM_COMMIT))
		return false;
	
	const auto result = true;
	VM_MEDIUM_END
	return result;
}
bool User::validMemory(const PEPROCESS process, const std::uintptr_t virtualAddress, const std::size_t size) noexcept {
	VM_MEDIUM_BEGIN
	if (!virtualAddress) return false;
	const auto memoryInformation = User::memoryInformation(process, virtualAddress);
	if (!memoryInformation) return false;
	// TODO: this is only valid for Win 10 Pro/Education, refer to https://docs.microsoft.com/en-us/windows/win32/memory/memory-limits-for-windows-releases#physical-memory-limits-windows-10
	//if (virtualAddress + size > 0x7FFFFFFFFFFF)
	//	return false;
	if (reinterpret_cast<std::uintptr_t>(memoryInformation->BaseAddress) + memoryInformation->RegionSize < virtualAddress + size)
		return false;
	if (!(memoryInformation->State & MEM_COMMIT))
		return false;
	
	volatile const auto result = true;
	VM_MEDIUM_END
	return result;
}

NTSTATUS User::copyMemory(const PEPROCESS from, const std::uintptr_t fromVirtualAddress, const PEPROCESS to, const std::uintptr_t toVirtualAddress,
						  const std::size_t size, const bool ignorePageProtection) noexcept {
	VM_MEDIUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	
	SIZE_T bytesCopied {};
	auto status = nt::MmCopyVirtualMemory(from, reinterpret_cast<PVOID>(fromVirtualAddress), to, reinterpret_cast<PVOID>(toVirtualAddress), size, UserMode, &bytesCopied);
	if (ignorePageProtection && status == STATUS_PARTIAL_COPY) {
		const auto fromMemoryInformation = User::memoryInformation(from, fromVirtualAddress);
		const auto toMemoryInformation = User::memoryInformation(to, toVirtualAddress);
		if (!fromMemoryInformation || !toMemoryInformation ||
			!User::validMemory(*fromMemoryInformation) || !User::validMemory(*toMemoryInformation))
			return status;
		if (toMemoryInformation->Protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY | PAGE_READWRITE))
			return status; // Some other error occured.

		const auto mdl {nt::IoAllocateMdl(reinterpret_cast<PVOID>(toVirtualAddress), static_cast<ULONG>(size), false, false, nullptr)};
		if (!mdl) return status;

		nt::MmProbeAndLockProcessPages(mdl, to, KernelMode, IoReadAccess);
		const auto mappedAddress = nt::MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, false, HighPagePriority);
		if (!mappedAddress) {
			nt::MmUnlockPages(mdl);
			nt::IoFreeMdl(mdl);
			return STATUS_USER_MAPPED_FILE;
		}

		status = nt::MmCopyVirtualMemory(from, reinterpret_cast<PVOID>(fromVirtualAddress), to, mappedAddress, size, KernelMode, &bytesCopied);
		nt::MmUnlockPages(mdl);
		nt::IoFreeMdl(mdl);
	}
	VM_MEDIUM_END
	return status;
}
std::pair<NTSTATUS, std::uintptr_t>
User::allocateMemory(const PEPROCESS process, const std::uint64_t zeroBits, std::size_t size, const std::uint32_t type, const std::uint32_t protection) noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Miscellaneous::Globals::NT;

	KAPC_STATE_T state {};
	nt::KeStackAttachProcess(process, &state);

	PVOID virtualAddress {};
	const auto status = nt::ZwAllocateVirtualMemory(NtCurrentProcess(), &virtualAddress, zeroBits, &size, type, protection);
	nt::KeUnstackDetachProcess(&state);
	VM_SIZE_SPEED_END

	return {status, reinterpret_cast<std::uintptr_t>(virtualAddress)};
}
NTSTATUS User::freeMemory(const PEPROCESS process, std::uintptr_t virtualAddress, std::size_t size, const std::uint32_t type) noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	
	KAPC_STATE_T state {};
	nt::KeStackAttachProcess(process, &state);
	const auto status = nt::ZwFreeVirtualMemory(NtCurrentProcess(), reinterpret_cast<PVOID*>(&virtualAddress), &size, type);
	nt::KeUnstackDetachProcess(&state);
	VM_SIZE_SPEED_END

	return status;
}

bool User::queueApc(const PETHREAD thread, const std::uintptr_t virtualAddress, const std::array<std::uint64_t, 3> arguments, const bool force) noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	auto inserted {false};

	const auto userModeApcRoutine = static_cast<PKKERNEL_ROUTINE>([](const PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*) {
		VM_MINIMUM_BEGIN
		delete apc;
		VM_MINIMUM_END
		__nop(); // Prevent tail call optimizations
	});
	
	const auto userModeApc {new KAPC {}};
	nt::KeInitializeApc(userModeApc, thread, OriginalApcEnvironment,
						userModeApcRoutine, nullptr, reinterpret_cast<PKNORMAL_ROUTINE>(virtualAddress),
						UserMode, reinterpret_cast<PVOID>(arguments[0]));
	if (!nt::KeInsertQueueApc(userModeApc, reinterpret_cast<PVOID>(arguments[1]), reinterpret_cast<PVOID>(arguments[2]), IO_NO_INCREMENT)) {
		delete userModeApc;
		return inserted;
	}

	inserted = true;
	if (force) {
		const auto kernelModeApcRoutine = static_cast<PKKERNEL_ROUTINE>([](const PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*) {
			VM_MINIMUM_BEGIN
			nt::KeTestAlertThread(UserMode);
			delete apc;
			VM_MINIMUM_END
			__nop(); // Prevent tail call optimizations
		});
		
		const auto kernelModeApc {new KAPC {}};
		nt::KeInitializeApc(kernelModeApc, thread, OriginalApcEnvironment,
							kernelModeApcRoutine, nullptr, nullptr,
							KernelMode, nullptr);
		if (!nt::KeInsertQueueApc(kernelModeApc, nullptr, nullptr, IO_NO_INCREMENT))
			delete kernelModeApc;
	}
	VM_SIZE_SPEED_END
	return inserted;
}

bool User::terminating(const PEPROCESS process) noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	
	LARGE_INTEGER time {};
	const auto terminating = nt::KeWaitForSingleObject(process, Executive, KernelMode, false, &time) == STATUS_WAIT_0;
	VM_SIZE_SPEED_END

	return terminating;
}

void User::iterateEnvironmentVariables(const PEPROCESS process, std::function<bool(std::wstring_view, std::wstring_view)> &&visitor) {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	
	const auto peb = reinterpret_cast<std::uintptr_t>(nt::PsGetProcessPeb(process));
	if (!peb || !validMemory(process, peb))
		return;

	// Read the user process parameters
	RtlUserProcessParameters64 userProcessParameters {};
	{
		constexpr std::size_t offsetToProcessParameters {0x20};
		KAPC_STATE_T state {};
		nt::KeStackAttachProcess(process, &state);
		const auto processParameters = *reinterpret_cast<RtlUserProcessParameters64**>(peb + offsetToProcessParameters);
		const auto processParametersValid = processParameters && validMemory(process, reinterpret_cast<std::uintptr_t>(processParameters), offsetof(RtlUserProcessParameters64, EnvironmentSize) + sizeof(RtlUserProcessParameters64::EnvironmentSize));
		if (processParametersValid)
			std::memcpy(&userProcessParameters, processParameters, offsetof(RtlUserProcessParameters64, EnvironmentSize) + sizeof(RtlUserProcessParameters64::EnvironmentSize));
		nt::KeUnstackDetachProcess(&state);
		if (!processParametersValid)
			return;
	}
	
	const auto environment = userProcessParameters.Environment;
	if (!environment || !validMemory(process, reinterpret_cast<std::uintptr_t>(environment)))
		return;

	{
		const auto environmentSize = userProcessParameters.EnvironmentSize;

		// Scoped to guarantee the destructor is called before the end of the VM macro
		const auto environmentCopy = std::make_unique<std::uint8_t[]>(environmentSize);
		// Copy the environment variables
		{
			KAPC_STATE_T state {};
			nt::KeStackAttachProcess(process, &state);
			std::memcpy(environmentCopy.get(), environment, environmentSize);
			nt::KeUnstackDetachProcess(&state);
		}
		std::wstring_view variables {reinterpret_cast<const wchar_t*>(environmentCopy.get()), environmentSize};
		for (std::size_t offset {}, end = variables.find(L'\0');
			offset < environmentSize / sizeof(wchar_t) && end != std::wstring_view::npos;
			offset = end + 1, end = variables.find(L'\0', offset)) {
			const auto variable = variables.substr(offset, end - offset);
			if (variable.empty())
				break;

			const auto delimiterPosition = variable.find(L'=');
			if (delimiterPosition == std::wstring_view::npos)
				break; // invalid

			const auto name = variable.substr(0, delimiterPosition);
			if (name.empty()) continue;
			const auto value = variable.substr(delimiterPosition + 1, variable.size() - delimiterPosition);

			// Call the visitor with the entry
			if (!visitor(name, value)) break;
		}
	}
	VM_SIZE_SPEED_END
}
