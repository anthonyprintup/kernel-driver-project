#include "Hook.hpp"

#include <intrin.h>

// ReSharper disable once CppUnusedIncludeDirective
#include <Framework/Utilities/Strings/Fnv1A.hpp>

#include "../Configuration.hpp"
#include "../Miscellaneous/Globals.hpp"
#include "../Utilities/NT/NT.hpp"
#include "../Spoofer/Disk.hpp"

#pragma region Requests
#include <common/Requests/Id.hpp>
#include <common/Requests/Impl/Process.hpp>
#include <common/Requests/Impl/Read.hpp>
#include <common/Requests/Impl/Write.hpp>
#include <common/Requests/Impl/Map.hpp>
#include <common/Requests/Impl/Unmap.hpp>
#include <common/Requests/Impl/Memory Protection.hpp>
#include <common/Requests/Impl/Allocate.hpp>
#include <common/Requests/Impl/Free.hpp>
#include <common/Requests/Impl/Apc.hpp>
#include <common/Requests/Impl/Spoofer.hpp>
#pragma endregion

extern "C" void returnStatus();
NTSTATUS handler(std::uintptr_t buffer);
NTSTATUS ntSetCompositionSurfaceAnalogExclusiveHooked(const std::uint64_t first, const std::uint64_t second) {
	using CallbackType = std::decay_t<decltype(ntSetCompositionSurfaceAnalogExclusiveHooked)>;
	using namespace KM::Miscellaneous::Globals::Syscalls;
	VM_MINIMUM_BEGIN
	const static auto original = dxgkrnlTable->original<CallbackType>(functionIndex);
	const auto magicImmediateCheck = second == GlobalConfiguration::magicImmediate;
	VM_MINIMUM_END

	VM_SIZE_SPEED_BEGIN
	if (!magicImmediateCheck)
		return original(first, second);
	VM_SIZE_SPEED_END

	VM_MAXIMUM_BEGIN
	// Handle the request
	_disable();
	const auto status = handler(first);
	_enable();

	// Set the return address, so we can bypass the ACCESS_DENIED return status
	*static_cast<std::uintptr_t*>(_AddressOfReturnAddress()) = reinterpret_cast<std::uintptr_t>(&returnStatus);
	VM_MAXIMUM_END
	return status;
}

bool KM::SystemCalls::hook() noexcept {
	VM_MAXIMUM_BEGIN
	auto status {false};

	using namespace Miscellaneous::Globals::Syscalls;
	dxgkrnlTable->hook(&ntSetCompositionSurfaceAnalogExclusiveHooked, functionIndex);
	dxgkrnlTable->replace();

	status = true;
	VM_MAXIMUM_END
	return status;
}

NTSTATUS handler(const std::uintptr_t buffer) {
	VM_MAXIMUM_BEGIN
	using namespace Requests;
	using namespace KM::Utilities::NT;
	namespace nt = KM::Miscellaneous::Globals::NT;
	if (!User::validMemory(nt::PsGetCurrentProcess(), buffer))
		return STATUS_INVALID_ADDRESS;
	
	const auto &requestId = *reinterpret_cast<Id*>(buffer);
	if (requestId == Id::PROCESS) {
		const auto request = reinterpret_cast<Impl::Process*>(buffer);
		const auto process = Kernel::process(request->hash);
		if (!process.object || User::terminating(process.object))
			return STATUS_NOT_FOUND;

		request->processId = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(nt::PsGetProcessId(process.object)));
		request->base      = reinterpret_cast<std::uintptr_t>(nt::PsGetProcessSectionBaseAddress(process.object));
		request->peb       = reinterpret_cast<std::uintptr_t>(nt::PsGetProcessPeb(process.object));
		return STATUS_SUCCESS;
	}
	if (requestId == Id::READ) {
		const auto request = reinterpret_cast<Impl::Read*>(buffer);
		const auto process = Kernel::process(request->processId);
		if (!process || User::terminating(process.object))
			return STATUS_NOT_FOUND;

		return User::copyMemory(process.object, request->virtualAddress, nt::PsGetCurrentProcess(), request->buffer, request->size);
	}
	if (requestId == Id::WRITE) {
		const auto request = reinterpret_cast<Impl::Write*>(buffer);
		const auto process = Kernel::process(request->processId);
		if (!process || User::terminating(process.object))
			return STATUS_NOT_FOUND;

		return User::copyMemory(nt::PsGetCurrentProcess(), request->buffer, process.object,
								request->virtualAddress, request->size, request->ignorePageProtection);
	}
	if (requestId == Id::MAP) {
		
	}
	if (requestId == Id::UNMAP) {
		
	}
	if (requestId == Id::MEMORY_PROTECTION) {
		const auto request = reinterpret_cast<Impl::MemoryProtection*>(buffer);
		const auto process = Kernel::process(request->processId);
		if (!process || User::terminating(process.object))
			return STATUS_NOT_FOUND;

		if (!User::validMemory(process.object, request->virtualAddress, request->size))
			return STATUS_INVALID_ADDRESS;
		return Kernel::protectMemory(process.object, request->virtualAddress, request->size, request->newProtection, request->oldProtection);
	}
	if (requestId == Id::ALLOCATE) {
		const auto request = reinterpret_cast<Impl::Allocate*>(buffer);
		const auto process = Kernel::process(request->processId);
		if (!process || User::terminating(process.object))
			return STATUS_NOT_FOUND;

		const auto [status, virtualAddress] = User::allocateMemory(process.object, request->zeroBits, request->size, request->type, request->protection);
		request->virtualAddress = virtualAddress;

		return status;
	}
	if (requestId == Id::FREE) {
		const auto request = reinterpret_cast<Impl::Free*>(buffer);
		const auto process = Kernel::process(request->processId);
		if (!process || User::terminating(process.object))
			return STATUS_NOT_FOUND;

		return User::freeMemory(process.object, request->virtualAddress, request->size, request->type);
	}
	if (requestId == Id::APC) {
		const auto request = reinterpret_cast<Impl::Apc*>(buffer);
		const auto process = Kernel::process(request->processId);
		if (!process || User::terminating(process.object))
			return STATUS_NOT_FOUND;

		PETHREAD target {};
		Kernel::iterateThreads([&](const PEPROCESS owner, const PETHREAD thread) {
			VM_MEDIUM_BEGIN
			auto continueSearching {true};
			if (nt::PsIsThreadTerminating(thread))
				return continueSearching;
			
			const auto ownerProcessId = static_cast<std::uint32_t>(reinterpret_cast<std::uint64_t>(nt::PsGetProcessId(owner)));
			if (ownerProcessId != request->processId)
				return continueSearching;

			KAPC_STATE_T state {};
			nt::KeStackAttachProcess(owner, &state);
			const auto threadEnvironmentBlock = nt::PsGetThreadTeb(thread);
			if (threadEnvironmentBlock->ThreadLocalStoragePointer && !threadEnvironmentBlock->Win32ThreadInfo && threadEnvironmentBlock->ActivationContextStackPointer) {
				target = thread;
				continueSearching = false;
			}
			nt::KeUnstackDetachProcess(&state);
			VM_MEDIUM_END
			return continueSearching;
		});
		if (!target)
			return STATUS_THREAD_NOT_IN_PROCESS;

		const auto queueingCurrentThread = target == nt::PsGetCurrentThread();
		if (queueingCurrentThread)
			nt::KeEnterGuardedRegion();
		const auto status = User::queueApc(target, request->virtualAddress, request->arguments, request->force) ? STATUS_SUCCESS : STATUS_USER_APC;
		if (queueingCurrentThread)
			nt::KeLeaveGuardedRegion();
		return status;
	}
	if (requestId == Id::SPOOFER) {
		const auto request = reinterpret_cast<Impl::Spoofer*>(buffer);
		if (request->action == Impl::SpooferAction::ACTIVATE && !KM::Miscellaneous::Globals::Drivers::disk)
			KM::Spoofer::hook();
		else if (request->action == Impl::SpooferAction::DEACTIVATE)
			KM::Spoofer::restore();
		else
			return STATUS_NOT_IMPLEMENTED;

		return STATUS_SUCCESS;
	}

	const auto status = STATUS_NOT_IMPLEMENTED;
	VM_MAXIMUM_END
	return status;
}
