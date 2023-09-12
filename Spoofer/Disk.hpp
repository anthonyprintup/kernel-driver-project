#pragma once

#include <list>

#include "../Utilities/NT/NT.hpp"
#include "../Utilities/Mutex.hpp"

namespace KM::Spoofer {
	namespace detail {
		using CompletionRoutineType = PIO_COMPLETION_ROUTINE;
		using PredicateType         = bool(*)(PDEVICE_OBJECT, PIRP);
		
		struct CallbackEntry {
			std::uint32_t         ioControlCode {};
			CompletionRoutineType completionRoutine {};
			PredicateType         predicate {};

			CallbackEntry(const std::uint32_t ioControlCode, const CompletionRoutineType completionRoutine, const PredicateType predicate) noexcept:
				ioControlCode {ioControlCode}, completionRoutine {completionRoutine}, predicate {predicate} {}
		};
		
		struct DeviceEntry {
			PDEVICE_OBJECT    object {};
			PVOID             extension {};
			PDRIVER_DISPATCH *dispatchTable {};
			PDRIVER_DISPATCH  deviceControlRoutine {};

			DeviceEntry(const PDEVICE_OBJECT object, const PVOID extension, PDRIVER_DISPATCH *dispatchTable, const PDRIVER_DISPATCH deviceControlRoutine) noexcept:
				object {object}, extension {extension}, dispatchTable {dispatchTable}, deviceControlRoutine {deviceControlRoutine} {}
			
			std::list<CallbackEntry> callbacks {};
		};

		struct CompletionRoutineContext {
			PVOID                  context  {};
			PIO_COMPLETION_ROUTINE original {};
			PIO_COMPLETION_ROUTINE callback {};
			bool onCancel {}, onSuccess {}, onError {};
		};
	}
	
	struct Disk: Utilities::NT::Kernel::Driver {
		Disk() noexcept;
		~Disk() noexcept;

		void hook(std::uint32_t ioControlCode, detail::CompletionRoutineType completionRoutine, detail::PredicateType predicate = [](PDEVICE_OBJECT, PIRP) { return true; }) noexcept;
		void restore() noexcept;

		Utilities::Mutex mutex {};
		std::list<detail::DeviceEntry> devices {};
	};

	void hook();
	void restore();
}
