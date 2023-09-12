#include "Context.hpp"

#include <intrin.h>

#include "../../Globals.hpp"

using namespace KM::Miscellaneous::NetIo::WinsockKernel;

void detail::irpDeleter(const PIRP irp) noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Globals::NT;
	if (irp) nt::IoFreeIrp(irp);
	VM_SIZE_SPEED_END
	__nop(); // Prevent tail call optimizations
}

NTSTATUS detail::irpCompletionRoutine(PDEVICE_OBJECT, PIRP, const PVOID event) noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Globals::NT;
	
	nt::KeSetEvent(static_cast<PKEVENT>(event), IO_NO_INCREMENT, false);
	const auto volatile status = STATUS_MORE_PROCESSING_REQUIRED;
	VM_SIZE_SPEED_END
	return status;
}

Context::Context(const std::uint8_t stackSize) noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Globals::NT;
	this->event = std::make_unique<KEVENT>();
	nt::KeInitializeEvent(this->event.get(), SynchronizationEvent, false);

	this->irp.reset(nt::IoAllocateIrp(stackSize, false));
	IoSetCompletionRoutine(this->irp.get(), &detail::irpCompletionRoutine, this->event.get(), true, true, true);
	VM_SIZE_SPEED_END
}

void Context::reuse() const noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Globals::NT;
	nt::KeResetEvent(this->event.get());
	
	nt::IoReuseIrp(this->irp.get(), STATUS_UNSUCCESSFUL);
	IoSetCompletionRoutine(this->irp.get(), &detail::irpCompletionRoutine, this->event.get(), true, true, true);
	VM_SIZE_SPEED_END
	__nop(); // Prevent tail call optimizations
}

void Context::timeout(const std::int64_t value) noexcept {
	MUTATE_BEGIN
	this->_timeout = value;
	MUTATE_END
	__nop(); // Prevent tail call optimizations
}

NTSTATUS Context::wait() const noexcept {
	VM_SIZE_SPEED_BEGIN
	namespace nt = Globals::NT;

	LARGE_INTEGER timeout {.QuadPart = static_cast<LONGLONG>(this->_timeout)};
	if (const auto waitStatus = nt::KeWaitForSingleObject(this->event.get(), Executive, KernelMode, false, &timeout);
		waitStatus == STATUS_TIMEOUT) {
		nt::IoCancelIrp(this->irp.get());
		nt::KeWaitForSingleObject(this->event.get(), Executive, KernelMode, false, nullptr);
		
		return STATUS_TIMEOUT;
	}
	
	const auto volatile status = this->irp->IoStatus.Status;
	VM_SIZE_SPEED_END
	return status;
}

Context::operator bool() const noexcept {
	MUTATE_BEGIN
	const auto volatile result = this->event && this->irp;
	MUTATE_END
	return result;
}
