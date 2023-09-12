#include "Mutex.hpp"

#include <intrin.h>

#include "../Miscellaneous/Globals.hpp"
namespace nt = KM::Miscellaneous::Globals::NT;

using namespace KM::Utilities;

Mutex::Mutex() noexcept {
	VM_MEDIUM_BEGIN
	// Inlined ExInitializeFastMutex because it calls KeInitializeEvent (import)
	WriteRaw(&this->mutex.Count, FM_LOCK_BIT);
	this->mutex.Owner = nullptr;
	this->mutex.Contention = 0;
	nt::KeInitializeEvent(&this->mutex.Event, SynchronizationEvent, FALSE);
	VM_MEDIUM_END
}

void Mutex::acquire() noexcept {
	VM_MEDIUM_BEGIN
	nt::ExAcquireFastMutex(&this->mutex);
	VM_MEDIUM_END
	__nop(); // Prevent tail call optimizations
}

bool Mutex::tryAcquire() noexcept {
	VM_MEDIUM_BEGIN
	const auto volatile result = nt::ExTryToAcquireFastMutex(&this->mutex);
	VM_MEDIUM_END
	return result;
}

void Mutex::release() noexcept {
	VM_MEDIUM_BEGIN
	nt::ExReleaseFastMutex(&this->mutex);
	VM_MEDIUM_END
	__nop(); // Prevent tail call optimizations
}
