// ReSharper disable CppParameterNamesMismatch
#include "Memory.hpp"

#include <ntifs.h>

#include "../Miscellaneous/Globals.hpp"
using namespace KM::Miscellaneous::Globals;

// Only defined with the debug configurations
#ifndef PAGED_ASSERT
#define PAGED_ASSERT(x)
#endif

void *__cdecl operator new(const size_t size) {
	PAGED_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
	return std::malloc(size);
}

void *__cdecl operator new(const size_t size, const std::nothrow_t&) noexcept {
	PAGED_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
	return std::malloc(size);
}

void *__cdecl operator new[](const size_t size) {
	PAGED_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
	return std::malloc(size);
}

void __cdecl operator delete(void *pointer) noexcept {
	PAGED_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
	std::free(pointer);
}

void __cdecl operator delete(void *pointer, [[maybe_unused]] size_t size) noexcept {
	PAGED_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
	operator delete(pointer);
}

void __cdecl operator delete[](void *pointer) noexcept {
	PAGED_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
	std::free(pointer);
}

__drv_maxIRQL(DISPATCH_LEVEL)
void *malloc(__in const size_t size) {
	VM_SIZE_SPEED_BEGIN
	const auto memory = NT::ExAllocatePool(NonPagedPool, size);
	VM_SIZE_SPEED_END
	return memory;
}

__drv_maxIRQL(DISPATCH_LEVEL)
void free(__inout void *pointer) {
	VM_SIZE_SPEED_BEGIN
	if (!pointer)
		return;
	
	NT::ExFreePool(pointer);
	VM_SIZE_SPEED_END
}

__drv_maxIRQL(DISPATCH_LEVEL)
extern "C" void *customReallocSecure(void *pointer, const size_t oldSize, const size_t newSize) {
	VM_SIZE_SPEED_BEGIN
	if (!newSize) {
		std::free(pointer);
		return nullptr;
	}

	const auto sizeToCopy = std::min(oldSize, newSize);
	const auto block = std::malloc(newSize);
	std::memcpy(block, pointer, sizeToCopy);
	std::memset(pointer, 0, oldSize);
	std::free(pointer);
	VM_SIZE_SPEED_END
	return block;
}

// Removed because we don't want to store the allocated size before the allocation, or check the page tables
/*__drv_maxIRQL(DISPATCH_LEVEL)
void *realloc(__in_opt void *pointer, __in const size_t size) {
	MUTATE_BEGIN
	if (!pointer)
		return std::malloc(size);

	const auto block = std::malloc(size);
	if (!block)
		return nullptr;

	std::memcpy(block, pointer, size);
	std::free(pointer);
	MUTATE_END
	return block;
}*/

__drv_maxIRQL(DISPATCH_LEVEL)
void *calloc(__in const size_t count, __in const size_t size) {
	MUTATE_BEGIN
	if (!size)
		return nullptr;
	if (static_cast<size_t>(~0) / count < size)
		return nullptr;

	const auto total = count * size;
	const auto block = std::malloc(total);
	if (!block)
		return nullptr;
	const auto result = std::memset(block, 0, total);
	MUTATE_END
	return result;
}