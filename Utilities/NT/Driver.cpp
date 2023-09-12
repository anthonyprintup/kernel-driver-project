#include "NT.hpp"

#include <intrin.h>

#include "../../Configuration.hpp"
#include "../../Miscellaneous/Globals.hpp"

using namespace KM::Utilities::NT::Kernel;

auto detail::resolveDriverObject(const std::wstring_view name) noexcept {
	VM_MINIMUM_BEGIN
	using namespace Miscellaneous::Globals::NT;
	UNICODE_STRING objectName {static_cast<USHORT>(name.length() * 2), static_cast<USHORT>(name.length() * 2), const_cast<wchar_t*>(name.data())};
	PDRIVER_OBJECT driverObject {};
	if (const auto status = ObReferenceObjectByName(
		&objectName, OBJ_CASE_INSENSITIVE, nullptr,
		0, *IoDriverObjectType, KernelMode, nullptr,
		reinterpret_cast<PVOID*>(&driverObject));
		status != STATUS_SUCCESS)
		driverObject = nullptr;
	VM_MINIMUM_END

	return driverObject;
}

void detail::dereference(const PVOID object) noexcept {
	VM_MINIMUM_BEGIN
	namespace nt = Miscellaneous::Globals::NT;
	nt::ObDereferenceObject(object);
	VM_MINIMUM_END
	__nop(); // Prevent tail call optimizations
}

#pragma region Driver
Driver::Driver(const std::wstring_view driverName) noexcept {
	VM_SIZE_SPEED_BEGIN
	this->driver = detail::resolveDriverObject(driverName);
	VM_SIZE_SPEED_END
}

Driver::~Driver() noexcept {
	VM_SIZE_BEGIN
	if (this->driver)
		Miscellaneous::Globals::NT::ObDereferenceObject(this->driver);
	VM_SIZE_END
	__nop(); // Prevent tail call optimizations
}

Driver::operator bool() const noexcept {
	VM_SIZE_BEGIN
	const auto result = this->driver != nullptr;
	VM_SIZE_END

	return result;
}
#pragma endregion Driver

Driver KM::Utilities::NT::Kernel::driver(const std::wstring_view name) noexcept {
	return {name};
}
