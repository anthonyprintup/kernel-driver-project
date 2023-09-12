#include "Disk.hpp"

#include <intrin.h>
#include <ntdddisk.h>
#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../Configuration.hpp"
#include "../Miscellaneous/Globals.hpp"
using namespace KM::Miscellaneous::Globals;

using namespace KM::Spoofer;

namespace callbacks {
	NTSTATUS storageQueryPropertyCompletionRoutine(const PDEVICE_OBJECT, const PIRP irp, PVOID) noexcept {
		VM_MINIMUM_BEGIN
		const auto storageDeviceDescriptor = static_cast<PSTORAGE_DEVICE_DESCRIPTOR>(irp->AssociatedIrp.SystemBuffer);
		if (storageDeviceDescriptor && storageDeviceDescriptor->SerialNumberOffset &&
			storageDeviceDescriptor->Version == sizeof(STORAGE_DEVICE_DESCRIPTOR)  &&
			storageDeviceDescriptor->Size    >= sizeof(STORAGE_DEVICE_DESCRIPTOR)  &&
			storageDeviceDescriptor->Size     > storageDeviceDescriptor->SerialNumberOffset) {
			const auto serialNumber = reinterpret_cast<char*>(storageDeviceDescriptor) + storageDeviceDescriptor->SerialNumberOffset;
			//if (!(std::string_view {serialNumber}.starts_with("VMWare NVME_0000")))
			//	__debugbreak();

			std::memset(serialNumber, 0, std::strlen(serialNumber));
			std::memcpy(serialNumber, xorstr_("System"), 7);
		}
		VM_MINIMUM_END
		return STATUS_SUCCESS;
	}

	// TODO: get the original arguments from NtDeviceIoControlFile by parsing the KTRAP_FRAME and check if the input is valid
	// TODO: change the output size of the STORAGE_DESCRIPTOR_HEADER to our size? (if possible...?) (avoid allowing ACs to check if there's a difference between the expected buffer size and the string size delta...)
	// TODO: handle ATA/NVME/whatever else identifier commands, otherwise the anti cheat can just get the serial numbers from there
	bool storageQueryPropertyPredicate(const PDEVICE_OBJECT, const PIRP irp) noexcept {
		VM_MINIMUM_BEGIN
		const auto volatile propertyQuery = static_cast<PSTORAGE_PROPERTY_QUERY>(irp->AssociatedIrp.SystemBuffer);
		const auto check = irp->AssociatedIrp.SystemBuffer != nullptr &&
			propertyQuery->PropertyId == StorageDeviceProperty &&
			propertyQuery->QueryType  == PropertyStandardQuery;

		//__debugbreak();
		VM_MINIMUM_END
		return check;
	}

	NTSTATUS smartRcvDriveDataCompletionRoutine(const PDEVICE_OBJECT, const PIRP irp, PVOID) noexcept {
		VM_MINIMUM_BEGIN
		const auto stackLocation = IoGetCurrentIrpStackLocation(irp);
		const auto idSector = reinterpret_cast<PIDSECTOR>(static_cast<PSENDCMDOUTPARAMS>(irp->AssociatedIrp.SystemBuffer)->bBuffer);
		if (idSector && stackLocation->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(SENDCMDOUTPARAMS)) {
			//if (!(std::string_view {idSector->sSerialNumber}.starts_with("MVaWerN MV_E0000")))
			//	__debugbreak();
			std::memset(idSector->sSerialNumber, 0, sizeof(idSector->sSerialNumber));
			std::memcpy(idSector->sSerialNumber, xorstr_("yStsme"), 7);
		}
		VM_MINIMUM_END
		return STATUS_SUCCESS;
	}
	bool smartRcvDriveDataPredicate(const PDEVICE_OBJECT, const PIRP irp) noexcept {
		VM_MINIMUM_BEGIN
		const auto volatile check = irp->AssociatedIrp.SystemBuffer != nullptr;
		VM_MINIMUM_END
		return check;
	}
}

Disk::Disk() noexcept:
	Driver {xorstr_(LR"(\Driver\Disk)")} {
	// Resolve attached devices
	VM_MAXIMUM_BEGIN

	// We have to call this before calling Mutex::acquire, because the IRQL is raised to APC level and BCryptGenRandom doesn't support system preferred RNGs at IRQLs higher than LOW_LEVEL.
	const auto dispatchTableOffset = **Symbols::classpnp::commonDeviceExtensionDispatchTable;

	this->mutex.acquire();
	for (auto device = this->driver->DeviceObject; device; device = device->NextDevice) {
		const auto dispatchTable = *reinterpret_cast<PDRIVER_DISPATCH**>(reinterpret_cast<std::uintptr_t>(device->DeviceExtension) + dispatchTableOffset);
		this->devices.emplace_back(device, device->DeviceExtension, dispatchTable, dispatchTable[IRP_MJ_DEVICE_CONTROL]);
	}
	this->mutex.release();
	VM_MAXIMUM_END
}

Disk::~Disk() noexcept {
	VM_SIZE_BEGIN
	this->restore();
	VM_SIZE_END
}

NTSTATUS deviceControlHooked(PDEVICE_OBJECT, PIRP);
void Disk::hook(const std::uint32_t ioControlCode, const detail::CompletionRoutineType completionRoutine, const detail::PredicateType predicate) noexcept {
	VM_MEDIUM_BEGIN
	for (auto &device : this->devices) {
		device.callbacks.emplace_back(ioControlCode, completionRoutine, predicate);
		
		// Hook the device control routine on all devices
		const auto dispatchTable = device.dispatchTable;
		if (dispatchTable[IRP_MJ_DEVICE_CONTROL] == &deviceControlHooked)
			continue;

		dispatchTable[IRP_MJ_DEVICE_CONTROL] = &deviceControlHooked;
	}
	VM_MEDIUM_END
	__nop(); // Prevent tail call optimizations
}

void Disk::restore() noexcept {
	VM_SIZE_BEGIN
	for (const auto &device : this->devices)
		device.dispatchTable[IRP_MJ_DEVICE_CONTROL] = device.deviceControlRoutine;
	VM_SIZE_END
	__nop(); // Prevent tail call optimizations
}

void KM::Spoofer::hook() {
	VM_MAXIMUM_BEGIN
	using namespace Utilities::NT::Kernel;
	const auto &disk = Drivers::disk = std::make_unique<Disk>();

	disk->hook(IOCTL_STORAGE_QUERY_PROPERTY,
			   &callbacks::storageQueryPropertyCompletionRoutine,
			   &callbacks::storageQueryPropertyPredicate);
	disk->hook(SMART_RCV_DRIVE_DATA,
			   &callbacks::smartRcvDriveDataCompletionRoutine,
			   &callbacks::smartRcvDriveDataPredicate);
	VM_MAXIMUM_END
	__nop(); // Prevent tail call optimizations
}

void KM::Spoofer::restore() {
	VM_MEDIUM_BEGIN
	using namespace Utilities::NT::Kernel;
	Drivers::disk.reset();
	VM_MEDIUM_END
	__nop(); // Prevent tail call optimizations
}

// TODO: find a way to automatically register new devices (callback?)
NTSTATUS completionRoutineHandler(PDEVICE_OBJECT, PIRP, PVOID);
NTSTATUS deviceControlHooked(const PDEVICE_OBJECT deviceObject, const PIRP irp) {
	VM_MINIMUM_BEGIN
	const auto &disk = Drivers::disk;
	if (const auto device = std::ranges::find_if(std::as_const(disk->devices), [=](const detail::DeviceEntry &entry) {
		return entry.object == deviceObject;
	}); device != disk->devices.cend()) {
		const auto stackLocation = IoGetCurrentIrpStackLocation(irp);
		const auto ioControlCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;

		const auto deviceControlRoutine = device->deviceControlRoutine;
		if (const auto entry = std::ranges::find_if(device->callbacks, [&](const detail::CallbackEntry &callback) {
			return callback.ioControlCode == ioControlCode;
		}); entry != device->callbacks.cend())
			if (entry->predicate(deviceObject, irp)) {
				const auto context = new detail::CompletionRoutineContext {
					stackLocation->Context, stackLocation->CompletionRoutine, entry->completionRoutine,
					false, true, false};
				stackLocation->Context = context;
				stackLocation->CompletionRoutine = &completionRoutineHandler;
				stackLocation->Control = SL_INVOKE_ON_CANCEL | SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR;
			}

		return deviceControlRoutine(deviceObject, irp);
	}

	// Device wasn't found, add to device list
	disk->mutex.acquire();
	const auto &firstDevice = disk->devices.front();
	auto &device = disk->devices.emplace_back(deviceObject, deviceObject->DeviceExtension, firstDevice.dispatchTable, firstDevice.deviceControlRoutine);
	disk->mutex.release();

	device.callbacks.emplace_back(IOCTL_STORAGE_QUERY_PROPERTY, &callbacks::storageQueryPropertyCompletionRoutine, &callbacks::storageQueryPropertyPredicate);
	device.callbacks.emplace_back(SMART_RCV_DRIVE_DATA, &callbacks::smartRcvDriveDataCompletionRoutine, &callbacks::smartRcvDriveDataPredicate);

	const auto volatile status = deviceControlHooked(deviceObject, irp);
	VM_MINIMUM_END
	
	return status;
}

NTSTATUS completionRoutineHandler(const PDEVICE_OBJECT deviceObject, const PIRP irp, const PVOID context) {
	VM_MINIMUM_BEGIN
	const auto completionRoutineContext = static_cast<detail::CompletionRoutineContext*>(context);
	NTSTATUS status {};
	if (completionRoutineContext->onCancel  && irp->Cancel ||
		completionRoutineContext->onSuccess && NT_SUCCESS(irp->IoStatus.Status) ||
		completionRoutineContext->onError   && !NT_SUCCESS(irp->IoStatus.Status))
		status = completionRoutineContext->callback(deviceObject, irp, context);
	if (irp->StackCount > 1 && completionRoutineContext->original)
		status = completionRoutineContext->original(deviceObject, irp, completionRoutineContext->context);
	
	delete completionRoutineContext;
	VM_MINIMUM_END

	return status;
}
