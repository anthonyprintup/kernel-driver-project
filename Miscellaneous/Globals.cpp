// ReSharper disable CppInconsistentNaming
// ReSharper disable CppClangTidyClangDiagnosticExitTimeDestructors
// ReSharper disable CppClangTidyPerformanceNoIntToPtr
#include "Globals.hpp"

#include <Framework/Utilities/Strings/XorStr.hpp>
#include <Framework/Utilities/Strings/Fnv1A.hpp>

#include "../Utilities/NT/NT.hpp"
using namespace KM::Utilities::NT;

using namespace KM::Miscellaneous::Globals;

#include "Net IO/Winsock Kernel/Wsk.hpp"
#include "Net IO/TLS/Client/Client.hpp"

#pragma region NT
#define DEFINE_FUNCTION(name) NT::name##Type NT::name {};

POBJECT_TYPE *NT::IoDriverObjectType {};
DEFINE_FUNCTION(ExAllocatePool)
DEFINE_FUNCTION(ExAllocatePoolWithTag)
DEFINE_FUNCTION(ExFreePoolWithTag)
DEFINE_FUNCTION(DbgPrintEx)
DEFINE_FUNCTION(_snprintf)
DEFINE_FUNCTION(_snprintf_s)
DEFINE_FUNCTION(ObReferenceObjectByName)
DEFINE_FUNCTION(ZwQuerySystemInformation)
DEFINE_FUNCTION(ObfDereferenceObject)
DEFINE_FUNCTION(PsLookupProcessByProcessId)
DEFINE_FUNCTION(PsLookupThreadByThreadId)
DEFINE_FUNCTION(PsGetProcessSectionBaseAddress)
DEFINE_FUNCTION(PsGetProcessId)
DEFINE_FUNCTION(PsGetProcessWow64Process)
DEFINE_FUNCTION(PsGetProcessPeb)
DEFINE_FUNCTION(PsGetThreadTeb)
DEFINE_FUNCTION(IoGetCurrentProcess)
DEFINE_FUNCTION(MmCopyVirtualMemory)
DEFINE_FUNCTION(ZwQueryVirtualMemory)
DEFINE_FUNCTION(ZwProtectVirtualMemory)
DEFINE_FUNCTION(KeStackAttachProcess)
DEFINE_FUNCTION(KeUnstackDetachProcess)
DEFINE_FUNCTION(ZwCreateFile)
DEFINE_FUNCTION(ZwReadFile)
DEFINE_FUNCTION(ZwWriteFile)
DEFINE_FUNCTION(ZwQueryInformationFile)
DEFINE_FUNCTION(ZwClose)
DEFINE_FUNCTION(IoAllocateMdl)
DEFINE_FUNCTION(IoFreeMdl)
DEFINE_FUNCTION(MmProbeAndLockProcessPages)
DEFINE_FUNCTION(MmMapLockedPagesSpecifyCache)
DEFINE_FUNCTION(MmUnlockPages)
DEFINE_FUNCTION(KeInitializeApc)
DEFINE_FUNCTION(KeInsertQueueApc)
DEFINE_FUNCTION(KeTestAlertThread)
DEFINE_FUNCTION(PsIsThreadTerminating)
DEFINE_FUNCTION(KeEnterGuardedRegion)
DEFINE_FUNCTION(KeLeaveGuardedRegion)
DEFINE_FUNCTION(PsGetCurrentThread)
DEFINE_FUNCTION(ZwAllocateVirtualMemory)
DEFINE_FUNCTION(ZwFreeVirtualMemory)
DEFINE_FUNCTION(KeWaitForSingleObject)
DEFINE_FUNCTION(KeDelayExecutionThread)
DEFINE_FUNCTION(MmMapIoSpace)
DEFINE_FUNCTION(MmUnmapIoSpace)
DEFINE_FUNCTION(ExGetFirmwareEnvironmentVariable)
DEFINE_FUNCTION(MmGetPhysicalAddress)
DEFINE_FUNCTION(KeInitializeEvent)
DEFINE_FUNCTION(IoAllocateIrp)
DEFINE_FUNCTION(IoInitializeIrp)
DEFINE_FUNCTION(IoCancelIrp)
DEFINE_FUNCTION(IoFreeIrp)
DEFINE_FUNCTION(IoReuseIrp)
DEFINE_FUNCTION(KeSetEvent)
DEFINE_FUNCTION(KeResetEvent)
DEFINE_FUNCTION(RtlMultiByteToUnicodeSize)
DEFINE_FUNCTION(RtlUnicodeToMultiByteSize)
DEFINE_FUNCTION(RtlMultiByteToUnicodeN)
DEFINE_FUNCTION(RtlUnicodeToMultiByteN)
DEFINE_FUNCTION(ExAcquireFastMutex)
DEFINE_FUNCTION(ExTryToAcquireFastMutex)
DEFINE_FUNCTION(ExReleaseFastMutex)
DEFINE_FUNCTION(ExAcquireFastMutexUnsafe)
DEFINE_FUNCTION(ExReleaseFastMutexUnsafe)
DEFINE_FUNCTION(PsGetCurrentProcessId)
DEFINE_FUNCTION(KeQuerySystemTimePrecise)
DEFINE_FUNCTION(ExLocalTimeToSystemTime)
DEFINE_FUNCTION(ExSystemTimeToLocalTime)
DEFINE_FUNCTION(RtlTimeToSecondsSince1970)
DEFINE_FUNCTION(KeExpandKernelStackAndCallout)

DEFINE_FUNCTION(HalEnumerateEnvironmentVariablesEx)

DEFINE_FUNCTION(BCryptOpenAlgorithmProvider)
DEFINE_FUNCTION(BCryptGenRandom)
DEFINE_FUNCTION(BCryptCloseAlgorithmProvider)

DEFINE_FUNCTION(WskRegister)
DEFINE_FUNCTION(WskDeregister)
DEFINE_FUNCTION(WskCaptureProviderNPI)
DEFINE_FUNCTION(WskReleaseProviderNPI)

#undef DEFINE_FUNCTION
#pragma endregion

#pragma region dxgkrnl
std::uintptr_t Syscalls::returnAddress {};
std::uintptr_t Syscalls::functionIndex {};
std::unique_ptr<VirtualFunctionTable> Syscalls::dxgkrnlTable {};
#pragma endregion

std::unique_ptr<KM::Spoofer::Disk> Drivers::disk {};

#pragma region WSK
WSK_REGISTRATION NetIo::registration {};
WSK_PROVIDER_NPI NetIo::provider {};
WSK_CLIENT_DISPATCH NetIo::dispatch {MAKE_WSK_VERSION(1, 0)};

std::unique_ptr<KM::Utilities::Mutex> NetIo::mutex {};
std::unique_ptr<std::map<KM::Miscellaneous::NetIo::SocketIdentifier, KM::Miscellaneous::NetIo::Socket>> NetIo::sockets {};
#pragma endregion WSK

#pragma region Symbols
#define DEFINE_SYMBOL(name) decltype(Symbols::name) Symbols::name {};

DEFINE_SYMBOL(ntoskrnl::wmipSMBiosTablePhysicalAddress)
DEFINE_SYMBOL(ntoskrnl::wmipSMBiosTableLength)
DEFINE_SYMBOL(ntoskrnl::wmipSMBiosVersionInfo)

DEFINE_SYMBOL(ntoskrnl::pnpDriverObject)

DEFINE_SYMBOL(ntoskrnl::forceDumpDisabled)

DEFINE_SYMBOL(ntoskrnl::kdPitchDebugger)
DEFINE_SYMBOL(ntoskrnl::kdBlockEnable)
DEFINE_SYMBOL(ntoskrnl::kdPreviouslyEnabled)
DEFINE_SYMBOL(ntoskrnl::kdpDebugRoutineSelect)
DEFINE_SYMBOL(ntoskrnl::kdDebuggerNotPresent)
DEFINE_SYMBOL(ntoskrnl::kdDebuggerEnabled)
DEFINE_SYMBOL(ntoskrnl::kdTransportMaxPacketSize)
DEFINE_SYMBOL(ntoskrnl::kdDebugDevice)
DEFINE_SYMBOL(ntoskrnl::halpDebugPortTable)
DEFINE_SYMBOL(ntoskrnl::kdpLoaderDebuggerBlock)
DEFINE_SYMBOL(ntoskrnl::kdpDebuggerDataListHead)
DEFINE_SYMBOL(ntoskrnl::kdIgnoreUmExceptions)
DEFINE_SYMBOL(ntoskrnl::kdVersionBlock)
DEFINE_SYMBOL(ntoskrnl::kdPrintBufferAllocateSize)
DEFINE_SYMBOL(ntoskrnl::kdPageDebuggerSection)
DEFINE_SYMBOL(ntoskrnl::kdpBootedNodebug)
DEFINE_SYMBOL(ntoskrnl::kdEnteredDebugger)
DEFINE_SYMBOL(ntoskrnl::kdpDebuggerStructuresInitialized)
DEFINE_SYMBOL(ntoskrnl::kdPortLocked)
DEFINE_SYMBOL(ntoskrnl::kdpContext)
DEFINE_SYMBOL(ntoskrnl::kdDebuggerEnteredCount)
DEFINE_SYMBOL(ntoskrnl::kdDebuggerEnteredWithoutLock)
DEFINE_SYMBOL(ntoskrnl::kdpMessageBuffer)
DEFINE_SYMBOL(ntoskrnl::kdPrintRolloverCount)
DEFINE_SYMBOL(ntoskrnl::kdPrintDefaultCircularBuffer)
DEFINE_SYMBOL(ntoskrnl::kdPrintBufferChanges)
DEFINE_SYMBOL(ntoskrnl::kdpBreakpointChangeCount)
DEFINE_SYMBOL(ntoskrnl::kdpPathBuffer)
DEFINE_SYMBOL(ntoskrnl::kiBootDebuggerActive)
DEFINE_SYMBOL(ntoskrnl::kdBreakAfterSymbolLoad)
DEFINE_SYMBOL(ntoskrnl::kdComPortInUse)
DEFINE_SYMBOL(ntoskrnl::kdHvComPortInUse)
DEFINE_SYMBOL(ntoskrnl::kdpTimeSlipEvent)

DEFINE_SYMBOL(ntoskrnl::seCiDebugOptions)
DEFINE_SYMBOL(ntoskrnl::seILSigningPolicy)

DEFINE_SYMBOL(ntoskrnl::hvcallpNoHypervisorPresent)
DEFINE_SYMBOL(ntoskrnl::hvcallCodeVa)
DEFINE_SYMBOL(ntoskrnl::hvlpFlags)
DEFINE_SYMBOL(ntoskrnl::hvlpRootFlags)
DEFINE_SYMBOL(ntoskrnl::hvlHypervisorConnected)
DEFINE_SYMBOL(ntoskrnl::hvlEnableIdleYield)
DEFINE_SYMBOL(ntoskrnl::hvlpVsmVtlCallVa)
DEFINE_SYMBOL(ntoskrnl::hvlpHypercallCodeVa)
DEFINE_SYMBOL(ntoskrnl::vslpNestedPageProtectionFlags)
DEFINE_SYMBOL(ntoskrnl::hvlpReferenceTscPage)
DEFINE_SYMBOL(ntoskrnl::hvlpHypervisorVersion)

DEFINE_SYMBOL(ntoskrnl::ethread::tcb)
DEFINE_SYMBOL(ntoskrnl::ethread::startAddress)
DEFINE_SYMBOL(ntoskrnl::ethread::win32StartAddress)

DEFINE_SYMBOL(ntoskrnl::kthread::initialStack)
DEFINE_SYMBOL(ntoskrnl::kthread::stackLimit)
DEFINE_SYMBOL(ntoskrnl::kthread::stackBase)
DEFINE_SYMBOL(ntoskrnl::kthread::systemCallNumber)
DEFINE_SYMBOL(ntoskrnl::kthread::trapFrame)

DEFINE_SYMBOL(dxgkrnl::global)

DEFINE_SYMBOL(classpnp::commonDeviceExtensionDispatchTable)
#undef DEFINE_SYMBOL
#pragma endregion Symbols

decltype(Hardware::hardwareId) Hardware::hardwareId {};

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments ...arguments) {
	if constexpr (Configuration::print) {
		VM_SIZE_BEGIN
		NT::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), arguments...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

bool KM::Miscellaneous::Globals::initialize() noexcept {
	VM_MAXIMUM_BEGIN
	auto success {true};
	
	const auto ntoskrnl = Kernel::ntoskrnl();

	#define RESOLVE(root, name) NT::name = reinterpret_cast<decltype(NT::name)>(PE::exported(root, Fnv1A(#name))); if (!NT::name) success = false;
	// ntoskrnl exports
	{
		RESOLVE(ntoskrnl, IoDriverObjectType)
		RESOLVE(ntoskrnl, ExAllocatePool)
		RESOLVE(ntoskrnl, ExAllocatePoolWithTag)
		RESOLVE(ntoskrnl, ExFreePoolWithTag)
		RESOLVE(ntoskrnl, DbgPrintEx)
		RESOLVE(ntoskrnl, _snprintf)
		RESOLVE(ntoskrnl, _snprintf_s)
		RESOLVE(ntoskrnl, ObReferenceObjectByName)
		RESOLVE(ntoskrnl, ZwQuerySystemInformation)
		RESOLVE(ntoskrnl, ObfDereferenceObject)
		RESOLVE(ntoskrnl, PsLookupProcessByProcessId)
		RESOLVE(ntoskrnl, PsLookupThreadByThreadId)
		RESOLVE(ntoskrnl, PsGetProcessSectionBaseAddress)
		RESOLVE(ntoskrnl, PsGetProcessId)
		RESOLVE(ntoskrnl, PsGetProcessWow64Process)
		RESOLVE(ntoskrnl, PsGetProcessPeb)
		RESOLVE(ntoskrnl, PsGetThreadTeb)
		RESOLVE(ntoskrnl, IoGetCurrentProcess)
		RESOLVE(ntoskrnl, MmCopyVirtualMemory)
		RESOLVE(ntoskrnl, ZwQueryVirtualMemory)
		RESOLVE(ntoskrnl, ZwProtectVirtualMemory)
		RESOLVE(ntoskrnl, KeStackAttachProcess)
		RESOLVE(ntoskrnl, KeUnstackDetachProcess)
		RESOLVE(ntoskrnl, ZwCreateFile)
		RESOLVE(ntoskrnl, ZwReadFile)
		RESOLVE(ntoskrnl, ZwWriteFile)
		RESOLVE(ntoskrnl, ZwQueryInformationFile)
		RESOLVE(ntoskrnl, ZwClose)
		RESOLVE(ntoskrnl, IoAllocateMdl)
		RESOLVE(ntoskrnl, IoFreeMdl)
		RESOLVE(ntoskrnl, MmProbeAndLockProcessPages)
		RESOLVE(ntoskrnl, MmMapLockedPagesSpecifyCache)
		RESOLVE(ntoskrnl, MmUnlockPages)
		RESOLVE(ntoskrnl, KeInitializeApc)
		RESOLVE(ntoskrnl, KeInsertQueueApc)
		RESOLVE(ntoskrnl, KeTestAlertThread)
		RESOLVE(ntoskrnl, PsIsThreadTerminating)
		RESOLVE(ntoskrnl, KeEnterGuardedRegion)
		RESOLVE(ntoskrnl, KeLeaveGuardedRegion)
		RESOLVE(ntoskrnl, PsGetCurrentThread)
		RESOLVE(ntoskrnl, ZwAllocateVirtualMemory)
		RESOLVE(ntoskrnl, ZwFreeVirtualMemory)
		RESOLVE(ntoskrnl, KeWaitForSingleObject)
		RESOLVE(ntoskrnl, KeDelayExecutionThread)
		RESOLVE(ntoskrnl, MmMapIoSpace)
		RESOLVE(ntoskrnl, MmUnmapIoSpace)
		RESOLVE(ntoskrnl, ExGetFirmwareEnvironmentVariable)
		RESOLVE(ntoskrnl, MmGetPhysicalAddress)
		RESOLVE(ntoskrnl, KeInitializeEvent)
		RESOLVE(ntoskrnl, IoAllocateIrp)
		RESOLVE(ntoskrnl, IoInitializeIrp)
		RESOLVE(ntoskrnl, IoCancelIrp)
		RESOLVE(ntoskrnl, IoFreeIrp)
		RESOLVE(ntoskrnl, IoReuseIrp)
		RESOLVE(ntoskrnl, KeSetEvent)
		RESOLVE(ntoskrnl, KeResetEvent)
		RESOLVE(ntoskrnl, RtlMultiByteToUnicodeSize)
		RESOLVE(ntoskrnl, RtlUnicodeToMultiByteSize)
		RESOLVE(ntoskrnl, RtlMultiByteToUnicodeN)
		RESOLVE(ntoskrnl, RtlUnicodeToMultiByteN)
		RESOLVE(ntoskrnl, ExAcquireFastMutex)
		RESOLVE(ntoskrnl, ExTryToAcquireFastMutex)
		RESOLVE(ntoskrnl, ExReleaseFastMutex)
		RESOLVE(ntoskrnl, ExAcquireFastMutexUnsafe)
		RESOLVE(ntoskrnl, ExReleaseFastMutexUnsafe)
		RESOLVE(ntoskrnl, PsGetCurrentProcessId)
		RESOLVE(ntoskrnl, KeQuerySystemTimePrecise)
		RESOLVE(ntoskrnl, ExLocalTimeToSystemTime)
		RESOLVE(ntoskrnl, ExSystemTimeToLocalTime)
		RESOLVE(ntoskrnl, RtlTimeToSecondsSince1970)
		RESOLVE(ntoskrnl, KeExpandKernelStackAndCallout)
		if constexpr (Configuration::print) {
			print(xorstr_("IoDriverObjectType:                 %p"), NT::IoDriverObjectType);
			print(xorstr_("ExAllocatePool:                     %p"), NT::ExAllocatePool);
			print(xorstr_("ExAllocatePoolWithTag:              %p"), NT::ExAllocatePoolWithTag);
			print(xorstr_("ExFreePoolWithTag:                  %p"), NT::ExFreePoolWithTag);
			print(xorstr_("DbgPrintEx:                         %p"), NT::DbgPrintEx);
			print(xorstr_("_snprintf:                          %p"), NT::_snprintf);
			print(xorstr_("_snprintf_s:                        %p"), NT::_snprintf_s);
			print(xorstr_("ObReferenceObjectByName:            %p"), NT::ObReferenceObjectByName);
			print(xorstr_("ZwQuerySystemInformation:           %p"), NT::ZwQuerySystemInformation);
			print(xorstr_("ObfDereferenceObject:               %p"), NT::ObfDereferenceObject);
			print(xorstr_("PsLookupProcessByProcessId:         %p"), NT::PsLookupProcessByProcessId);
			print(xorstr_("PsLookupThreadByThreadId:           %p"), NT::PsLookupThreadByThreadId);
			print(xorstr_("PsGetProcessSectionBaseAddress:     %p"), NT::PsGetProcessSectionBaseAddress);
			print(xorstr_("PsGetProcessId:                     %p"), NT::PsGetProcessId);
			print(xorstr_("PsGetProcessWow64Process:           %p"), NT::PsGetProcessWow64Process);
			print(xorstr_("PsGetProcessPeb:                    %p"), NT::PsGetProcessPeb);
			print(xorstr_("PsGetThreadTeb:                     %p"), NT::PsGetThreadTeb);
			print(xorstr_("IoGetCurrentProcess:                %p"), NT::IoGetCurrentProcess);
			print(xorstr_("MmCopyVirtualMemory:                %p"), NT::MmCopyVirtualMemory);
			print(xorstr_("ZwQueryVirtualMemory:               %p"), NT::ZwQueryVirtualMemory);
			print(xorstr_("ZwProtectVirtualMemory:             %p"), NT::ZwProtectVirtualMemory);
			print(xorstr_("KeStackAttachProcess:               %p"), NT::KeStackAttachProcess);
			print(xorstr_("KeUnstackDetachProcess:             %p"), NT::KeUnstackDetachProcess);
			print(xorstr_("ZwCreateFile:                       %p"), NT::ZwCreateFile);
			print(xorstr_("ZwReadFile:                         %p"), NT::ZwReadFile);
			print(xorstr_("ZwWriteFile:                        %p"), NT::ZwWriteFile);
			print(xorstr_("ZwQueryInformationFile:             %p"), NT::ZwQueryInformationFile);
			print(xorstr_("ZwClose:                            %p"), NT::ZwClose);
			print(xorstr_("IoAllocateMdl:                      %p"), NT::IoAllocateMdl);
			print(xorstr_("IoFreeMdl:                          %p"), NT::IoFreeMdl);
			print(xorstr_("MmProbeAndLockProcessPages:         %p"), NT::MmProbeAndLockProcessPages);
			print(xorstr_("MmMapLockedPagesSpecifyCache:       %p"), NT::MmMapLockedPagesSpecifyCache);
			print(xorstr_("MmUnlockPages:                      %p"), NT::MmUnlockPages);
			print(xorstr_("KeInitializeApc:                    %p"), NT::KeInitializeApc);
			print(xorstr_("KeInsertQueueApc:                   %p"), NT::KeInsertQueueApc);
			print(xorstr_("KeTestAlertThread:                  %p"), NT::KeTestAlertThread);
			print(xorstr_("PsIsThreadTerminating:              %p"), NT::PsIsThreadTerminating);
			print(xorstr_("KeEnterGuardedRegion:               %p"), NT::KeEnterGuardedRegion);
			print(xorstr_("KeLeaveGuardedRegion:               %p"), NT::KeLeaveGuardedRegion);
			print(xorstr_("PsGetCurrentThread:                 %p"), NT::PsGetCurrentThread);
			print(xorstr_("ZwAllocateVirtualMemory:            %p"), NT::ZwAllocateVirtualMemory);
			print(xorstr_("ZwFreeVirtualMemory:                %p"), NT::ZwFreeVirtualMemory);
			print(xorstr_("KeWaitForSingleObject:              %p"), NT::KeWaitForSingleObject);
			print(xorstr_("KeDelayExecutionThread:             %p"), NT::KeDelayExecutionThread);
			print(xorstr_("MmMapIoSpace:                       %p"), NT::MmMapIoSpace);
			print(xorstr_("MmUnmapIoSpace:                     %p"), NT::MmUnmapIoSpace);
			print(xorstr_("ExGetFirmwareEnvironmentVariable:   %p"), NT::ExGetFirmwareEnvironmentVariable);
			print(xorstr_("MmGetPhysicalAddress:               %p"), NT::MmGetPhysicalAddress);
			print(xorstr_("KeInitializeEvent:                  %p"), NT::KeInitializeEvent);
			print(xorstr_("IoAllocateIrp:                      %p"), NT::IoAllocateIrp);
			print(xorstr_("IoInitializeIrp:                    %p"), NT::IoInitializeIrp);
			print(xorstr_("IoCancelIrp:                        %p"), NT::IoCancelIrp);
			print(xorstr_("IoFreeIrp:                          %p"), NT::IoFreeIrp);
			print(xorstr_("IoReuseIrp:                         %p"), NT::IoReuseIrp);
			print(xorstr_("KeSetEvent:                         %p"), NT::KeSetEvent);
			print(xorstr_("KeResetEvent:                       %p"), NT::KeResetEvent);
			print(xorstr_("RtlMultiByteToUnicodeSize:          %p"), NT::RtlMultiByteToUnicodeSize);
			print(xorstr_("RtlUnicodeToMultiByteSize:          %p"), NT::RtlUnicodeToMultiByteSize);
			print(xorstr_("RtlMultiByteToUnicodeN:             %p"), NT::RtlMultiByteToUnicodeN);
			print(xorstr_("RtlUnicodeToMultiByteN:             %p"), NT::RtlUnicodeToMultiByteN);
			print(xorstr_("ExAcquireFastMutex:                 %p"), NT::ExAcquireFastMutex);
			print(xorstr_("ExReleaseFastMutex:                 %p"), NT::ExReleaseFastMutex);
			print(xorstr_("ExAcquireFastMutexUnsafe:           %p"), NT::ExAcquireFastMutexUnsafe);
			print(xorstr_("ExReleaseFastMutexUnsafe:           %p"), NT::ExReleaseFastMutexUnsafe);
			print(xorstr_("PsGetCurrentProcessId:              %p"), NT::PsGetCurrentProcessId);
			print(xorstr_("KeQuerySystemTimePrecise:           %p"), NT::KeQuerySystemTimePrecise);
			print(xorstr_("ExLocalTimeToSystemTime:            %p"), NT::ExLocalTimeToSystemTime);
			print(xorstr_("ExSystemTimeToLocalTime:            %p"), NT::ExSystemTimeToLocalTime);
			print(xorstr_("RtlTimeToSecondsSince1970:          %p"), NT::RtlTimeToSecondsSince1970);
			print(xorstr_("KeExpandKernelStackAndCallout:      %p"), NT::KeExpandKernelStackAndCallout);
		}
		if (!success) return success;
	}

	// hal exports
	{
		std::uintptr_t base {};
		if (const auto [hal, halSize] = Kernel::module(Fnv1A("hal.dll")); hal)
			if (const auto [text, textSize] = PE::section(hal, Fnv1A(".text")); text && textSize)
				base = hal;
		if (!base) base = ntoskrnl;

		RESOLVE(base, HalEnumerateEnvironmentVariablesEx)
		if constexpr (Configuration::print)
			print(xorstr_("HalEnumerateEnvironmentVariablesEx: %p"), NT::HalEnumerateEnvironmentVariablesEx);
		if (!success) return success;
	}
	
	// cng exports
	{
		const auto [cng, cngSize] = Kernel::module(Fnv1A("cng.sys"));
		
		RESOLVE(cng, BCryptOpenAlgorithmProvider)
		RESOLVE(cng, BCryptGenRandom)
		RESOLVE(cng, BCryptCloseAlgorithmProvider)
		if constexpr (Configuration::print) {
			print(xorstr_("BCryptOpenAlgorithmProvider:        %p"), NT::BCryptOpenAlgorithmProvider);
			print(xorstr_("BCryptGenRandom:                    %p"), NT::BCryptGenRandom);
			print(xorstr_("BCryptCloseAlgorithmProvider:       %p"), NT::BCryptCloseAlgorithmProvider);
		}
		if (!success) return success;
	}

	// netio exports
	{
		const auto [netio, netioSize] = Kernel::module(Fnv1A("NETIO.SYS"));
		
		RESOLVE(netio, WskRegister)
		RESOLVE(netio, WskDeregister)
		RESOLVE(netio, WskCaptureProviderNPI)
		RESOLVE(netio, WskReleaseProviderNPI)
		if constexpr (Configuration::print) {
			print(xorstr_("WskRegister:                        %p"), NT::WskRegister);
			print(xorstr_("WskDeregister:                      %p"), NT::WskDeregister);
			print(xorstr_("WskCaptureProviderNPI:              %p"), NT::WskCaptureProviderNPI);
			print(xorstr_("WskReleaseProviderNPI:              %p"), NT::WskReleaseProviderNPI);
		}
		if (!success) return success;
	}

	// dxgkrnl
	// TODO: move this below the networking setup, resolve offsets using symbols!
	/*{
		const auto [dxgkrnl, dxgkrnlSize] = Kernel::module(Fnv1A("dxgkrnl.sys"));
		if (!dxgkrnl)
			return success = false;

		const auto ntSetCompositionSurfaceAnalogExclusive = PE::exported(dxgkrnl, Fnv1A("NtSetCompositionSurfaceAnalogExclusive"));
		if (!ntSetCompositionSurfaceAnalogExclusive)
			return success = false;

		using namespace Utilities;
		Syscalls::returnAddress = Scanner::scan(
			reinterpret_cast<std::uint8_t*>(ntSetCompositionSurfaceAnalogExclusive), 0xFF,
			reinterpret_cast<std::uint8_t*>(xorstr_("\xBF\x22\x00\x00\xC0")),
			reinterpret_cast<std::uint8_t*>(xorstr_("\xFF\xFF\xFF\xFF\xFF")), 5); // +5 is call cs:__imp_KeLeaveCriticalRegion
		if (!Syscalls::returnAddress)
			return success = false;
		
		const auto [textSection, textSectionSize] = PE::section(dxgkrnl, Fnv1A(".text"));
		if (!textSection)
			return success = false;

		// TODO: resolve using symbol parsing
		// ?m_pGlobal@DXGGLOBAL@@0PEAV1@EA

		auto global = Scanner::scan(
			reinterpret_cast<std::uint8_t*>(textSection), textSectionSize,
			reinterpret_cast<std::uint8_t*>(xorstr_("\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x0F\x84\x00\x00\x00\x00\x48\x83\xC4\x00\xC3")),
			reinterpret_cast<std::uint8_t*>(xorstr_("\xFF\xFF\xFF\x2E\xFF\xFF\xFF\x2E\x2E\x2E\x2E\xFF\xFF\xFF\xFF\xFF\x2E\x2E\x2E\x2E\xFF\xFF\xFF\x2E\xFF")), 7);
		if (!global)
			return success = false;

		global += *reinterpret_cast<std::int32_t*>(global) + sizeof(std::int32_t);
		global = *reinterpret_cast<std::uintptr_t*>(global);
		if (!global)
			return success = false;

		const auto functionTableOffset = *reinterpret_cast<std::uint32_t*>(Scanner::scan(
			reinterpret_cast<std::uint8_t*>(ntSetCompositionSurfaceAnalogExclusive), 0x50,
			reinterpret_cast<std::uint8_t*>(xorstr_("\xE8\x00\x00\x00\x00\x4C\x8B\x80")),
			reinterpret_cast<std::uint8_t*>(xorstr_("\xFF\x2E\x2E\x2E\x2E\xFF\xFF\xFF")), 8));
		// DXGKW32KIMPORTS->UserUnsafeIsCurrentProcessDwm
		Syscalls::functionIndex = *reinterpret_cast<std::uint32_t*>(Scanner::scan(
			reinterpret_cast<std::uint8_t*>(ntSetCompositionSurfaceAnalogExclusive), 0x50,
			reinterpret_cast<std::uint8_t*>(xorstr_("\x4C\x8B\x80\x00\x00\x00\x00\x49\x8B\x80")),
			reinterpret_cast<std::uint8_t*>(xorstr_("\xFF\xFF\xFF\x2E\x2E\x2E\x2E\xFF\xFF\xFF")), 10)) / sizeof(std::uintptr_t);
		if (!Syscalls::functionIndex)
			return success = false;

		const auto win32kbaseFunctionTable {global + functionTableOffset};
		if (!*reinterpret_cast<std::uintptr_t*>(win32kbaseFunctionTable))
			return success = false; // ghetto crash fix
		Syscalls::dxgkrnlTable = std::make_unique<VirtualFunctionTable>(win32kbaseFunctionTable);
	}*/

	// networking
	{
		namespace wsk = Miscellaneous::NetIo::WinsockKernel;
		if (wsk::startup() != STATUS_SUCCESS)
			return success = false;

		NetIo::mutex   = std::make_unique<decltype(NetIo::mutex)::element_type>();
		NetIo::sockets = std::make_unique<decltype(NetIo::sockets)::element_type>();
	}

	// Register libtomcrypt and libtommath
	tls::client::registerCiphers();
	tls::client::registerHashes();
	tls::client::registerPrngs();
	#undef RESOLVE

	bool symbolsReadSuccessfully {};
	NT::KeExpandKernelStackAndCallout(&Symbols::resolveSymbols, &symbolsReadSuccessfully, MAXIMUM_EXPANSION_SIZE);
	if (!symbolsReadSuccessfully)
		return symbolsReadSuccessfully;
	// TODO: if not successful send a request to the server

	// TODO: anti debug

	// Calculate the (unique) hardware id of the machine
	Hardware::hardwareId = std::make_unique<decltype(Hardware::hardwareId)::element_type>();

	// TODO: communicate with the server
	VM_MAXIMUM_END
	return success;
}
