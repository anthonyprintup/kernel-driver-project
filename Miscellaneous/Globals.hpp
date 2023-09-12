// ReSharper disable CppInconsistentNaming
#pragma once

#include <map>

#include <Framework/Utilities/Hooks/Virtual Function Table.hpp>

// ReSharper disable once CppUnusedIncludeDirective
#include "../Configuration.hpp"
#include "../Utilities/NT/Definitions.hpp"
#include "../Spoofer/Disk.hpp"

#include "../Utilities/Mutex.hpp"
#include "Net IO/Socket.hpp"
#include "../Utilities/Obfuscation.hpp"

#include "Security/Hardware Id.hpp"

#include <bcrypt.h>

namespace KM::Miscellaneous::Globals {	
	// TODO: pointer obfuscation?
	#define OBFUSCATED_PTR(x) extern std::unique_ptr<::KM::Utilities::Obfuscation::Pointer<x, __COUNTER__ + 0x100>>
	namespace NT {
		#define EXPORTED_FUNCTION(name) using name##Type = std::decay_t<decltype(name)>; extern name##Type (name);
		#define EXPORTED_FUNCTION_TYPE(name, type) using name##Type = type; extern name##Type name;
		
		extern POBJECT_TYPE *IoDriverObjectType;

		EXPORTED_FUNCTION(ExAllocatePool)  // NOLINT(clang-diagnostic-deprecated-declarations)
		EXPORTED_FUNCTION(ExAllocatePoolWithTag)
		EXPORTED_FUNCTION(ExFreePoolWithTag)
		
		EXPORTED_FUNCTION_TYPE(DbgPrintEx, ULONG(__cdecl*)(ULONG, ULONG, PCSTR, ...))
		EXPORTED_FUNCTION(_snprintf)
		EXPORTED_FUNCTION_TYPE(_snprintf_s, int(*)(char*, size_t, size_t, const char*, ...))
		EXPORTED_FUNCTION_TYPE(ObReferenceObjectByName, NTSTATUS(*)(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*))
		EXPORTED_FUNCTION_TYPE(ZwQuerySystemInformation, NTSTATUS(*)(ULONG, PVOID, ULONG, PULONG))
		EXPORTED_FUNCTION(ObfDereferenceObject)
		EXPORTED_FUNCTION_TYPE(PsLookupProcessByProcessId, NTSTATUS(*)(HANDLE, PEPROCESS*))
		EXPORTED_FUNCTION_TYPE(PsLookupThreadByThreadId, NTSTATUS(*)(HANDLE, PETHREAD*))
		EXPORTED_FUNCTION_TYPE(PsGetProcessSectionBaseAddress, PVOID(*)(PEPROCESS))
		EXPORTED_FUNCTION(PsGetProcessId)
		EXPORTED_FUNCTION_TYPE(PsGetProcessWow64Process, PEWOW64PROCESS(*)(PEPROCESS))
		EXPORTED_FUNCTION_TYPE(PsGetProcessPeb, PPEB(*)(PEPROCESS))
		EXPORTED_FUNCTION_TYPE(PsGetThreadTeb, PTEB(*)(PETHREAD))
		EXPORTED_FUNCTION_TYPE(IoGetCurrentProcess, PEPROCESS(*)())
		EXPORTED_FUNCTION_TYPE(MmCopyVirtualMemory, NTSTATUS(*)(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T))
		EXPORTED_FUNCTION_TYPE(ZwQueryVirtualMemory, NTSTATUS(*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T))
		EXPORTED_FUNCTION_TYPE(ZwProtectVirtualMemory, NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))
		EXPORTED_FUNCTION_TYPE(KeStackAttachProcess, void(*)(PEPROCESS, PKAPC_STATE_T))
		EXPORTED_FUNCTION_TYPE(KeUnstackDetachProcess, void(*)(PKAPC_STATE_T))
		EXPORTED_FUNCTION(ZwCreateFile)
		EXPORTED_FUNCTION(ZwReadFile)
		EXPORTED_FUNCTION(ZwWriteFile)
		EXPORTED_FUNCTION(ZwQueryInformationFile)
		EXPORTED_FUNCTION(ZwClose)
		EXPORTED_FUNCTION(IoAllocateMdl)
		EXPORTED_FUNCTION(IoFreeMdl)
		EXPORTED_FUNCTION(MmProbeAndLockProcessPages)
		EXPORTED_FUNCTION(MmMapLockedPagesSpecifyCache)
		EXPORTED_FUNCTION(MmUnlockPages)
		EXPORTED_FUNCTION_TYPE(KeInitializeApc, void(*)(PKAPC, PETHREAD, KAPC_ENVIRONMENT, PKKERNEL_ROUTINE, PKRUNDOWN_ROUTINE, PKNORMAL_ROUTINE, KPROCESSOR_MODE, PVOID))
		EXPORTED_FUNCTION_TYPE(KeInsertQueueApc, BOOLEAN(*)(PRKAPC, PVOID, PVOID, KPRIORITY))
		EXPORTED_FUNCTION_TYPE(KeTestAlertThread, BOOLEAN(*)(KPROCESSOR_MODE))
		EXPORTED_FUNCTION_TYPE(PsIsThreadTerminating, BOOLEAN(*)(PETHREAD))
		EXPORTED_FUNCTION(KeEnterGuardedRegion)
		EXPORTED_FUNCTION(KeLeaveGuardedRegion)
		EXPORTED_FUNCTION(PsGetCurrentThread)
		EXPORTED_FUNCTION_TYPE(ZwAllocateVirtualMemory, NTSTATUS(*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG))
		EXPORTED_FUNCTION_TYPE(ZwFreeVirtualMemory, NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG))
		EXPORTED_FUNCTION(KeWaitForSingleObject)
		EXPORTED_FUNCTION(KeDelayExecutionThread)
		EXPORTED_FUNCTION(MmMapIoSpace)
		EXPORTED_FUNCTION(MmUnmapIoSpace)
		EXPORTED_FUNCTION(ExGetFirmwareEnvironmentVariable)
		EXPORTED_FUNCTION(MmGetPhysicalAddress)
		EXPORTED_FUNCTION(KeInitializeEvent)
		EXPORTED_FUNCTION(IoSetCompletionRoutine)
		EXPORTED_FUNCTION(IoAllocateIrp)
		EXPORTED_FUNCTION(IoInitializeIrp)
		EXPORTED_FUNCTION(IoCancelIrp)
		EXPORTED_FUNCTION(IoFreeIrp)
		EXPORTED_FUNCTION(IoReuseIrp)
		EXPORTED_FUNCTION(KeSetEvent)
		EXPORTED_FUNCTION(KeResetEvent)
		EXPORTED_FUNCTION_TYPE(RtlMultiByteToUnicodeSize, NTSTATUS(*)(PULONG, const CHAR*, ULONG))
		EXPORTED_FUNCTION_TYPE(RtlUnicodeToMultiByteSize, NTSTATUS(*)(PULONG, PCWCH, ULONG))
		EXPORTED_FUNCTION_TYPE(RtlMultiByteToUnicodeN, NTSTATUS(*)(PWCH, ULONG, PULONG, const CHAR*, ULONG))
		EXPORTED_FUNCTION_TYPE(RtlUnicodeToMultiByteN, NTSTATUS(*)(PCHAR, ULONG, PULONG, PCWCH, ULONG))
		EXPORTED_FUNCTION(ExAcquireFastMutex)
		EXPORTED_FUNCTION(ExTryToAcquireFastMutex)
		EXPORTED_FUNCTION(ExReleaseFastMutex)
		EXPORTED_FUNCTION(ExAcquireFastMutexUnsafe)
		EXPORTED_FUNCTION(ExReleaseFastMutexUnsafe)
		EXPORTED_FUNCTION(PsGetCurrentProcessId)
		EXPORTED_FUNCTION(KeQuerySystemTimePrecise)
		EXPORTED_FUNCTION(ExLocalTimeToSystemTime)
		EXPORTED_FUNCTION(ExSystemTimeToLocalTime)
		EXPORTED_FUNCTION_TYPE(RtlTimeToSecondsSince1970, BOOLEAN(*)(PLARGE_INTEGER, PULONG))
		EXPORTED_FUNCTION(KeExpandKernelStackAndCallout)

		EXPORTED_FUNCTION_TYPE(HalEnumerateEnvironmentVariablesEx, NTSTATUS(*)(ULONG, PVOID, PULONG))
		
		EXPORTED_FUNCTION(BCryptOpenAlgorithmProvider)
		EXPORTED_FUNCTION(BCryptGenRandom)
		EXPORTED_FUNCTION(BCryptCloseAlgorithmProvider)

		EXPORTED_FUNCTION(WskRegister)
		EXPORTED_FUNCTION(WskDeregister)
		EXPORTED_FUNCTION(WskCaptureProviderNPI)
		EXPORTED_FUNCTION(WskReleaseProviderNPI)

		#undef EXPORTED_FUNCTION_TYPE
		#undef EXPORTED_FUNCTION
	}
	namespace Syscalls {
		extern std::uintptr_t
			returnAddress,
			functionIndex;
		extern std::unique_ptr<Framework::Utilities::Hooks::VirtualFunctionTable> dxgkrnlTable;
	}
	namespace Drivers {
		extern std::unique_ptr<Spoofer::Disk> disk;
	}
	namespace NetIo {
		extern WSK_REGISTRATION registration;
		extern WSK_PROVIDER_NPI provider;
		extern WSK_CLIENT_DISPATCH dispatch;

		extern std::unique_ptr<Utilities::Mutex> mutex;
		extern std::unique_ptr<std::map<Miscellaneous::NetIo::SocketIdentifier, Miscellaneous::NetIo::Socket>> sockets;
	}
	namespace Symbols {
		namespace ntoskrnl {
			// All located in: WmipGetSMBiosTableData
			OBFUSCATED_PTR(std::uintptr_t) wmipSMBiosTablePhysicalAddress;
			OBFUSCATED_PTR(std::uint16_t)  wmipSMBiosTableLength;
			OBFUSCATED_PTR(std::uint32_t)  wmipSMBiosVersionInfo;

			// CLASSPNP.SYS
			OBFUSCATED_PTR(std::uintptr_t) pnpDriverObject;

			// Functions
			OBFUSCATED_PTR(std::uintptr_t) forceDumpDisabled; // bool, used for disabling memory dumps

			// Anti debugging
			// TODO: check if any 'oIdK' (KdIo) pages are allocated
			OBFUSCATED_PTR(std::uintptr_t) kdPitchDebugger;                  // Expected to be true
			OBFUSCATED_PTR(std::uintptr_t) kdBlockEnable;                    // Expected to be true
			OBFUSCATED_PTR(std::uintptr_t) kdPreviouslyEnabled;              // Expected to be false
			OBFUSCATED_PTR(std::uintptr_t) kdpDebugRoutineSelect;            // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) kdDebuggerNotPresent;             // Expected to be true
			OBFUSCATED_PTR(std::uintptr_t) kdDebuggerEnabled;                // Expected to be false
			OBFUSCATED_PTR(std::uintptr_t) kdTransportMaxPacketSize;         // Expected to be 0xFA0 (0x480 when being debugged)
			OBFUSCATED_PTR(std::uintptr_t) kdDebugDevice;                    // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) halpDebugPortTable;               // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) kdpLoaderDebuggerBlock;           // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) kdpDebuggerDataListHead;          // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) kdIgnoreUmExceptions;             // Expected to be false
			OBFUSCATED_PTR(std::uintptr_t) kdVersionBlock;                   // TODO: investigate
			OBFUSCATED_PTR(std::uintptr_t) kdPrintBufferAllocateSize;        // Expected to be 0uZ
			OBFUSCATED_PTR(std::uintptr_t) kdPageDebuggerSection;            // Expected to be true
			OBFUSCATED_PTR(std::uintptr_t) kdpBootedNodebug;                 // Expected to be true
			OBFUSCATED_PTR(std::uintptr_t) kdEnteredDebugger;                // Expected to be 0/false
			OBFUSCATED_PTR(std::uintptr_t) kdpDebuggerStructuresInitialized; // Expected to be false
			OBFUSCATED_PTR(std::uintptr_t) kdPortLocked;                     // Expected to be false
			OBFUSCATED_PTR(std::uintptr_t) kdpContext;                       // Expected to be null (16 bytes)
			OBFUSCATED_PTR(std::uintptr_t) kdDebuggerEnteredCount;           // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) kdDebuggerEnteredWithoutLock;     // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) kdpMessageBuffer;                 // Expected to be null (KdTransportMaxPacketSize bytes)
			OBFUSCATED_PTR(std::uintptr_t) kdPrintRolloverCount;             // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) kdPrintDefaultCircularBuffer;     // Expected to be null (KdTransportMaxPacketSize bytes)
			OBFUSCATED_PTR(std::uintptr_t) kdPrintBufferChanges;             // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) kdpBreakpointChangeCount;         // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) kdpPathBuffer;                    // Expected to be null (5 bytes)
			OBFUSCATED_PTR(std::uintptr_t) kiBootDebuggerActive;             // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) kdBreakAfterSymbolLoad;           // Expected to be false
			OBFUSCATED_PTR(std::uintptr_t) kdComPortInUse;                   // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) kdHvComPortInUse;                 // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) kdpTimeSlipEvent;                 // Expected to be nullptr

			// Signing policy
			OBFUSCATED_PTR(std::uintptr_t) seCiDebugOptions;                 // Expected to be 0
			OBFUSCATED_PTR(std::uintptr_t) seILSigningPolicy;                // TODO: investigate

			// Hypervisors
			OBFUSCATED_PTR(std::uintptr_t) hvcallpNoHypervisorPresent;
			OBFUSCATED_PTR(std::uintptr_t) hvcallCodeVa;                     // Expected to be `HvcallpNoHypervisorPresent`
			OBFUSCATED_PTR(std::uintptr_t) hvlpFlags;                        // Expected to be 0u (TODO: investigate HvlPhase0Initialize)
			OBFUSCATED_PTR(std::uintptr_t) hvlpRootFlags;                    // Expected to be 0u (TODO: investigate)
			OBFUSCATED_PTR(std::uintptr_t) hvlHypervisorConnected;           // Expected to be false
			OBFUSCATED_PTR(std::uintptr_t) hvlEnableIdleYield;               // Expected to be true
			OBFUSCATED_PTR(std::uintptr_t) hvlpVsmVtlCallVa;                 // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) hvlpHypercallCodeVa;              // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) vslpNestedPageProtectionFlags;    // Expected to be 0 (TODO: investigate)
			OBFUSCATED_PTR(std::uintptr_t) hvlpReferenceTscPage;             // Expected to be nullptr
			OBFUSCATED_PTR(std::uintptr_t) hvlpHypervisorVersion;            // Expected to be null (16 bytes)
			
			namespace ethread {
				// _ETHREAD::Tcb
				OBFUSCATED_PTR(std::size_t) tcb;
				// _ETHREAD::StartAddress
				OBFUSCATED_PTR(std::size_t) startAddress;
				// _ETHREAD::Win32StartAddress
				OBFUSCATED_PTR(std::size_t) win32StartAddress;
			}
			namespace kthread {
				// _KTHREAD::InitialStack
				OBFUSCATED_PTR(std::size_t) initialStack;
				// _KTHREAD::StackLimit
				OBFUSCATED_PTR(std::size_t) stackLimit;
				// _KTHREAD::StackBase
				OBFUSCATED_PTR(std::size_t) stackBase;
				// _KTHREAD::SystemCallNumber
				OBFUSCATED_PTR(std::size_t) systemCallNumber;
				// _KTHREAD::TrapFrame
				OBFUSCATED_PTR(std::size_t) trapFrame;
			}
		}
		namespace dxgkrnl {
			// DXGGLOBAL::m_pGlobal
			OBFUSCATED_PTR(std::uintptr_t) global;
		}
		namespace classpnp {
			// _COMMON_DEVICE_EXTENSION::DispatchTable
			OBFUSCATED_PTR(std::ptrdiff_t) commonDeviceExtensionDispatchTable;
		}

		void resolveSymbols(void *successful);
		void cleanup();
	}
	namespace Hardware {
		OBFUSCATED_PTR(hwid::HardwareId) hardwareId;
	}
	#undef OBFUSCATED_PTR

	bool initialize() noexcept;
}
