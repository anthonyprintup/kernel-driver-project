// ReSharper disable CppInconsistentNaming
// ReSharper disable IdentifierTypo
#pragma once

#include <ntddk.h>
#include <windef.h>
#include <wsk.h>

constexpr auto IMAGE_DOS_SIGNATURE {0x5A4D};
constexpr auto IMAGE_NT_SIGNATURE  {0x4550};
#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER)  \
    ((ULONG_PTR)(ntheader) +                                      \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +           \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
typedef struct _IMAGE_SECTION_HEADER {
	BYTE  Name[8];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
typedef struct _IMAGE_DEBUG_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD  MajorVersion;
	WORD  MinorVersion;
	DWORD Type;
	DWORD SizeOfData;
	DWORD AddressOfRawData;
	DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD   Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        PBYTE ForwarderString;
        PDWORD Function;
        ULONGLONG Ordinal;
        PIMAGE_IMPORT_BY_NAME AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;
typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
typedef struct _IDSECTOR {
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[3];
	CHAR    sSerialNumber[20];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[8];
	CHAR    sModelNumber[40];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[128];
} IDSECTOR, *PIDSECTOR;
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
struct MemoryBasicInformationType {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
};
typedef struct KAPC_STATE_T {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS *Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE_T, *PKAPC_STATE_T;
struct _ACTIVATION_CONTEXT_STACK {
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;                //0x0
    struct _LIST_ENTRY FrameListCache;                                      //0x8
    ULONG Flags;                                                            //0x18
    ULONG NextCookieSequenceNumber;                                         //0x1c
    ULONG StackId;                                                          //0x20
};
struct _GDI_TEB_BATCH {
    ULONG Offset:31;                                                        //0x0
    ULONG HasRenderingCommand:1;                                            //0x0
    ULONGLONG HDC;                                                          //0x8
    ULONG Buffer[310];                                                      //0x10
}; 
struct _TEB {
    struct _NT_TIB NtTib;                                                   //0x0
    VOID* EnvironmentPointer;                                               //0x38
    struct _CLIENT_ID ClientId;                                             //0x40
    VOID* ActiveRpcHandle;                                                  //0x50
    VOID* ThreadLocalStoragePointer;                                        //0x58
    struct _PEB* ProcessEnvironmentBlock;                                   //0x60
    ULONG LastErrorValue;                                                   //0x68
    ULONG CountOfOwnedCriticalSections;                                     //0x6c
    VOID* CsrClientThread;                                                  //0x70
    VOID* Win32ThreadInfo;                                                  //0x78
    ULONG User32Reserved[26];                                               //0x80
    ULONG UserReserved[5];                                                  //0xe8
    VOID* WOW32Reserved;                                                    //0x100
    ULONG CurrentLocale;                                                    //0x108
    ULONG FpSoftwareStatusRegister;                                         //0x10c
    VOID* ReservedForDebuggerInstrumentation[16];                           //0x110
    VOID* SystemReserved1[30];                                              //0x190
    CHAR PlaceholderCompatibilityMode;                                      //0x280
    UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
    CHAR PlaceholderReserved[10];                                           //0x282
    ULONG ProxiedProcessId;                                                 //0x28c
    struct _ACTIVATION_CONTEXT_STACK _ActivationStack;                      //0x290
    UCHAR WorkingOnBehalfTicket[8];                                         //0x2b8
    LONG ExceptionCode;                                                     //0x2c0
    UCHAR Padding0[4];                                                      //0x2c4
    struct _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;        //0x2c8
    ULONGLONG InstrumentationCallbackSp;                                    //0x2d0
    ULONGLONG InstrumentationCallbackPreviousPc;                            //0x2d8
    ULONGLONG InstrumentationCallbackPreviousSp;                            //0x2e0
    ULONG TxFsContext;                                                      //0x2e8
    UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
    UCHAR UnalignedLoadStoreExceptions;                                     //0x2ed
    UCHAR Padding1[2];                                                      //0x2ee
    struct _GDI_TEB_BATCH GdiTebBatch;                                      //0x2f0
    struct _CLIENT_ID RealClientId;                                         //0x7d8
    VOID* GdiCachedProcessHandle;                                           //0x7e8
    ULONG GdiClientPID;                                                     //0x7f0
    ULONG GdiClientTID;                                                     //0x7f4
    VOID* GdiThreadLocalInfo;                                               //0x7f8
    ULONGLONG Win32ClientInfo[62];                                          //0x800
    VOID* glDispatchTable[233];                                             //0x9f0
    ULONGLONG glReserved1[29];                                              //0x1138
    VOID* glReserved2;                                                      //0x1220
    VOID* glSectionInfo;                                                    //0x1228
    VOID* glSection;                                                        //0x1230
    VOID* glTable;                                                          //0x1238
    VOID* glCurrentRC;                                                      //0x1240
    VOID* glContext;                                                        //0x1248
    ULONG LastStatusValue;                                                  //0x1250
    UCHAR Padding2[4];                                                      //0x1254
    struct _UNICODE_STRING StaticUnicodeString;                             //0x1258
    WCHAR StaticUnicodeBuffer[261];                                         //0x1268
    UCHAR Padding3[6];                                                      //0x1472
    VOID* DeallocationStack;                                                //0x1478
    VOID* TlsSlots[64];                                                     //0x1480
    struct _LIST_ENTRY TlsLinks;                                            //0x1680
    VOID* Vdm;                                                              //0x1690
    VOID* ReservedForNtRpc;                                                 //0x1698
    VOID* DbgSsReserved[2];                                                 //0x16a0
    ULONG HardErrorMode;                                                    //0x16b0
    UCHAR Padding4[4];                                                      //0x16b4
    VOID* Instrumentation[11];                                              //0x16b8
    struct _GUID ActivityId;                                                //0x1710
    VOID* SubProcessTag;                                                    //0x1720
    VOID* PerflibData;                                                      //0x1728
    VOID* EtwTraceData;                                                     //0x1730
    VOID* WinSockData;                                                      //0x1738
    ULONG GdiBatchCount;                                                    //0x1740
    union
    {
        struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
        ULONG IdealProcessorValue;                                          //0x1744
        struct
        {
            UCHAR ReservedPad0;                                             //0x1744
            UCHAR ReservedPad1;                                             //0x1745
            UCHAR ReservedPad2;                                             //0x1746
            UCHAR IdealProcessor;                                           //0x1747
        };
    };
    ULONG GuaranteedStackBytes;                                             //0x1748
    UCHAR Padding5[4];                                                      //0x174c
    VOID* ReservedForPerf;                                                  //0x1750
    VOID* ReservedForOle;                                                   //0x1758
    ULONG WaitingOnLoaderLock;                                              //0x1760
    UCHAR Padding6[4];                                                      //0x1764
    VOID* SavedPriorityState;                                               //0x1768
    ULONGLONG ReservedForCodeCoverage;                                      //0x1770
    VOID* ThreadPoolData;                                                   //0x1778
    VOID** TlsExpansionSlots;                                               //0x1780
    VOID* DeallocationBStore;                                               //0x1788
    VOID* BStoreLimit;                                                      //0x1790
    ULONG MuiGeneration;                                                    //0x1798
    ULONG IsImpersonating;                                                  //0x179c
    VOID* NlsCache;                                                         //0x17a0
    VOID* pShimData;                                                        //0x17a8
    ULONG HeapData;                                                         //0x17b0
    UCHAR Padding7[4];                                                      //0x17b4
    VOID* CurrentTransactionHandle;                                         //0x17b8
    struct _TEB_ACTIVE_FRAME* ActiveFrame;                                  //0x17c0
    VOID* FlsData;                                                          //0x17c8
    VOID* PreferredLanguages;                                               //0x17d0
    VOID* UserPrefLanguages;                                                //0x17d8
    VOID* MergedPrefLanguages;                                              //0x17e0
    ULONG MuiImpersonation;                                                 //0x17e8
    union
    {
        volatile USHORT CrossTebFlags;                                      //0x17ec
        USHORT SpareCrossTebBits:16;                                        //0x17ec
    };
    union
    {
        USHORT SameTebFlags;                                                //0x17ee
        struct
        {
            USHORT SafeThunkCall:1;                                         //0x17ee
            USHORT InDebugPrint:1;                                          //0x17ee
            USHORT HasFiberData:1;                                          //0x17ee
            USHORT SkipThreadAttach:1;                                      //0x17ee
            USHORT WerInShipAssertCode:1;                                   //0x17ee
            USHORT RanProcessInit:1;                                        //0x17ee
            USHORT ClonedThread:1;                                          //0x17ee
            USHORT SuppressDebugMsg:1;                                      //0x17ee
            USHORT DisableUserStackWalk:1;                                  //0x17ee
            USHORT RtlExceptionAttached:1;                                  //0x17ee
            USHORT InitialThread:1;                                         //0x17ee
            USHORT SessionAware:1;                                          //0x17ee
            USHORT LoadOwner:1;                                             //0x17ee
            USHORT LoaderWorker:1;                                          //0x17ee
            USHORT SkipLoaderInit:1;                                        //0x17ee
            USHORT SpareSameTebBits:1;                                      //0x17ee
        };
    };
    VOID* TxnScopeEnterCallback;                                            //0x17f0
    VOID* TxnScopeExitCallback;                                             //0x17f8
    VOID* TxnScopeContext;                                                  //0x1800
    ULONG LockCount;                                                        //0x1808
    LONG WowTebOffset;                                                      //0x180c
    VOID* ResourceRetValue;                                                 //0x1810
    VOID* ReservedForWdf;                                                   //0x1818
    ULONGLONG ReservedForCrt;                                               //0x1820
    struct _GUID EffectiveContainerId;                                      //0x1828
};
using PTEB = _TEB*;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation, // q: RTL_PROCESS_LOCKS
	SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q
	SystemVdmBopInformation, // not implemented // 20
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented
	SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
	SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q
	SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q
	SystemComPlusPackage, // q; s
	SystemNumaAvailableMemory, // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
	SystemObjectSecurityMode, // q: ULONG // 70
	SystemWatchdogTimerHandler, // s (kernel-mode only)
	SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
	SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation, // q; s (kernel-mode only)
	SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
	SystemPrefetchPatchInformation, // not implemented
	SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
	SystemNumaProximityNodeInformation,
	SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s
	SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION // SmQueryStoreInformation
	SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
	SystemNativeBasicInformation, // not implemented
	SystemSpare1, // not implemented
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation,
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
	SystemBadPageInformation,
	SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
	SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
	SystemSpare0,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation, // q: ULONG
	SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
	SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation,
	SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
	SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation,
	SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation, // 180
	SystemSupportedProcessorArchitectures,
	SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
	SystemControlFlowTransition,
	SystemKernelDebuggingAllowed, // s: ULONG
	SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
	SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemIntegrityQuotaInformation,
	SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
	SystemProcessorIdleMaskInformation, // q: ULONG_PTR // since REDSTONE3
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
	SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
	SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
	SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
	SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
	SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
	SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
	SystemCodeIntegrityUnlockModeInformation,
	SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
	SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
	SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
	SystemCodeIntegritySyntheticCacheInformation,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION {
    struct {
        ULONG KvaShadowEnabled:1;
        ULONG KvaShadowUserGlobal:1;
        ULONG KvaShadowPcid:1;
        ULONG KvaShadowInvpcid:1;
        ULONG KvaShadowRequired:1;
        ULONG KvaShadowRequiredAvailable:1;
        ULONG InvalidPteBit:6;
        ULONG L1DataCacheFlushSupported:1;
        ULONG L1TerminalFaultMitigationPresent:1;
        ULONG Reserved:18;
    } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, * PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;
typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;
typedef VOID (*PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID KKERNEL_ROUTINE(PRKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2);
typedef KKERNEL_ROUTINE (*PKKERNEL_ROUTINE);
typedef VOID (*PKRUNDOWN_ROUTINE)(PRKAPC Apc);

struct _CURDIR {
	_UNICODE_STRING DosPath;
	VOID* Handle;
};
struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	_STRING DosPath;
};
struct RtlUserProcessParameters64 {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	VOID* ConsoleHandle;
	ULONG ConsoleFlags;
	VOID* StandardInput;
	VOID* StandardOutput;
	VOID* StandardError;
	_CURDIR CurrentDirectory;
	_UNICODE_STRING DllPath;
	_UNICODE_STRING ImagePathName;
	_UNICODE_STRING CommandLine;
	VOID* Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	_UNICODE_STRING WindowTitle;
	_UNICODE_STRING DesktopInfo;
	_UNICODE_STRING ShellInfo;
	_UNICODE_STRING RuntimeData;
	_RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONGLONG EnvironmentSize;
	ULONGLONG EnvironmentVersion;
	VOID* PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
	_UNICODE_STRING RedirectionDllName;
	_UNICODE_STRING HeapPartitionName;
	ULONGLONG* DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
	ULONG DefaultThreadpoolThreadMaximum;
};
typedef struct _EWOW64PROCESS {
	VOID* Peb;
	USHORT Machine;
	enum _SYSTEM_DLL_TYPE NtdllType;
} EWOW64PROCESS, *PEWOW64PROCESS;
