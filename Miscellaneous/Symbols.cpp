// ReSharper disable CppClangTidyCppcoreguidelinesMacroUsage
#include <ranges>

#include "Globals.hpp"
namespace globals = KM::Miscellaneous::Globals;
namespace symbols = globals::Symbols;

#include <Framework/Utilities/Strings/XorStr.hpp>
#include <Framework/Utilities/Strings/Fnv1A.hpp>

#include "Pdb/msf/Pdb.hpp"
#include "Pdb/Cache.hpp"

#include "../Utilities/NT/NT.hpp"
namespace nt = KM::Utilities::NT;

#include "Net IO/TLS/Client/Client.hpp"
#include "Net IO/HTTP/Client.hpp"
#include "Net IO/TLS/Crypto/Hashes.hpp"

#include "Security/Hardware Id.hpp"
namespace hwid = KM::Miscellaneous::hwid;

#include "../Utilities/Strings.hpp"
namespace strings = KM::Utilities::Strings;

namespace libtomcrypt {
	extern int chacha20PrngIdentifier;
}

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments ...arguments) {
	if constexpr (Configuration::print) {
		VM_SIZE_BEGIN
		globals::NT::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), arguments...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

namespace detail {
	namespace files {
		struct Header {
			tls::BitArray<512> hash {}; // hmac sha512 hash of the data
			std::size_t entries {};     // Amount of entries
			std::size_t size {};        // Expected file size
		};
		enum struct EntryIdentifier: std::uint64_t {
			NTOSKRNL = Fnv1A("ntoskrnl.exe") + Fnv1A("\xc1\x23\x7a\x84\x72\x2c\xb7\xe8"),
			DXGKRNL  = Fnv1A("dxgkrnl.sys")  + Fnv1A("\xe3\xf1\xfe\x43\xcc\xae\xc8\x98"),
			CLASSPNP = Fnv1A("CLASSPNP.SYS") + Fnv1A("\xf2\x63\xc1\x99\xb6\x35\x97\xaa")
		};
		struct Entry {
			EntryIdentifier identifier {}; // Unique data identifier
			std::size_t offset {};         // Offset to data
			std::size_t size {};           // Size of data
		};
	}

	__declspec(noinline) void allocateSymbols();
	__declspec(noinline) bool resolveNtSymbols(tls::SpanType pdbBytes);
	__declspec(noinline) bool resolveDirectXSymbols(tls::SpanType pdbBytes);
	__declspec(noinline) bool resolveClassPnpSymbols(tls::SpanType pdbBytes);
	__declspec(noinline) std::optional<tls::aes::DecryptedDataType> downloadSymbols(std::uintptr_t moduleBase);

	using FileNameBuffer = tls::Array<8 + 4>; // 8 random characters + '.' + 3 random characters
	__declspec(noinline) FileNameBuffer generateFileName(std::wstring_view username);
	__declspec(noinline) tls::VectorType readCacheFile(tls::SpanType secretKeyBuffer);
	__declspec(noinline) void parseCacheFile(bool &successful, tls::SpanType secretKeyBuffer);

	using InitializerList = std::initializer_list<std::pair<files::EntryIdentifier, const tls::SpanType>>;
	__declspec(noinline) void writeCacheFile(tls::SpanType secretKeyBuffer, InitializerList pdbs);
}

void symbols::resolveSymbols(void *successful) {
	VM_MAXIMUM_BEGIN
	// Allocate the symbol objects
	detail::allocateSymbols();

	// Read the cache file, if it exists
	{
		// With the secret key we're trying to verify the caller
		auto secretKey = xorstr(
			"\x4a\x80\x60\x06\xdf\x43\x89\x17\xb7\x38\x47\x89\xf0\xb5\xe1\x09"
			"\x7d\xe3\xfe\x93\xe0\xfe\xb2\x6e\xa2\xdd\xa0\xbf\x93\xc9\x6b\xa2"
			"\x45\x62\xcb\x21\x35\x67\xd0\x36\x50\x54\x79\x56\xe1\x15\xc6\x46"
			"\xe2\xda\xf6\x3e\x7d\x85\xf5\xb0\xba\x9b\x28\x08\x7b\x00\xb2\x92");
		bool parsingSuccessful {};
		detail::parseCacheFile(parsingSuccessful, {reinterpret_cast<const tls::UnderlyingDataType*>(secretKey.crypt_get()), secretKey.size()});
		secretKey.crypt();

		// The symbols were successfully parsed from the cache file
		if (parsingSuccessful) {
			*static_cast<bool*>(successful) = true;
			return;
		}
	}

	// Cache file doesn't exist, or was outdated
	// ntoskrnl
	const auto ntoskrnl = nt::Kernel::ntoskrnl();
	const auto ntoskrnlPdb = detail::downloadSymbols(ntoskrnl);
	if (!ntoskrnlPdb) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Unable to download the NT kernel pdb."));
		return;
	}
	if (!detail::resolveNtSymbols(ntoskrnlPdb.value())) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Failed to resolve NT kernel symbols."));
		return;
	}

	// dxgkrnl
	const auto [dxgkrnl, dxgkrnlSize] = nt::Kernel::module(Fnv1A("dxgkrnl.sys"));
	const auto dxgkrnlPdb = detail::downloadSymbols(dxgkrnl);
	if (!dxgkrnlPdb) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Unable to download the DirextX pdb."));
		return;
	}
	if (!detail::resolveDirectXSymbols(dxgkrnlPdb.value())) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Failed to resolve DirectX symbols."));
		return;
	}


	const auto [classPnp, classPnpSize] = nt::Kernel::module(Fnv1A("CLASSPNP.SYS"));
	const auto classPnpPdb = detail::downloadSymbols(classPnp);
	if (!classPnpPdb) {
		if constexpr (Configuration::print)
			print(xorstr_("Failed to download symbols from CLASSPNP.SYS."));
		return;
	}
	if (!detail::resolveClassPnpSymbols(classPnpPdb.value())) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Failed to resolve CLASSPNP symbols."));
		return;
	}

	// Write the downloaded symbols to the cache file
	{
		using detail::files::EntryIdentifier;
		// With the secret key we're trying to verify the caller
		auto secretKey = xorstr(
			"\xac\x5b\x8e\x95\xd1\xa9\xdd\x74\xf3\x2e\xbe\xda\xe0\xd3\x9b\x62"
			"\xce\x13\xb3\xc6\xae\x6c\x14\xfc\x00\x9d\x7f\xd5\x22\x56\x51\x84"
			"\x0d\x39\xa4\x66\xe0\x74\xd3\x0e\x38\x81\x75\x5a\x55\x2d\xef\x50"
			"\xa6\x72\xd1\x9b\x3e\x96\x7e\x48\xfe\x88\x34\xac\xa2\x21\x22\xcd");
		detail::writeCacheFile({reinterpret_cast<const tls::UnderlyingDataType*>(secretKey.crypt_get()), secretKey.size()},
			{{EntryIdentifier::NTOSKRNL, ntoskrnlPdb.value()},
			 {EntryIdentifier::DXGKRNL,  dxgkrnlPdb.value()},
			 {EntryIdentifier::CLASSPNP, classPnpPdb.value()}});
		secretKey.crypt();
	}

	*static_cast<bool*>(successful) = true;
	VM_MAXIMUM_END
}

void symbols::cleanup() {
	{
		using namespace ntoskrnl;
		wmipSMBiosTablePhysicalAddress.reset();
		wmipSMBiosTableLength.reset();
		wmipSMBiosVersionInfo.reset();
		pnpDriverObject.reset();
		forceDumpDisabled.reset();
		kdPitchDebugger.reset();
		kdBlockEnable.reset();
		kdPreviouslyEnabled.reset();
		kdpDebugRoutineSelect.reset();
		kdDebuggerNotPresent.reset();
		kdDebuggerEnabled.reset();
		kdTransportMaxPacketSize.reset();
		kdDebugDevice.reset();
		halpDebugPortTable.reset();
		kdpLoaderDebuggerBlock.reset();
		kdpDebuggerDataListHead.reset();
		kdIgnoreUmExceptions.reset();
		kdVersionBlock.reset();
		kdPrintBufferAllocateSize.reset();
		kdPageDebuggerSection.reset();
		kdpBootedNodebug.reset();
		kdEnteredDebugger.reset();
		kdpDebuggerStructuresInitialized.reset();
		kdPortLocked.reset();
		kdpContext.reset();
		kdDebuggerEnteredCount.reset();
		kdDebuggerEnteredWithoutLock.reset();
		kdpMessageBuffer.reset();
		kdPrintRolloverCount.reset();
		kdPrintDefaultCircularBuffer.reset();
		kdPrintBufferChanges.reset();
		kdpBreakpointChangeCount.reset();
		kdpPathBuffer.reset();
		kiBootDebuggerActive.reset();
		kdBreakAfterSymbolLoad.reset();
		kdComPortInUse.reset();
		kdHvComPortInUse.reset();
		kdpTimeSlipEvent.reset();
		seCiDebugOptions.reset();
		seILSigningPolicy.reset();
		hvcallpNoHypervisorPresent.reset();
		hvcallCodeVa.reset();
		hvlpFlags.reset();
		hvlpRootFlags.reset();
		hvlHypervisorConnected.reset();
		hvlEnableIdleYield.reset();
		hvlpVsmVtlCallVa.reset();
		hvlpHypercallCodeVa.reset();
		vslpNestedPageProtectionFlags.reset();
		hvlpReferenceTscPage.reset();
		hvlpHypervisorVersion.reset();

		ethread::tcb.reset();
		ethread::startAddress.reset();
		ethread::win32StartAddress.reset();

		kthread::initialStack.reset();
		kthread::stackLimit.reset();
		kthread::stackBase.reset();
		kthread::systemCallNumber.reset();
		kthread::trapFrame.reset();
	}
	{
		using namespace dxgkrnl;
		global.reset();
	}
	{
		using namespace classpnp;
		commonDeviceExtensionDispatchTable.reset();
	}
}

void detail::allocateSymbols() {
	VM_MAXIMUM_BEGIN
	#define ALLOCATE_PTR(x) x = std::make_unique<decltype(x)::element_type>();

	using namespace globals::Symbols;
	ALLOCATE_PTR(ntoskrnl::wmipSMBiosTablePhysicalAddress)
	ALLOCATE_PTR(ntoskrnl::wmipSMBiosTableLength)
	ALLOCATE_PTR(ntoskrnl::wmipSMBiosVersionInfo)

	ALLOCATE_PTR(ntoskrnl::pnpDriverObject)

	ALLOCATE_PTR(ntoskrnl::forceDumpDisabled)

	ALLOCATE_PTR(ntoskrnl::kdPitchDebugger)
	ALLOCATE_PTR(ntoskrnl::kdBlockEnable)
	ALLOCATE_PTR(ntoskrnl::kdPreviouslyEnabled)
	ALLOCATE_PTR(ntoskrnl::kdpDebugRoutineSelect)
	ALLOCATE_PTR(ntoskrnl::kdDebuggerNotPresent)
	ALLOCATE_PTR(ntoskrnl::kdDebuggerEnabled)
	ALLOCATE_PTR(ntoskrnl::kdTransportMaxPacketSize)
	ALLOCATE_PTR(ntoskrnl::kdDebugDevice)
	ALLOCATE_PTR(ntoskrnl::halpDebugPortTable)
	ALLOCATE_PTR(ntoskrnl::kdpLoaderDebuggerBlock)
	ALLOCATE_PTR(ntoskrnl::kdpDebuggerDataListHead)
	ALLOCATE_PTR(ntoskrnl::kdIgnoreUmExceptions)
	ALLOCATE_PTR(ntoskrnl::kdVersionBlock)
	ALLOCATE_PTR(ntoskrnl::kdPrintBufferAllocateSize)
	ALLOCATE_PTR(ntoskrnl::kdPageDebuggerSection)
	ALLOCATE_PTR(ntoskrnl::kdpBootedNodebug)
	ALLOCATE_PTR(ntoskrnl::kdEnteredDebugger)
	ALLOCATE_PTR(ntoskrnl::kdpDebuggerStructuresInitialized)
	ALLOCATE_PTR(ntoskrnl::kdPortLocked)
	ALLOCATE_PTR(ntoskrnl::kdpContext)
	ALLOCATE_PTR(ntoskrnl::kdDebuggerEnteredCount)
	ALLOCATE_PTR(ntoskrnl::kdDebuggerEnteredWithoutLock)
	ALLOCATE_PTR(ntoskrnl::kdpMessageBuffer)
	ALLOCATE_PTR(ntoskrnl::kdPrintRolloverCount)
	ALLOCATE_PTR(ntoskrnl::kdPrintDefaultCircularBuffer)
	ALLOCATE_PTR(ntoskrnl::kdPrintBufferChanges)
	ALLOCATE_PTR(ntoskrnl::kdpBreakpointChangeCount)
	ALLOCATE_PTR(ntoskrnl::kdpPathBuffer)
	ALLOCATE_PTR(ntoskrnl::kiBootDebuggerActive)
	ALLOCATE_PTR(ntoskrnl::kdBreakAfterSymbolLoad)
	ALLOCATE_PTR(ntoskrnl::kdComPortInUse)
	ALLOCATE_PTR(ntoskrnl::kdHvComPortInUse)
	ALLOCATE_PTR(ntoskrnl::kdpTimeSlipEvent)

	ALLOCATE_PTR(ntoskrnl::seCiDebugOptions)
	ALLOCATE_PTR(ntoskrnl::seILSigningPolicy)

	ALLOCATE_PTR(ntoskrnl::hvcallpNoHypervisorPresent)
	ALLOCATE_PTR(ntoskrnl::hvcallCodeVa)
	ALLOCATE_PTR(ntoskrnl::hvlpFlags)
	ALLOCATE_PTR(ntoskrnl::hvlpRootFlags)
	ALLOCATE_PTR(ntoskrnl::hvlHypervisorConnected)
	ALLOCATE_PTR(ntoskrnl::hvlEnableIdleYield)
	ALLOCATE_PTR(ntoskrnl::hvlpVsmVtlCallVa)
	ALLOCATE_PTR(ntoskrnl::hvlpHypercallCodeVa)
	ALLOCATE_PTR(ntoskrnl::vslpNestedPageProtectionFlags)
	ALLOCATE_PTR(ntoskrnl::hvlpReferenceTscPage)
	ALLOCATE_PTR(ntoskrnl::hvlpHypervisorVersion)

	ALLOCATE_PTR(ntoskrnl::ethread::tcb)
	ALLOCATE_PTR(ntoskrnl::ethread::startAddress)
	ALLOCATE_PTR(ntoskrnl::ethread::win32StartAddress)

	ALLOCATE_PTR(ntoskrnl::kthread::initialStack)
	ALLOCATE_PTR(ntoskrnl::kthread::stackLimit)
	ALLOCATE_PTR(ntoskrnl::kthread::stackBase)
	ALLOCATE_PTR(ntoskrnl::kthread::systemCallNumber)
	ALLOCATE_PTR(ntoskrnl::kthread::trapFrame)

	ALLOCATE_PTR(dxgkrnl::global)

	ALLOCATE_PTR(classpnp::commonDeviceExtensionDispatchTable)

	#undef ALLOCATE_PTR
	VM_MAXIMUM_END
}
bool detail::resolveNtSymbols(const tls::SpanType pdbBytes) {
	VM_MAXIMUM_BEGIN
	const auto ntoskrnl = nt::Kernel::ntoskrnl();
	const auto pdb = msf::load(pdbBytes);
	if (!pdb) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Unable to parse the NT kernel pdb."));
		return false;
	}

	// Verify the guid
	const auto codeViewDebugInformation = nt::PE::codeViewDebugInformation(ntoskrnl);
	if (const auto infoHeader = pdb->infoStream()->header();
		std::memcmp(&codeViewDebugInformation->guid, &infoHeader->guid, sizeof(GUID)) != 0)
		return false;

	using namespace msf::types;
	const auto &sectionHeaders = pdb->debugInformationStream()->sectionHeaders();
	pdb->symbolRecords()->iterate([&](const PublicSymbol32 &symbol) {
		VM_MEDIUM_BEGIN
		if (symbol.segment >= sectionHeaders.size())
			return;

		const Hash symbolNameHash {symbol.name()};
		const auto sectionOffset = sectionHeaders[symbol.segment - 1].virtualAddress;
		const auto offset = sectionOffset + symbol.offset;

		using namespace symbols::ntoskrnl;
		if (symbolNameHash == Fnv1A("WmipSMBiosTablePhysicalAddress"))
			*wmipSMBiosTablePhysicalAddress = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("WmipSMBiosTableLength"))
			*wmipSMBiosTableLength = *reinterpret_cast<std::uint16_t*>(ntoskrnl + offset);
		else if (symbolNameHash == Fnv1A("WmipSMBiosVersionInfo"))
			*wmipSMBiosVersionInfo = *reinterpret_cast<std::uint32_t*>(ntoskrnl + offset);
		else if (symbolNameHash == Fnv1A("PnpDriverObject"))
			*pnpDriverObject = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("ForceDumpDisabled"))
			*forceDumpDisabled = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPitchDebugger"))
			*kdPitchDebugger = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdBlockEnable"))
			*kdBlockEnable = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPreviouslyEnabled"))
			*kdPreviouslyEnabled = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpDebugRoutineSelect"))
			*kdpDebugRoutineSelect = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdDebuggerNotPresent"))
			*kdDebuggerNotPresent = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdDebuggerEnabled"))
			*kdDebuggerEnabled = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdTransportMaxPacketSize"))
			*kdTransportMaxPacketSize = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdDebugDevice"))
			*kdDebugDevice = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HalpDebugPortTable"))
			*halpDebugPortTable = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpLoaderDebuggerBlock"))
			*kdpLoaderDebuggerBlock = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpDebuggerDataListHead"))
			*kdpDebuggerDataListHead = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdIgnoreUmExceptions"))
			*kdIgnoreUmExceptions = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdVersionBlock"))
			*kdVersionBlock = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPrintBufferAllocateSize"))
			*kdPrintBufferAllocateSize = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPageDebuggerSection"))
			*kdPageDebuggerSection = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpBootedNodebug"))
			*kdpBootedNodebug = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdEnteredDebugger"))
			*kdEnteredDebugger = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpDebuggerStructuresInitialized"))
			*kdpDebuggerStructuresInitialized = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPortLocked"))
			*kdPortLocked = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpContext"))
			*kdpContext = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdDebuggerEnteredCount"))
			*kdDebuggerEnteredCount = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdDebuggerEnteredWithoutLock"))
			*kdDebuggerEnteredWithoutLock = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpMessageBuffer"))
			*kdpMessageBuffer = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPrintRolloverCount"))
			*kdPrintRolloverCount = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPrintDefaultCircularBuffer"))
			*kdPrintDefaultCircularBuffer = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdPrintBufferChanges"))
			*kdPrintBufferChanges = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpBreakpointChangeCount"))
			*kdpBreakpointChangeCount = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpPathBuffer"))
			*kdpPathBuffer = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KiBootDebuggerActive"))
			*kiBootDebuggerActive = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdBreakAfterSymbolLoad"))
			*kdBreakAfterSymbolLoad = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdComPortInUse"))
			*kdComPortInUse = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdHvComPortInUse"))
			*kdHvComPortInUse = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("KdpTimeSlipEvent"))
			*kdpTimeSlipEvent = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("SeCiDebugOptions"))
			*seCiDebugOptions = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("SeILSigningPolicy"))
			*seILSigningPolicy = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvcallpNoHypervisorPresent"))
			*hvcallpNoHypervisorPresent = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvcallCodeVa"))
			*hvcallCodeVa = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlpFlags"))
			*hvlpFlags = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlpRootFlags"))
			*hvlpRootFlags = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlHypervisorConnected"))
			*hvlHypervisorConnected = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlEnableIdleYield"))
			*hvlEnableIdleYield = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlpVsmVtlCallVa"))
			*hvlpVsmVtlCallVa = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlpHypercallCodeVa"))
			*hvlpHypercallCodeVa = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("VslpNestedPageProtectionFlags"))
			*vslpNestedPageProtectionFlags = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlpReferenceTscPage"))
			*hvlpReferenceTscPage = ntoskrnl + offset;
		else if (symbolNameHash == Fnv1A("HvlpHypervisorVersion"))
			*hvlpHypervisorVersion = ntoskrnl + offset;
		VM_MEDIUM_END
	});
	
	// Type Symbols
	{
		const pdb::Cache cache {pdb.value()};

		const auto eThread = cache.structure(Fnv1A("_ETHREAD"));
		const auto kThread = cache.structure(Fnv1A("_KTHREAD"));
		if (!eThread || !kThread) {
			if constexpr (Configuration::print)
				print(xorstr_("[-] Could not find the _ETHREAD or _KTHREAD structures."));
			return false;
		}

		// _ETHREAD
		{
			const auto tcb               = eThread->variable(Fnv1A("Tcb"));
			const auto startAddress      = eThread->variable(Fnv1A("StartAddress"));
			const auto win32StartAddress = eThread->variable(Fnv1A("Win32StartAddress"));
			if (!tcb || !startAddress || !win32StartAddress) {
				if constexpr (Configuration::print)
					print(xorstr_("[-] Could not find the _ETHREAD variables."));
				return false;
			}

			using namespace symbols::ntoskrnl;
			*ethread::tcb               = tcb->offset;
			*ethread::startAddress      = startAddress->offset;
			*ethread::win32StartAddress = win32StartAddress->offset;
		}
		// _KTHREAD
		{
			const auto initialStack     = kThread->variable(Fnv1A("InitialStack"));
			const auto stackLimit       = kThread->variable(Fnv1A("StackLimit"));
			const auto stackBase        = kThread->variable(Fnv1A("StackBase"));
			const auto systemCallNumber = kThread->variable(Fnv1A("SystemCallNumber"));
			const auto trapFrame        = kThread->variable(Fnv1A("TrapFrame"));
			if (!initialStack || !stackLimit || !stackBase || !systemCallNumber || !trapFrame) {
				if constexpr (Configuration::print)
					print(xorstr_("[-] Could not find the _KTHREAD variables."));
				return false;
			}

			using namespace symbols::ntoskrnl;
			*kthread::initialStack     = initialStack->offset;
			*kthread::stackLimit       = stackLimit->offset;
			*kthread::stackBase        = stackBase->offset;
			*kthread::systemCallNumber = systemCallNumber->offset;
			*kthread::trapFrame        = trapFrame->offset;
		}
	}

	using namespace symbols::ntoskrnl;
	if constexpr (Configuration::print) {
		print(xorstr_("WmipSMBiosTablePhysicalAddress:     %p"), **wmipSMBiosTablePhysicalAddress);
		print(xorstr_("WmipSMBiosTableLength:              %p"), **wmipSMBiosTableLength);
		print(xorstr_("WmipSMBiosVersionInfo:              %p"), **wmipSMBiosVersionInfo);
		print(xorstr_("PnpDriverObject:                    %p"), **pnpDriverObject);
		print(xorstr_("ForceDumpDisabled:                  %p"), **forceDumpDisabled);
		print(xorstr_("KdPitchDebugger:                    %p"), **kdPitchDebugger);
		print(xorstr_("KdBlockEnable:                      %p"), **kdBlockEnable);
		print(xorstr_("KdPreviouslyEnabled:                %p"), **kdPreviouslyEnabled);
		print(xorstr_("KdpDebugRoutineSelect:              %p"), **kdpDebugRoutineSelect);
		print(xorstr_("KdDebuggerNotPresent:               %p"), **kdDebuggerNotPresent);
		print(xorstr_("KdDebuggerEnabled:                  %p"), **kdDebuggerEnabled);
		print(xorstr_("KdTransportMaxPacketSize:           %p"), **kdTransportMaxPacketSize);
		print(xorstr_("KdDebugDevice:                      %p"), **kdDebugDevice);
		print(xorstr_("HalpDebugPortTable:                 %p"), **halpDebugPortTable);
		print(xorstr_("KdpLoaderDebuggerBlock:             %p"), **kdpLoaderDebuggerBlock);
		print(xorstr_("KdpDebuggerDataListHead:            %p"), **kdpDebuggerDataListHead);
		print(xorstr_("KdIgnoreUmExceptions:               %p"), **kdIgnoreUmExceptions);
		print(xorstr_("KdVersionBlock:                     %p"), **kdVersionBlock);
		print(xorstr_("KdPrintBufferAllocateSize:          %p"), **kdPrintBufferAllocateSize);
		print(xorstr_("KdPageDebuggerSection:              %p"), **kdPageDebuggerSection);
		print(xorstr_("KdpBootedNodebug:                   %p"), **kdpBootedNodebug);
		print(xorstr_("KdEnteredDebugger:                  %p"), **kdEnteredDebugger);
		print(xorstr_("KdpDebuggerStructuresInitialized:   %p"), **kdpDebuggerStructuresInitialized);
		print(xorstr_("KdPortLocked:                       %p"), **kdPortLocked);
		print(xorstr_("KdpContext:                         %p"), **kdpContext);
		print(xorstr_("KdDebuggerEnteredCount:             %p"), **kdDebuggerEnteredCount);
		print(xorstr_("KdDebuggerEnteredWithoutLock:       %p"), **kdDebuggerEnteredWithoutLock);
		print(xorstr_("KdpMessageBuffer:                   %p"), **kdpMessageBuffer);
		print(xorstr_("KdPrintRolloverCount:               %p"), **kdPrintRolloverCount);
		print(xorstr_("KdPrintDefaultCircularBuffer:       %p"), **kdPrintDefaultCircularBuffer);
		print(xorstr_("KdPrintBufferChanges:               %p"), **kdPrintBufferChanges);
		print(xorstr_("KdpBreakpointChangeCount:           %p"), **kdpBreakpointChangeCount);
		print(xorstr_("KdpPathBuffer:                      %p"), **kdpPathBuffer);
		print(xorstr_("KiBootDebuggerActive:               %p"), **kiBootDebuggerActive);
		print(xorstr_("KdBreakAfterSymbolLoad:             %p"), **kdBreakAfterSymbolLoad);
		print(xorstr_("KdComPortInUse:                     %p"), **kdComPortInUse);
		print(xorstr_("KdHvComPortInUse:                   %p"), **kdHvComPortInUse);
		print(xorstr_("KdpTimeSlipEvent:                   %p"), **kdpTimeSlipEvent);
		print(xorstr_("SeCiDebugOptions:                   %p"), **seCiDebugOptions);
		print(xorstr_("SeILSigningPolicy:                  %p"), **seILSigningPolicy);
		print(xorstr_("HvcallpNoHypervisorPresent:         %p"), **hvcallpNoHypervisorPresent);
		print(xorstr_("HvcallCodeVa:                       %p"), **hvcallCodeVa);
		print(xorstr_("HvlpFlags:                          %p"), **hvlpFlags);
		print(xorstr_("HvlpRootFlags:                      %p"), **hvlpRootFlags);
		print(xorstr_("HvlHypervisorConnected:             %p"), **hvlHypervisorConnected);
		print(xorstr_("HvlEnableIdleYield:                 %p"), **hvlEnableIdleYield);
		print(xorstr_("HvlpVsmVtlCallVa:                   %p"), **hvlpVsmVtlCallVa);
		print(xorstr_("HvlpHypercallCodeVa:                %p"), **hvlpHypercallCodeVa);
		print(xorstr_("VslpNestedPageProtectionFlags:      %p"), **vslpNestedPageProtectionFlags);
		print(xorstr_("HvlpReferenceTscPage:               %p"), **hvlpReferenceTscPage);
		print(xorstr_("HvlpHypervisorVersion:              %p"), **hvlpHypervisorVersion);
		print(xorstr_("_ETHREAD::Tcb:                      %p"), **ethread::tcb);
		print(xorstr_("_ETHREAD::StartAddress:             %p"), **ethread::startAddress);
		print(xorstr_("_ETHREAD::Win32StartAddress:        %p"), **ethread::win32StartAddress);
		print(xorstr_("_KTHREAD::InitialStack:             %p"), **kthread::initialStack);
		print(xorstr_("_KTHREAD::StackLimit:               %p"), **kthread::stackLimit);
		print(xorstr_("_KTHREAD::StackBase:                %p"), **kthread::stackBase);
		print(xorstr_("_KTHREAD::SystemCallNumber:         %p"), **kthread::systemCallNumber);
		print(xorstr_("_KTHREAD::TrapFrame:                %p"), **kthread::trapFrame);
	}

	// Successful flag
	volatile const auto successful =
		**wmipSMBiosTablePhysicalAddress && **wmipSMBiosTableLength            && **wmipSMBiosVersionInfo &&
		**pnpDriverObject                && **forceDumpDisabled                && **kdPitchDebugger &&
		**kdBlockEnable                  && **kdPreviouslyEnabled              && **kdpDebugRoutineSelect &&
		**kdDebuggerNotPresent           && **kdDebuggerEnabled                && **kdTransportMaxPacketSize &&
		**kdDebugDevice                  && **halpDebugPortTable               && **kdpLoaderDebuggerBlock &&
		**kdpDebuggerDataListHead        && **kdIgnoreUmExceptions             && **kdVersionBlock &&
		**kdPrintBufferAllocateSize      && **kdPageDebuggerSection            && **kdpBootedNodebug &&
		**kdEnteredDebugger              && **kdpDebuggerStructuresInitialized && **kdPortLocked &&
		**kdpContext                     && **kdDebuggerEnteredCount           && **kdDebuggerEnteredWithoutLock &&
		**kdpMessageBuffer               && **kdPrintRolloverCount             && **kdPrintDefaultCircularBuffer &&
		**kdPrintBufferChanges           && **kdpBreakpointChangeCount         && **kdpPathBuffer &&
		**kiBootDebuggerActive           && **kdBreakAfterSymbolLoad           && **kdComPortInUse &&
		**kdHvComPortInUse               && **kdpTimeSlipEvent                 && **seCiDebugOptions &&
		**seILSigningPolicy              && **hvcallpNoHypervisorPresent       && **hvcallCodeVa &&
		**hvlpFlags                      && **hvlpRootFlags                    && **hvlHypervisorConnected &&
		**hvlEnableIdleYield             && **hvlpVsmVtlCallVa                 && **hvlpHypercallCodeVa &&
		**vslpNestedPageProtectionFlags  && **hvlpReferenceTscPage             && **hvlpHypervisorVersion &&
		**ethread::tcb == 0              && **ethread::startAddress            && **ethread::win32StartAddress &&
		**kthread::initialStack          && **kthread::stackLimit              && **kthread::stackBase &&
		**kthread::systemCallNumber      && **kthread::trapFrame;
	VM_MAXIMUM_END
	return successful;
}
bool detail::resolveDirectXSymbols(const tls::SpanType pdbBytes) {
	VM_MAXIMUM_BEGIN
	const auto [dxgkrnl, dxgkrnlSize] = nt::Kernel::module(Fnv1A("dxgkrnl.sys"));
	const auto pdb = msf::load(pdbBytes);
	if (!pdb) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Unable to parse the DirextX pdb."));
		return false;
	}

	// Verify the guid
	const auto codeViewDebugInformation = nt::PE::codeViewDebugInformation(dxgkrnl);
	if (const auto infoHeader = pdb->infoStream()->header();
		std::memcmp(&codeViewDebugInformation->guid, &infoHeader->guid, sizeof(GUID)) != 0)
		return false;

	using namespace msf::types;
	const auto &sectionHeaders = pdb->debugInformationStream()->sectionHeaders();
	pdb->symbolRecords()->iterate([&](const PublicSymbol32 &symbol) {
		VM_MEDIUM_BEGIN
		if (symbol.segment >= sectionHeaders.size())
			return true;

		const Hash symbolNameHash {symbol.name()};
		const auto sectionOffset = sectionHeaders[symbol.segment - 1].virtualAddress;
		const auto offset = sectionOffset + symbol.offset;

		using namespace symbols::dxgkrnl;
		if (symbolNameHash == Fnv1A("?m_pGlobal@DXGGLOBAL@@0PEAV1@EA")) { // DXGGlobal::m_pGlobal
			*global = dxgkrnl + offset;
			return false;
		}

		volatile auto result {true};
		VM_MEDIUM_END
		return result;
	});

	using namespace symbols::dxgkrnl;
	if constexpr (Configuration::print) {
		print(xorstr_("DXGGlobal::m_pGlobal:               %p"), **global);
	}
	volatile const auto result = global->decrypt() != nullptr;
	VM_MAXIMUM_END
	return result;
}
bool detail::resolveClassPnpSymbols(const tls::SpanType pdbBytes) {
	VM_MAXIMUM_BEGIN
	const auto pdb = msf::load(pdbBytes);
	if (!pdb) {
		if constexpr (Configuration::print)
			print(xorstr_("Failed to load the CLASSPNP.SYS pdb."));
		return false;
	}

	const auto [classPnp, classPnpSize] = nt::Kernel::module(Fnv1A("CLASSPNP.SYS"));
	// Verify the guid
	const auto codeViewDebugInformation = nt::PE::codeViewDebugInformation(classPnp);
	if (const auto infoHeader = pdb->infoStream()->header();
		std::memcmp(&codeViewDebugInformation->guid, &infoHeader->guid, sizeof(GUID)) != 0)
		return false;

	using namespace msf;
	const pdb::Cache cache {pdb.value()};

	const auto commonDeviceExtension = cache.structure(Fnv1A("_COMMON_DEVICE_EXTENSION"));
	if (!commonDeviceExtension) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Could not find the _COMMON_DEVICE_EXTENSION structure."));
		return false;
	}

	const auto dispatchTable = commonDeviceExtension->variable(Fnv1A("DispatchTable"));
	if (!dispatchTable || dispatchTable->type != UnderlyingType::PROCEDURE) {
		if constexpr (Configuration::print)
			print(xorstr_("[-] Missing or invalid underlying type when resolving _COMMON_DEVICE_EXTENSION::DispatchTable."));
		return false;
	}

	using namespace symbols::classpnp;
	*commonDeviceExtensionDispatchTable = static_cast<std::ptrdiff_t>(dispatchTable->offset);
	if constexpr (Configuration::debug)
		print(xorstr_("COMMON_DEVICE_EXTENSION::DispatchTable: %p"), **commonDeviceExtensionDispatchTable);

	volatile const auto result = **commonDeviceExtensionDispatchTable != 0;
	VM_MAXIMUM_END
	return result;
}
std::optional<tls::aes::DecryptedDataType> detail::downloadSymbols(const std::uintptr_t moduleBase) {
	VM_MAXIMUM_BEGIN
	namespace pe = nt::PE;

	do {
		const auto codeViewDebugInformation = pe::codeViewDebugInformation(moduleBase);
		if (!codeViewDebugInformation) {
			if constexpr (Configuration::print)
				print(xorstr_("[-] Failed to resolve ntoskrnl's debug information."));
			break;
		}
		const auto pdbUrlPath = pe::generatePdbUrlPath(codeViewDebugInformation);
		if (!pdbUrlPath) {
			if constexpr (Configuration::print)
				print(xorstr_("[-] Failed to generate ntoskrnl's pdb url."));
			break;
		}

		auto msdlHost = xorstr("msdl.microsoft.com");
		msdlHost.crypt();

		tls::client::Tls12Client msdlClient {msdlHost.get(), 443};
		http::Request msdlRequest {http::RequestMethod::GET, msdlHost.get(), pdbUrlPath.value()};

		const auto msdlResponseData = msdlClient.send(msdlRequest.build());
		if (msdlResponseData.empty()) {
			if constexpr (Configuration::print)
				print(xorstr_("[-] Failed to retrieve a response from MSDL."));
			break;
		}
		msdlHost.crypt();
		msdlClient.close();

		http::Response msdlResponse {};
		msdlResponse.parse(msdlResponseData);
		if (msdlResponse.statusCode != http::StatusCode::FOUND) {
			if constexpr (Configuration::print)
				print(xorstr_("[!] Unexpected status code from msdl.microsoft.com: %i."), static_cast<std::underlying_type_t<http::StatusCode>>(msdlResponse.statusCode));
			break;
		}

		const auto newLocation = msdlResponse.header(http::HeaderType::LOCATION);
		if (newLocation.empty()) {
			if constexpr (Configuration::print)
				print(xorstr_("[!] Missing Location header from msdl.microsoft.com"));
			break;
		}

		const auto [redirectHost, redirectData] = http::parseUri(newLocation);
		tls::client::Tls12Client cdnClient {redirectHost, 443};
		http::Request cdnRequest {http::RequestMethod::GET, redirectHost, redirectData};
		const auto cdnResponseData = cdnClient.send(cdnRequest.build());

		http::Response cdnResponse {};
		if (auto decryptedContent = cdnResponse.receive(cdnResponseData, cdnClient);
			decryptedContent)
			return decryptedContent;
		if constexpr (Configuration::print)
			print(xorstr_("[!] Failed to receive the PDB from %.*s"), redirectHost.length(), redirectHost.data());
	} while (false);
	VM_MAXIMUM_END
	return std::nullopt;
}

detail::FileNameBuffer detail::generateFileName(const std::wstring_view username) {
	VM_MINIMUM_BEGIN
	const auto efiHwid = hwid::efi();

	libtomcrypt::prng_state prngState {};
	libtomcrypt::chacha20_prng_start(&prngState);
	libtomcrypt::chacha20_prng_add_entropy(efiHwid.data(), static_cast<unsigned long>(hwid::sha512HashSize), &prngState);
	if (!username.empty())
		libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(username.data()), static_cast<unsigned long>(username.length() * sizeof(wchar_t)), &prngState);
	{
		auto staticEntropyBytes = xorstr(
			"\xb8\x2b\x48\x63\xdb\x05\xfc\x61\x91\x68\xe2\x60\x4e\x5c\x33\x86"
			"\x4c\xba\x32\x30\xa6\x26\x1a\x49\x77\x57\x2a\x25\x19\x1d\xd3\x70"
			"\xaf\x98\xde\x60\x4c\x12\x42\x2c\xbf\x4d\xa5\xbb\xb2\x9a\xff\x1d"
			"\x3e\x02\x3b\xfc\x58\xb1\x68\x00\xfa\xbb\xd5\x26\x17\x09\x49\x08"
			"\x9a\x4e\x9f\x85\xd2\x3d\x12\x29\x97\xff\xd1\x77\x5c\xf5\xdc\x1c"
			"\x0c\xb7\xd5\xb2\x1d\x5f\xc8\x9f\xcd\xb7\xb8\xd6\xfb\x1d\x05\x1b"
			"\xeb\x24\x49\x81\xc2\x90\xfa\xb4\xb8\x14\x19\x32\xd4\x49\xb3\x3e"
			"\x4d\xed\xbf\xb9\xc6\x80\xbd\xd0\x31\xe0\x72\x59\x07\x13\x38\x8a"
			"\x08\x3f\xbc\x96\xab\x2e\x40\x83\xaf\xbf\xd0\xee\x7d\xd8\xd2\x02"
			"\x1f\xe9\x45\xf6\x7e\x0f\xe2\x30\x36\xc5\x37\x97\x08\x15\xa9\x50"
			"\x2f\x23\x8a\x50\x09\x13\x70\xaa\x73\x3e\x75\x1c\x9b\x7b\x98\x37"
			"\x6e\x88\xd7\xcc\x4f\xcf\xb1\x80\xd9\xdd\xbe\xc8\xa4\x03\x5c\x53"
			"\x86\xb4\x36\xb2\x98\x58\xcd\xef\x0c\x40\x27\x92\x3b\x3b\x27\x2d"
			"\x87\xc3\x89\xad\x95\x2f\x60\xea\xa7\xaf\xdb\xb5\x93\xca\xdc\x78"
			"\xdb\x43\xf9\x28\x13\xba\x35\xe1\x12\x57\x78\x4c\x81\x50\xd2\xb3"
			"\x72\x86\xa2\xab\x21\x27\x03\xab\x89\x5e\x32\x21\x0f\x4d\x09\xb7"
			"\x50\xcd\xec\x11\x64\x36\xd5\x82\xe7\xf5\x6d\xc7\xbb\x4d\x9b\xab"
			"\x8e\x1b\xe9\xf0\x3d\x91\x58\xe2\xfa\xcc\xa3\x0b\x69\x7a\xf1\x9f"
			"\x13\x43\x6e\xf2\x3d\x54\xf4\xed\x15\x48\x54\x9d\xf1\x66\x6b\x51"
			"\xbc\x3e\x98\x33\xf8\xd6\xce\xec\x1a\xbd\x4b\x8c\x04\xef\x17\xb4"
			"\x63\x90\x05\xf9\xad\xe2\x46\x54\xc5\xa3\xb2\x55\x66\x1a\xf8\x2e"
			"\x87\x16\x2b\x72\xb5\xca\x73\xb3\x3a\x4a\x51\xe6\xae\x7b\x4f\x02"
			"\x0f\x37\x9c\xaf\x2e\x26\x4f\x1c\x7c\x80\xb9\x2e\x0e\xe9\x23\x28"
			"\xb1\xdd\xa6\xac\x86\x4c\x8c\xf1\x4c\xd0\x72\xff\x38\x46\x63\xfc"
			"\xbf\x83\xa8\xe9\x7b\x7d\x18\xdf\xad\xec\xad\xd9\xd0\x77\x5c\x01"
			"\xf8\x78\x05\x92\xae\x65\x88\x42\x6d\xd8\x07\x1f\x0d\x30\x24\x1b"
			"\x0e\x25\x6c\xa1\x6f\x1c\xc6\x8f\xd6\xd8\x1f\x57\x56\x49\x9e\x93"
			"\x25\xb0\xac\x0d\xf3\x53\x1b\x5d\x73\xb1\xa3\xb3\x67\x13\xf2\x63"
			"\xa6\xb5\xd4\x33\x06\xce\x7e\x99\xe7\x8e\x21\x38\x19\x42\xf5\x62"
			"\x7c\xad\x5b\x2c\xab\x70\x3a\x47\xff\x7a\x8e\xeb\x2c\xb2\x2b\x83"
			"\xf9\x53\x2f\xb0\xe3\xf5\xcb\xed\x33\x84\xdc\x4d\x59\xff\xf3\xc3"
			"\x8c\x87\x34\x2b\x05\x78\xf5\x30\x22\x61\x6b\xe7\x63\xcc\x3b\xb2");
		libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(staticEntropyBytes.crypt_get()), 512ul, &prngState);
		staticEntropyBytes.crypt();
	}
	libtomcrypt::chacha20_prng_ready(&prngState);

	FileNameBuffer buffer {};
	libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(buffer.data(), buffer.size(), &prngState);
	libtomcrypt::chacha20_prng_done(&prngState);
	
	for (std::size_t i {}; auto &character : buffer) {
		if (i % 2 == 0)
			character = character % ('9' + 1 - '0') + '0'; // 0-9
		else if (i % 3 == 0)
			character = character % ('Z' + 1 - 'A') + 'A'; // A-Z
		else
			character = character % ('z' + 1 - 'a') + 'a'; // a-z
		++i;
	}

	buffer[buffer.size() - 4] = '.'; // delimiter filename.extension
	VM_MINIMUM_END
	return buffer;
}
tls::VectorType detail::readCacheFile(const tls::SpanType secretKeyBuffer) {
	VM_MINIMUM_BEGIN
	{
		if (secretKeyBuffer.size_bytes() != 64)
			return {};
		auto secretKey = xorstr(
			"\x6e\xa8\x43\xb5\x3e\xde\xc4\x61\x3a\xe3\x70\x8d\xc6\xff\x9a\xa9"
			"\xed\x56\xf1\xf6\x10\x77\xe2\x21\xf3\xee\x08\x82\x17\x73\x9b\x99"
			"\xde\x8a\xa3\x1d\x3f\x0e\x25\xc7\xb7\x21\x1d\x55\x66\x2c\x45\x50"
			"\xed\x4b\xec\xcb\x3e\xb2\x8d\x17\x23\x4a\x99\xb4\xce\x98\xee\xbe");
		if (std::memcmp(secretKey.crypt_get(), secretKeyBuffer.data(), secretKey.size()) != 0) {
			secretKey.crypt();
			return {};
		}
		secretKey.crypt();
	}

	const auto [explorerProcess] = nt::Kernel::process(Hash {Fnv1A("explorer.exe")});

	std::wstring tempPath {}, username {};
	{
		auto prefix = xorstr(LR"(\DosDevices\)");
		tempPath += prefix.crypt_get();
		prefix.crypt();
	}
	auto tempFound {false};
	nt::User::iterateEnvironmentVariables(explorerProcess, [&](const std::wstring_view name, const std::wstring_view value) {
		VM_MINIMUM_BEGIN
		volatile auto shouldContinue {true};
		if (const Hash nameHash {name};
			!tempFound && (nameHash == Fnv1A(L"TEMP") || nameHash == Fnv1A(L"TMP"))) {
			tempPath += value;
			tempFound = true;
		} else if (nameHash == Fnv1A(L"USERNAME"))
			username = value;
		if (tempFound && !username.empty())
			shouldContinue = false;
		VM_MINIMUM_END
		return shouldContinue;
	});
	if (tempPath.empty())
		return {};
	
	const auto fileNameBuffer = generateFileName(username);
	const std::string_view fileName {reinterpret_cast<const char*>(fileNameBuffer.data()), fileNameBuffer.size()};

	auto delimiter = xorstr(LR"(\)");
	const auto filePath = tempPath + delimiter.crypt_get() + strings::unicode(fileName);
	delimiter.crypt();

	const auto [status, fileContents] = nt::Kernel::readFile(filePath);
	if (!NT_SUCCESS(status) || fileContents.empty() || fileContents.size() <= tls::aes::defaultTagLength)
		return {};
	VM_MINIMUM_END
	VM_MAXIMUM_BEGIN
	// Decrypt the file (scoped to prevent destructors leaking out of the VM macro)
	{
		const auto efiHwid = hwid::efi();

		libtomcrypt::prng_state prngState {};
		libtomcrypt::chacha20_prng_start(&prngState);
		libtomcrypt::chacha20_prng_add_entropy(efiHwid.data(), static_cast<unsigned long>(hwid::sha512HashSize), &prngState);
		if (!username.empty())
			libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(username.data()), static_cast<unsigned long>(username.length() * sizeof(wchar_t)), &prngState);
		{
			auto staticEntropyBytes = xorstr(
				"\x04\xb3\xde\x8d\x7e\x8a\xca\xd7\x72\x20\xf5\xf6\xb0\x8d\xaf\xf9"
				"\x54\x31\x5b\xea\xe6\x8d\xd2\x92\x49\xee\x4c\x0b\x6b\xdc\x5f\xd0"
				"\xdd\xf5\xe2\x6c\x53\x90\x2c\x6f\x42\x7a\x59\x0a\xdf\xbf\x45\xaa"
				"\x74\x4f\x94\xed\xc2\xf5\xe3\x62\xd9\x3b\x49\x6d\xcb\x8c\xa0\x27"
				"\x35\x9c\xf0\x6a\x38\xe9\x03\x3b\x77\x01\xa3\x44\x5f\x46\x26\x89"
				"\x98\xac\x2e\xc6\xec\x47\x0f\xab\x63\x1c\xfe\x0f\xcb\x43\x5f\x82"
				"\xea\xba\xa5\x27\xe6\x6a\x9e\x69\x4f\x37\x6b\x7a\xd8\x51\x36\x26"
				"\x6b\xb4\x06\x33\x5c\x31\x70\x04\x99\x36\xce\x53\x96\x21\xee\xa7"
				"\xb4\xcd\x81\x29\xf9\x16\x39\x80\x28\x23\x4d\x49\xb8\x03\x30\x98"
				"\xde\x4f\xc1\x75\x2e\x82\x8e\x4d\x74\xda\xc2\x96\x20\x5a\x2c\xc2"
				"\x3e\x1f\x63\x7e\x35\x69\x82\x19\x76\xae\x44\x61\x52\x87\x8a\x58"
				"\x3d\x66\x80\x07\xe2\x32\x03\xa2\xfa\x08\x0a\x4b\x85\x1c\x0a\xc5"
				"\x50\x9c\xfb\xce\x3b\xc4\xaf\x27\x77\x82\x5d\x91\xeb\x26\x15\xd1"
				"\xce\xb3\xf8\xe2\x95\xaa\x94\xc9\x05\xa5\x3e\x0e\xc6\x04\x9a\x4e"
				"\x9c\x76\xfa\x78\x24\xc3\xeb\x69\x01\x0d\x6c\x14\xda\xd2\xee\x72"
				"\x59\x2b\x69\xd8\x6e\x3e\xd6\xf9\xab\x59\xe7\x52\x8f\xde\xdd\xe8"
				"\x5b\x6f\x23\xa3\x3f\xb2\x2b\x27\xd8\xff\xbc\x87\xca\x19\x7b\x2a"
				"\x4d\x9e\x28\x7f\x64\x4d\x2c\xa7\xb4\x29\x12\x45\x0c\xf0\x2b\x70"
				"\x5f\x88\x94\x48\x13\x98\x3b\x33\x94\x67\x3a\x57\xc3\x89\x88\xed"
				"\x13\x7f\xaf\x66\x66\x26\x76\x01\x7f\xdc\x07\x57\x3a\x1e\xd2\x8c"
				"\x26\x4c\xba\x35\x2d\x98\x35\xc1\xf3\x73\xaf\x70\x52\xf6\x49\xe5"
				"\xed\xbd\xb5\x31\xe6\xec\xe2\x9e\xcd\x43\x1d\x69\xba\xbf\xd7\x39"
				"\xb4\x41\xe3\x36\x9d\xb8\x44\x45\xbc\x67\xfd\x00\x8c\x6b\xea\x2e"
				"\xa4\x4b\x1c\xb3\x0e\xb2\xcd\xc4\x6c\x29\x09\xe3\xf2\xec\x6e\x36"
				"\x64\x5e\x21\x64\xea\xee\x76\x5e\x79\x99\x16\x70\x60\xb7\x7f\xc0"
				"\x05\xa6\x18\x5f\xac\xca\xce\xcd\xe0\x39\x74\x31\xea\xfe\x13\xcf"
				"\x2a\x0a\x6b\xcb\x94\x28\xaf\x2e\x71\x1d\x97\xf3\xf8\xd0\xb1\x5d"
				"\x4a\xfb\xd6\xee\x9b\x44\xe1\x2f\xe3\x88\x0f\x92\xdc\xba\x75\xab"
				"\x2b\x0f\x38\x78\xbe\x9c\x83\x59\x49\xbe\x2b\xdb\xe1\xeb\xfd\x0c"
				"\x90\x74\x65\x94\x62\xfe\xa6\x3a\x04\x04\x8c\x15\x18\x43\x05\xfb"
				"\x63\x6e\xa4\xfb\x33\xb9\x25\xdb\x73\x1b\x2d\x8b\xa3\xb2\xf4\x28"
				"\x7f\x69\xbb\xa6\xee\x7f\xd6\x00\xd8\xfb\xc0\xfb\x78\x94\x4f\x8f");
			libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(staticEntropyBytes.crypt_get()), 512ul, &prngState);
			staticEntropyBytes.crypt();
		}
		libtomcrypt::chacha20_prng_ready(&prngState);

		tls::aes::SecretKeyType<256> secretKey {};
		libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(secretKey.data(), secretKey.size(), &prngState);
		tls::aes::GcmInitializationVectorType iv {};
		libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(iv.data(), iv.size(), &prngState);
		tls::Array<32> authenticationData {};
		libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(authenticationData.data(), authenticationData.size(), &prngState);
		libtomcrypt::chacha20_prng_done(&prngState);

		if (auto decryptedData = tls::aes::decrypt<tls::aes::CipherMode::GCM>(fileContents, secretKey, iv, authenticationData);
			!decryptedData.empty())
			return decryptedData;
		if constexpr (Configuration::debug)
			print(xorstr_("[!] Cache file buffer was modified (failed to decrypt)"));
	}
	VM_MAXIMUM_END
	return {};
}
void detail::parseCacheFile(bool &successful, const tls::SpanType secretKeyBuffer) {
	VM_MINIMUM_BEGIN
	// Verify the secret key
	{
		if (secretKeyBuffer.size_bytes() != 64)
			return;
		auto secretKey = xorstr(
			"\x4a\x80\x60\x06\xdf\x43\x89\x17\xb7\x38\x47\x89\xf0\xb5\xe1\x09"
			"\x7d\xe3\xfe\x93\xe0\xfe\xb2\x6e\xa2\xdd\xa0\xbf\x93\xc9\x6b\xa2"
			"\x45\x62\xcb\x21\x35\x67\xd0\x36\x50\x54\x79\x56\xe1\x15\xc6\x46"
			"\xe2\xda\xf6\x3e\x7d\x85\xf5\xb0\xba\x9b\x28\x08\x7b\x00\xb2\x92");
		if (std::memcmp(secretKey.crypt_get(), secretKeyBuffer.data(), secretKey.size()) != 0) {
			secretKey.crypt();
			return;
		}
		secretKey.crypt();
	}

	// Read the cache file
	// With the secret key we're trying to verify the caller
	auto secretKey = xorstr(
		"\x6e\xa8\x43\xb5\x3e\xde\xc4\x61\x3a\xe3\x70\x8d\xc6\xff\x9a\xa9"
		"\xed\x56\xf1\xf6\x10\x77\xe2\x21\xf3\xee\x08\x82\x17\x73\x9b\x99"
		"\xde\x8a\xa3\x1d\x3f\x0e\x25\xc7\xb7\x21\x1d\x55\x66\x2c\x45\x50"
		"\xed\x4b\xec\xcb\x3e\xb2\x8d\x17\x23\x4a\x99\xb4\xce\x98\xee\xbe");
	const auto cacheFile = readCacheFile({reinterpret_cast<const tls::UnderlyingDataType*>(secretKey.crypt_get()), secretKey.size()});
	secretKey.crypt();
	if (cacheFile.empty() || cacheFile.size() < sizeof(files::Header))
		return;

	// Parse the cache file
	volatile bool ntoskrnlResolved {}, dxgkrnlResolved {}, classpnpResolved {};
	do {
		tls::stream::Reader fileReader {cacheFile};

		const files::Header fileHeader {
			.hash    = fileReader.read<sizeof(files::Header::hash)>(),
			.entries = fileReader.read<decltype(files::Header::entries)>(),
			.size    = fileReader.read<decltype(files::Header::size)>()};

		// Verify the file hash
		{
			libtomcrypt::prng_state prngState {};
			libtomcrypt::chacha20_prng_start(&prngState);
			{
				auto staticEntropyBytes = xorstr(
					"\x32\x9e\x7f\x56\x06\xd1\x6a\x61\x32\x6e\x92\xb5\xdd\x05\x15\x84"
					"\x09\xb3\x65\x0d\x68\x64\x11\xb0\xaa\x1d\x27\xbd\x52\x4b\xc7\xdf"
					"\x83\xca\xff\x54\x9b\x21\x13\x37\x19\x8d\xba\xa4\xd7\xf3\x1a\x12"
					"\x06\xcc\xab\x51\x96\xf7\x79\x45\x64\x07\x07\x25\xe3\x95\xd8\xe8"
					"\xb2\x41\x1b\xb8\x18\x00\xa7\xe2\xd2\xde\x89\x23\xbe\x4b\xff\x36"
					"\x5f\x47\x23\x2d\xf3\x4d\x4d\x24\xb0\xc1\xc1\xab\x56\x25\x8e\xcd"
					"\xe9\xac\xee\x53\x3e\x48\x50\xb7\x7f\x54\x76\xb2\x88\x94\x44\xa0"
					"\x7f\x3c\xd9\x81\x92\x7b\x62\x31\x11\xd2\x4c\x42\x8e\x3d\x96\xa8"
					"\xd8\x5a\x5d\x63\x0f\x5d\xea\x94\x8b\x47\xe4\xc1\x2b\xce\x9c\x27"
					"\x83\x36\x88\x70\x62\xfb\x85\x88\x7e\xcf\x57\x42\x97\xc8\xff\x4a"
					"\x2b\x54\x56\x49\x3e\x23\xbe\x03\x5a\xef\x22\xd6\xe7\x7d\xba\xe0"
					"\x57\x80\x14\x6c\x2b\xd1\x79\x7f\xa8\x3c\xbe\x80\x65\xde\xd8\x24"
					"\xe5\x7b\x85\xd3\x50\x73\x51\x10\x99\x16\x8d\xab\x26\xb8\x01\x89"
					"\x59\x46\x95\x89\x50\xc6\xb4\x9a\x9c\xa1\x26\xfc\x63\xd6\x00\xb9"
					"\x76\x49\xe9\x11\x93\x76\x5f\xe9\x70\xae\x51\x38\xa5\x43\x7a\xd3"
					"\x20\x66\x34\x79\x1f\x5a\x90\x69\x40\xed\x97\x47\xec\x6e\xb5\x70"
					"\x4e\xed\x2e\x6a\xb2\xee\x48\x8b\x60\xb0\x3a\x0a\xfc\xc0\x6c\x07"
					"\xb7\x59\x2a\x47\xdb\xce\xbd\x5a\xeb\x97\x2c\x5c\xa0\x27\x1e\xda"
					"\xf3\x3f\x8c\xa6\xb6\xd5\xf0\x3d\xbc\x55\xdd\x72\xa3\x95\xab\xbd"
					"\xd9\x75\x94\x57\xf3\x00\x44\xf9\x14\x6d\x64\x0f\xa9\x6f\x18\x80"
					"\xef\x0f\x0f\x8f\x23\xbc\x56\xb8\x9b\xd1\x4d\x4d\x5c\x4a\xbd\xfd"
					"\x6d\x06\x9b\xb8\xc4\x23\x2d\x66\xec\xb3\x8f\xee\xdf\xae\x0c\x1a"
					"\xbc\xe6\x8c\x2e\x4c\x83\x01\x60\xc9\x07\x96\xbd\x4a\x58\x7d\xb4"
					"\xfd\xf8\x8b\xe2\xad\x8b\xe0\x8c\xd8\xeb\x56\x48\x7b\x40\xa6\xcf"
					"\x93\x80\xf7\x3e\x64\x00\x3a\xa0\xe5\xb0\xc1\xc5\x81\xdc\x68\xb7"
					"\x68\x0f\x7d\xe8\x74\x2c\xa0\x9a\x3b\xe7\x1a\x0d\xec\xf4\x8f\x9f"
					"\x5e\xe6\x89\x3b\x45\xc3\xca\x6e\xd5\xb8\xd6\x20\x62\x91\xe5\xe3"
					"\xc8\x07\x67\x65\xbe\xa3\xf5\x6e\x26\x63\xc8\x87\x9a\xdf\x97\x79"
					"\xcf\x55\x4e\x26\x6a\x5c\x15\xf5\x4b\x13\xe1\x62\x93\xa5\x50\x09"
					"\xa8\xf4\x43\xdc\x0b\x38\xf2\xf4\xd2\x84\x2d\x82\xb9\x1e\x2d\x9d"
					"\x8b\xa1\x45\xc1\x63\xac\x55\x59\xa5\x2a\xb9\x63\x4f\x57\xb9\x60"
					"\x09\xf6\x3b\xec\x6a\x00\x50\x01\xdf\x88\x11\xd5\x02\x7d\x1e\xb6");
				libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(staticEntropyBytes.crypt_get()), 512ul, &prngState);
				staticEntropyBytes.crypt();
			}
			libtomcrypt::chacha20_prng_ready(&prngState);

			tls::BitArray<512> keyBuffer {};
			libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(keyBuffer.data(), keyBuffer.size(), &prngState);
			libtomcrypt::chacha20_prng_done(&prngState);

			// Skip the hash in the header when calculating the hash
			const auto calculatedHash = tls::hmacSha<512>(keyBuffer, fileReader.data().subspan(sizeof(files::Header::hash)));
			if (calculatedHash != fileHeader.hash) {
				if constexpr (Configuration::debug)
					print(xorstr_("[!] Cache file hash mismatch!"));
				// TODO: _CRITICAL_ modifications detected (they got past the AES authentication tag?) - PANIC!!!!
				return;
			}
		}

		// Verify the file size
		if (cacheFile.size() != fileHeader.size || cacheFile.size() < sizeof(fileHeader) + sizeof(files::Entry) * fileHeader.entries) {
			if constexpr (Configuration::debug)
				print(xorstr_("Cache file size wasn't equal to the file header size, or it was too small: %llu"), fileHeader.size);
			break;
		}

		std::size_t calculatedFileSize {
			sizeof(files::Header) + sizeof(files::Entry) * fileHeader.entries};
		for (std::size_t i {}; i < fileHeader.entries; ++i) {
			const files::Entry entry {
				.identifier = static_cast<decltype(files::Entry::identifier)>(fileReader.read<std::underlying_type_t<decltype(files::Entry::identifier)>>()),
				.offset     = fileReader.read<decltype(files::Entry::offset)>(),
				.size       = fileReader.read<decltype(files::Entry::size)>()};
			if (entry.offset + entry.size > fileHeader.size) {
				if constexpr (Configuration::print)
					print(xorstr_("Invalid entry bounds in cache file"));
				// TODO: *critical* file tampering detected
				break;
			}

			const tls::SpanType data = fileReader.data().subspan(entry.offset, entry.size);
			if (entry.identifier == files::EntryIdentifier::NTOSKRNL) {
				if (!detail::resolveNtSymbols(data)) {
					if constexpr (Configuration::print)
						print(xorstr_("[-] Failed to resolve NT kernel symbols from cache file."));
					break;
				}
				ntoskrnlResolved = true;
			} else if (entry.identifier == files::EntryIdentifier::DXGKRNL) {
				if (!detail::resolveDirectXSymbols(data)) {
					if constexpr (Configuration::print)
						print(xorstr_("[-] Failed to resolve DirectX symbols from cache file."));
					break;
				}
				dxgkrnlResolved = true;
			} else if (entry.identifier == files::EntryIdentifier::CLASSPNP) {
				if (!detail::resolveClassPnpSymbols(data)) {
					if constexpr (Configuration::print)
						print(xorstr_("[-] Failed to resolve CLASSPNP symbols from cache file."));
					break;
				}
				classpnpResolved = true;
			}

			calculatedFileSize += entry.size;
		}
		if (calculatedFileSize != fileHeader.size || !ntoskrnlResolved || !dxgkrnlResolved || !classpnpResolved)
			break;
	} while (false);

	if (!ntoskrnlResolved || !dxgkrnlResolved || !classpnpResolved)
		return;

	// Symbols have been resolved, downloading them is unnecessary
	successful = true;
	VM_MINIMUM_END
}
void detail::writeCacheFile(const tls::SpanType secretKeyBuffer, const InitializerList pdbs) {
	VM_MINIMUM_BEGIN
	// Verify the secret key
	{
		if (secretKeyBuffer.size_bytes() != 64)
			return;
		auto secretKey = xorstr(
			"\xac\x5b\x8e\x95\xd1\xa9\xdd\x74\xf3\x2e\xbe\xda\xe0\xd3\x9b\x62"
			"\xce\x13\xb3\xc6\xae\x6c\x14\xfc\x00\x9d\x7f\xd5\x22\x56\x51\x84"
			"\x0d\x39\xa4\x66\xe0\x74\xd3\x0e\x38\x81\x75\x5a\x55\x2d\xef\x50"
			"\xa6\x72\xd1\x9b\x3e\x96\x7e\x48\xfe\x88\x34\xac\xa2\x21\x22\xcd");
		if (std::memcmp(secretKey.crypt_get(), secretKeyBuffer.data(), secretKey.size()) != 0) {
			secretKey.crypt();
			return;
		}
		secretKey.crypt();
	}

	// Prepare the entries and copy all the data into a single array
	std::vector<files::Entry> entries {};
	tls::VectorType data {};
	const std::size_t headerSize {sizeof(files::Header) + sizeof(files::Entry) * pdbs.size() + data.size()};
	for (const auto &[identifier, bytes] : pdbs) {
		// Copy the bytes
		const auto currentOffset = data.size();
		data.resize(currentOffset + bytes.size_bytes());
		std::memcpy(data.data() + currentOffset, bytes.data(), bytes.size_bytes());

		// Insert the entry
		entries.emplace_back(identifier, headerSize + currentOffset, bytes.size_bytes());
	}
	
	// Prepare the header
	const files::Header header {
		.entries = entries.size(),
		.size    = headerSize + data.size()};

	// Compile the plaintext data
	tls::stream::Writer fileWriter {};

	// Write the header
	const auto hashPosition = fileWriter.write<sizeof(files::Header::hash)>();
	fileWriter.write(header.entries);
	fileWriter.write(header.size);

	// Write the entries
	for (const auto &[identifier, offset, size] : entries) {
		fileWriter.write(static_cast<std::underlying_type_t<decltype(identifier)>>(identifier));
		fileWriter.write(offset);
		fileWriter.write(size);
	}

	// Write the bytes
	const auto dataBuffer = fileWriter.expand(data.size());
	std::memcpy(dataBuffer, data.data(), data.size());

	// Calculate the hmac sha512 hash
	//   Generate the key
	tls::BitArray<512> key {};
	{
		libtomcrypt::prng_state prngState {};
		libtomcrypt::chacha20_prng_start(&prngState);
		{
			auto staticEntropyBytes = xorstr(
				"\x32\x9e\x7f\x56\x06\xd1\x6a\x61\x32\x6e\x92\xb5\xdd\x05\x15\x84"
				"\x09\xb3\x65\x0d\x68\x64\x11\xb0\xaa\x1d\x27\xbd\x52\x4b\xc7\xdf"
				"\x83\xca\xff\x54\x9b\x21\x13\x37\x19\x8d\xba\xa4\xd7\xf3\x1a\x12"
				"\x06\xcc\xab\x51\x96\xf7\x79\x45\x64\x07\x07\x25\xe3\x95\xd8\xe8"
				"\xb2\x41\x1b\xb8\x18\x00\xa7\xe2\xd2\xde\x89\x23\xbe\x4b\xff\x36"
				"\x5f\x47\x23\x2d\xf3\x4d\x4d\x24\xb0\xc1\xc1\xab\x56\x25\x8e\xcd"
				"\xe9\xac\xee\x53\x3e\x48\x50\xb7\x7f\x54\x76\xb2\x88\x94\x44\xa0"
				"\x7f\x3c\xd9\x81\x92\x7b\x62\x31\x11\xd2\x4c\x42\x8e\x3d\x96\xa8"
				"\xd8\x5a\x5d\x63\x0f\x5d\xea\x94\x8b\x47\xe4\xc1\x2b\xce\x9c\x27"
				"\x83\x36\x88\x70\x62\xfb\x85\x88\x7e\xcf\x57\x42\x97\xc8\xff\x4a"
				"\x2b\x54\x56\x49\x3e\x23\xbe\x03\x5a\xef\x22\xd6\xe7\x7d\xba\xe0"
				"\x57\x80\x14\x6c\x2b\xd1\x79\x7f\xa8\x3c\xbe\x80\x65\xde\xd8\x24"
				"\xe5\x7b\x85\xd3\x50\x73\x51\x10\x99\x16\x8d\xab\x26\xb8\x01\x89"
				"\x59\x46\x95\x89\x50\xc6\xb4\x9a\x9c\xa1\x26\xfc\x63\xd6\x00\xb9"
				"\x76\x49\xe9\x11\x93\x76\x5f\xe9\x70\xae\x51\x38\xa5\x43\x7a\xd3"
				"\x20\x66\x34\x79\x1f\x5a\x90\x69\x40\xed\x97\x47\xec\x6e\xb5\x70"
				"\x4e\xed\x2e\x6a\xb2\xee\x48\x8b\x60\xb0\x3a\x0a\xfc\xc0\x6c\x07"
				"\xb7\x59\x2a\x47\xdb\xce\xbd\x5a\xeb\x97\x2c\x5c\xa0\x27\x1e\xda"
				"\xf3\x3f\x8c\xa6\xb6\xd5\xf0\x3d\xbc\x55\xdd\x72\xa3\x95\xab\xbd"
				"\xd9\x75\x94\x57\xf3\x00\x44\xf9\x14\x6d\x64\x0f\xa9\x6f\x18\x80"
				"\xef\x0f\x0f\x8f\x23\xbc\x56\xb8\x9b\xd1\x4d\x4d\x5c\x4a\xbd\xfd"
				"\x6d\x06\x9b\xb8\xc4\x23\x2d\x66\xec\xb3\x8f\xee\xdf\xae\x0c\x1a"
				"\xbc\xe6\x8c\x2e\x4c\x83\x01\x60\xc9\x07\x96\xbd\x4a\x58\x7d\xb4"
				"\xfd\xf8\x8b\xe2\xad\x8b\xe0\x8c\xd8\xeb\x56\x48\x7b\x40\xa6\xcf"
				"\x93\x80\xf7\x3e\x64\x00\x3a\xa0\xe5\xb0\xc1\xc5\x81\xdc\x68\xb7"
				"\x68\x0f\x7d\xe8\x74\x2c\xa0\x9a\x3b\xe7\x1a\x0d\xec\xf4\x8f\x9f"
				"\x5e\xe6\x89\x3b\x45\xc3\xca\x6e\xd5\xb8\xd6\x20\x62\x91\xe5\xe3"
				"\xc8\x07\x67\x65\xbe\xa3\xf5\x6e\x26\x63\xc8\x87\x9a\xdf\x97\x79"
				"\xcf\x55\x4e\x26\x6a\x5c\x15\xf5\x4b\x13\xe1\x62\x93\xa5\x50\x09"
				"\xa8\xf4\x43\xdc\x0b\x38\xf2\xf4\xd2\x84\x2d\x82\xb9\x1e\x2d\x9d"
				"\x8b\xa1\x45\xc1\x63\xac\x55\x59\xa5\x2a\xb9\x63\x4f\x57\xb9\x60"
				"\x09\xf6\x3b\xec\x6a\x00\x50\x01\xdf\x88\x11\xd5\x02\x7d\x1e\xb6");
			libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(staticEntropyBytes.crypt_get()), 512ul, &prngState);
			staticEntropyBytes.crypt();
		}
		libtomcrypt::chacha20_prng_ready(&prngState);
		
		libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(key.data(), key.size(), &prngState);
		libtomcrypt::chacha20_prng_done(&prngState);
	}

	//   Save the hash
	const auto fileHash = tls::hmacSha<512>(key, fileWriter.subspan(sizeof(files::Header::hash)));
	std::memcpy(fileWriter.data() + hashPosition, fileHash.data(), fileHash.size());
	VM_MINIMUM_END

	VM_MAXIMUM_BEGIN
	// Generate the ciphertext and save the data to disk
	{
		const auto [explorerProcess] = nt::Kernel::process(Hash {Fnv1A("explorer.exe")});

		std::wstring tempPath {}, username {};
		{
			auto prefix = xorstr(LR"(\DosDevices\)");
			tempPath += prefix.crypt_get();
			prefix.crypt();
		}
		auto tempFound {false};
		nt::User::iterateEnvironmentVariables(explorerProcess, [&](const std::wstring_view name, const std::wstring_view value) {
			VM_MINIMUM_BEGIN
			volatile auto shouldContinue {true};
			if (const Hash nameHash {name};
				!tempFound && (nameHash == Fnv1A(L"TEMP") || nameHash == Fnv1A(L"TMP"))) {
				tempPath += value;
				tempFound = true;
			} else if (nameHash == Fnv1A(L"USERNAME"))
				username = value;
			if (tempFound && !username.empty())
				shouldContinue = false;
			VM_MINIMUM_END
			return shouldContinue;
		});
		if (tempPath.empty())
			return;

		const auto efiHwid = hwid::efi();

		libtomcrypt::prng_state prngState {};
		libtomcrypt::chacha20_prng_start(&prngState);
		libtomcrypt::chacha20_prng_add_entropy(efiHwid.data(), static_cast<unsigned long>(hwid::sha512HashSize), &prngState);
		if (!username.empty())
			libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(username.data()), static_cast<unsigned long>(username.length() * sizeof(wchar_t)), &prngState);
		{
			auto staticEntropyBytes = xorstr(
				"\x04\xb3\xde\x8d\x7e\x8a\xca\xd7\x72\x20\xf5\xf6\xb0\x8d\xaf\xf9"
				"\x54\x31\x5b\xea\xe6\x8d\xd2\x92\x49\xee\x4c\x0b\x6b\xdc\x5f\xd0"
				"\xdd\xf5\xe2\x6c\x53\x90\x2c\x6f\x42\x7a\x59\x0a\xdf\xbf\x45\xaa"
				"\x74\x4f\x94\xed\xc2\xf5\xe3\x62\xd9\x3b\x49\x6d\xcb\x8c\xa0\x27"
				"\x35\x9c\xf0\x6a\x38\xe9\x03\x3b\x77\x01\xa3\x44\x5f\x46\x26\x89"
				"\x98\xac\x2e\xc6\xec\x47\x0f\xab\x63\x1c\xfe\x0f\xcb\x43\x5f\x82"
				"\xea\xba\xa5\x27\xe6\x6a\x9e\x69\x4f\x37\x6b\x7a\xd8\x51\x36\x26"
				"\x6b\xb4\x06\x33\x5c\x31\x70\x04\x99\x36\xce\x53\x96\x21\xee\xa7"
				"\xb4\xcd\x81\x29\xf9\x16\x39\x80\x28\x23\x4d\x49\xb8\x03\x30\x98"
				"\xde\x4f\xc1\x75\x2e\x82\x8e\x4d\x74\xda\xc2\x96\x20\x5a\x2c\xc2"
				"\x3e\x1f\x63\x7e\x35\x69\x82\x19\x76\xae\x44\x61\x52\x87\x8a\x58"
				"\x3d\x66\x80\x07\xe2\x32\x03\xa2\xfa\x08\x0a\x4b\x85\x1c\x0a\xc5"
				"\x50\x9c\xfb\xce\x3b\xc4\xaf\x27\x77\x82\x5d\x91\xeb\x26\x15\xd1"
				"\xce\xb3\xf8\xe2\x95\xaa\x94\xc9\x05\xa5\x3e\x0e\xc6\x04\x9a\x4e"
				"\x9c\x76\xfa\x78\x24\xc3\xeb\x69\x01\x0d\x6c\x14\xda\xd2\xee\x72"
				"\x59\x2b\x69\xd8\x6e\x3e\xd6\xf9\xab\x59\xe7\x52\x8f\xde\xdd\xe8"
				"\x5b\x6f\x23\xa3\x3f\xb2\x2b\x27\xd8\xff\xbc\x87\xca\x19\x7b\x2a"
				"\x4d\x9e\x28\x7f\x64\x4d\x2c\xa7\xb4\x29\x12\x45\x0c\xf0\x2b\x70"
				"\x5f\x88\x94\x48\x13\x98\x3b\x33\x94\x67\x3a\x57\xc3\x89\x88\xed"
				"\x13\x7f\xaf\x66\x66\x26\x76\x01\x7f\xdc\x07\x57\x3a\x1e\xd2\x8c"
				"\x26\x4c\xba\x35\x2d\x98\x35\xc1\xf3\x73\xaf\x70\x52\xf6\x49\xe5"
				"\xed\xbd\xb5\x31\xe6\xec\xe2\x9e\xcd\x43\x1d\x69\xba\xbf\xd7\x39"
				"\xb4\x41\xe3\x36\x9d\xb8\x44\x45\xbc\x67\xfd\x00\x8c\x6b\xea\x2e"
				"\xa4\x4b\x1c\xb3\x0e\xb2\xcd\xc4\x6c\x29\x09\xe3\xf2\xec\x6e\x36"
				"\x64\x5e\x21\x64\xea\xee\x76\x5e\x79\x99\x16\x70\x60\xb7\x7f\xc0"
				"\x05\xa6\x18\x5f\xac\xca\xce\xcd\xe0\x39\x74\x31\xea\xfe\x13\xcf"
				"\x2a\x0a\x6b\xcb\x94\x28\xaf\x2e\x71\x1d\x97\xf3\xf8\xd0\xb1\x5d"
				"\x4a\xfb\xd6\xee\x9b\x44\xe1\x2f\xe3\x88\x0f\x92\xdc\xba\x75\xab"
				"\x2b\x0f\x38\x78\xbe\x9c\x83\x59\x49\xbe\x2b\xdb\xe1\xeb\xfd\x0c"
				"\x90\x74\x65\x94\x62\xfe\xa6\x3a\x04\x04\x8c\x15\x18\x43\x05\xfb"
				"\x63\x6e\xa4\xfb\x33\xb9\x25\xdb\x73\x1b\x2d\x8b\xa3\xb2\xf4\x28"
				"\x7f\x69\xbb\xa6\xee\x7f\xd6\x00\xd8\xfb\xc0\xfb\x78\x94\x4f\x8f");
			libtomcrypt::chacha20_prng_add_entropy(reinterpret_cast<const unsigned char*>(staticEntropyBytes.crypt_get()), 512ul, &prngState);
			staticEntropyBytes.crypt();
		}
		libtomcrypt::chacha20_prng_ready(&prngState);

		tls::aes::SecretKeyType<256> secretKey {};
		libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(secretKey.data(), secretKey.size(), &prngState);
		tls::aes::GcmInitializationVectorType iv {};
		libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(iv.data(), iv.size(), &prngState);
		tls::Array<32> authenticationData {};
		libtomcrypt::prng_descriptor[libtomcrypt::chacha20PrngIdentifier].read(authenticationData.data(), authenticationData.size(), &prngState);
		libtomcrypt::chacha20_prng_done(&prngState);

		const auto ciphertext = tls::aes::encrypt<tls::aes::CipherMode::GCM>(fileWriter, secretKey, iv, authenticationData);
		if (ciphertext.empty()) {
			if constexpr (Configuration::debug)
				print(xorstr_("[!] Failed to encrypt data for the cache file."));
			return;
		}

		// Save the data to disk
		const auto fileNameBuffer = generateFileName(username);
		const std::string_view fileName {reinterpret_cast<const char*>(fileNameBuffer.data()), fileNameBuffer.size()};

		auto delimiter = xorstr(LR"(\)");
		const auto filePath = tempPath + delimiter.crypt_get() + strings::unicode(fileName);
		delimiter.crypt();

		if (const auto status = nt::Kernel::writeFile(filePath, ciphertext);
			!NT_SUCCESS(status)) {
			if constexpr (Configuration::debug)
				print(xorstr_("[!] Failed to write cache file to disk."));
		}
	}
	VM_MAXIMUM_END
}
