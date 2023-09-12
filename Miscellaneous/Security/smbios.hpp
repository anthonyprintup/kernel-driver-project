// ReSharper disable CppClangTidyClangDiagnosticUnusedPrivateField
#pragma once

#include "../../Utilities/NT/NT.hpp"

namespace KM::Miscellaneous::smbios {
	namespace versions {
		constexpr auto v20  {0x02'00'00};
		constexpr auto v21  {0x02'01'00};
		constexpr auto v22  {0x02'02'00};
		constexpr auto v23  {0x02'03'00};
		constexpr auto v24  {0x02'04'00};
		constexpr auto v25  {0x02'05'00};
		constexpr auto v26  {0x02'06'00};
		constexpr auto v27  {0x02'07'00};
		constexpr auto v28  {0x02'08'00};
		constexpr auto v30  {0x03'00'00};
		constexpr auto v31  {0x03'01'00};
		constexpr auto v311 {0x03'01'01};
		constexpr auto v32  {0x03'02'00};
		constexpr auto v33  {0x03'03'00};
		constexpr auto v34  {0x03'04'00};
	}
	namespace structures {
		#pragma pack(push, 1)
		struct EntryPoint32 { // Table 1 - SMBIOS 2.1 (32-bit) Entry Point structure
			std::uint8_t anchor[4] {}; // _SM_
			std::uint8_t checksum  {};
			std::uint8_t length    {};
			struct {
				std::uint8_t major {};
				std::uint8_t minor {};
			} version {};
			std::uint16_t maximumStructureSize {};
			struct {
				std::uint8_t entryPoint {};
			} revision {};
			std::uint8_t formattedArea[5] {};
			struct {
				std::uint8_t anchor[5] {}; // _DMI_
				std::uint8_t checksum  {};
			} intermediate {};
			struct {
				std::uint16_t length {};
				std::uint32_t address {};
			} structureTable {};
			std::uint16_t structures {};
			std::uint8_t  bcdRevision {};
		};
		struct EntryPoint64 { // Table 2 - SMBIOS 3.0 (64-bit) Entry Point structure
			std::uint8_t anchor[5] {}; // _SM3_
			std::uint8_t checksum  {};
			std::uint8_t length    {}; // 0x18
			struct {
				std::uint8_t major {};
				std::uint8_t minor {};
			} version {};
			struct {
				std::uint8_t document   {};
				std::uint8_t entryPoint {};
			} revision {};
		private:
			std::uint8_t reserved {};
		public:
			struct {
				std::uint32_t  maximumSize {};
				std::uintptr_t address     {};
			} structureTable {};
		};
		
		enum struct Type: std::uint8_t {
			BiosInformation, // required
			SystemInformation, // required
			BaseboardInformation,
			SystemEnclosure, // required
			ProcessorInformation, // required
			MemoryControllerInformation, // obsolete
			MemoryModuleInformation, // obsolete
			CacheInformation, // required
			PortConnectorInformation,
			SystemSlots, // required
			OnBoardDevicesInformation, // obsolete
			OemStrings,
			SystemConfigurationOptions,
			BiosLanguageInformation,
			GroupAssociations,
			SystemEventLog,
			PhysicalMemoryArray, // required
			MemoryDevice, // required
			MemoryErrorInformation32,
			MemoryArrayMappedAddress, // required
			MemoryDeviceMappedAddress,
			BuiltinPointingDevice,
			PortableBattery,
			SystemReset,
			HardwareSecurity,
			SystemPowerControls,
			VoltageProbe,
			CoolingDevice,
			TemperatureProbe,
			ElectricalCurrentProbe,
			OutOfBandRemoteAccess,
			BootIntegrityServices,
			SystemBootInformation, // required
			MemoryErrorInformation64,
			ManagementDevice,
			ManagementDeviceComponent,
			ManagementDeviceThresholdData,
			MemoryChannel,
			IpmiDeviceInformation,
			SystemPowerSupply,
			AdditionalInformation,
			OnboardDevicesExtendedInformation,
			ManagementControllerHostInterface,
			TpmDevice,
			ProcessorAdditionalInformation,
			Inactive = 126,
			EndOfTable
		};

		using StringType = std::uint8_t;
		struct Header { // 2.0+
			std::uint8_t  type   {};
			std::uint8_t  length {};
			std::uint16_t handle {};
		};
		struct BiosInformation: Header { // required
			std::uint8_t vendor {}; // string
			struct {
				StringType    version {}; // string
				std::uint16_t startingAddressSegment {};
				StringType    releaseDate {}; // string
				std::uint8_t  romSize {};
				std::uint64_t characteristics {}; // bit field
				
				// 2.4+
				std::uint16_t characteristicsExtensionBytes {}; // bit field
				struct {
					std::uint8_t major {};
					std::uint8_t minor {};
				} release {};
				struct {
					std::uint8_t major {};
					std::uint8_t minor {};
				} embeddedControllerFirmwareRelease {};

				// 3.1+
				std::uint16_t extendedRomSize {};
			} bios {};
		};
		struct SystemInformation: Header { // required
			StringType manufacturer {}; // string
			StringType productName {}; // string
			StringType version {}; // string
			StringType serialNumber {}; // string

			// 2.1+
			struct {
				struct {
					std::uint32_t low {};
					std::uint16_t mid {};
					std::uint16_t highAndVersion {};
				} time {};
				struct {
					std::uint8_t sequenceHighAndReserved {};
					std::uint8_t sequenceLow {};
				} clock {};
				std::uint8_t node[6] {};
			} uuid {};
			std::uint8_t wakeupType {}; // enum

			// 2.4+
			StringType skuNumber {}; // string
			StringType family {}; // string
		};
		struct SystemEnclosure: Header { // required
			StringType   manufacturer {}; // string
			std::uint8_t type {};
			StringType   version {}; // string
			StringType   serialNumber {}; // string
			StringType   assetTagNumber {}; // string

			// 2.1+
			std::uint8_t bootupState {}; // enum
			std::uint8_t powerSupplyState {}; // enum
			std::uint8_t thermalState {}; // enum
			std::uint8_t securityStatus {}; // enum

			// 2.3+
			std::uint32_t vendorSpecificInformation {};
			std::uint8_t  height {};
			std::uint8_t  numberOfPowerCords {};

			// contained element count, contained element record length, contained elements, SKU number
		};
		struct ProcessorInformation: Header { // required
			StringType socketDesignation {}; // string
			struct {
				std::uint8_t  type {}; // enum
				std::uint8_t  family {}; // enum
				std::uint64_t id {};
				StringType version {}; // string
			} processor {};
			std::uint8_t  voltage {};
			std::uint16_t externalClock {};
			struct {
				std::uint16_t max {};
				std::uint16_t current {};
			} speed {};
			std::uint8_t  status {};
			std::uint8_t  upgradeable {}; // enum

			// 2.1+
			struct {
				std::uint16_t l1 {};
				std::uint16_t l2 {};
				std::uint16_t l3 {};
			} cacheHandles {};

			// 2.3+
			StringType serialNumber {}; // string
			StringType assetTag {}; // string
			StringType partNumber {}; // string

			// 2.5+
			struct {
				std::uint8_t cores {};
				std::uint8_t coresEnabled {};
				std::uint8_t threads {};
			} counts {};
			std::uint16_t  processorCharacteristics {}; // bit field
			
			// 2.6+
			struct {
				std::uint8_t family {}; // enum
			} processor2 {};

			// 3.0+
			struct {
				std::uint16_t cores {};
				std::uint16_t coresEnabled {};
				std::uint16_t threads {};
			} counts2 {};
		};
		struct CacheInformation: Header { // required
			StringType    socketDesignation {}; // string
			std::uint16_t configuration {};
			std::uint16_t maximumSize {};
			std::uint16_t installedSize {};
			struct {
				std::uint16_t supported {}; // bit field
				std::uint16_t current {}; // bit field
			} sramType {};

			// 2.1+
			std::uint8_t  speed {};
			std::uint8_t  errorCorrectionType {}; // enum
			std::uint8_t  systemCacheType {}; // enum
			std::uint8_t  associativity {}; // enum
			
			// 3.1+
			std::uint32_t maximumSize2 {}; // bit field
			std::uint32_t installedSize2 {}; // bit field
		};
		struct SystemSlots: Header { // required
			struct {
				StringType    designation {}; // string
				std::uint8_t  type {}; // enum
				std::uint8_t  dataBusWidth {}; // enum
				std::uint8_t  currentUsage {}; // enum
				std::uint8_t  length {}; // enum
				std::uint16_t id {};
				std::uint8_t  characteristics1 {}; // bit field

				// 2.1+
				std::uint8_t  characteristics2 {}; // bit field
			} slot {};

			// 2.6+
			std::uint16_t segmentGroupNumber {}; // bit field
			std::uint8_t  busNumber {};
			std::uint8_t  deviceNumber {}; // bit field

			// 3.2 and 3.4 are missing due to non static implementations
		};
		struct PhysicalMemoryArray: Header { // required
			// 2.1+
			std::uint8_t  location {}; // enum
			std::uint8_t  use {}; // enum
			std::uint8_t  memoryErrorCorrection {}; // enum
			std::uint32_t maximumCapacity {};
			std::uint16_t memoryErrorInformationHandle {};
			std::uint16_t numberOfMemoryDevices {};

			// 2.7+
			std::uint64_t extendedMaximumCapacity {};
		};
		struct MemoryDevice: Header { // required
			// 2.1+
			std::uint16_t physicalMemoryArrayHandle {};
			std::uint16_t memoryErrorInformationHandle {};
			std::uint16_t totalWidth {};
			std::uint16_t dataWidth {};
			std::uint16_t size {};
			std::uint8_t  formFactor {}; // enum
			std::uint8_t  deviceSet {};
			StringType    deviceLocator {}; // string
			StringType    bankLocator {}; // string
			std::uint8_t  memoryType {}; // enum
			std::uint16_t typeDetail {}; // bit field
			
			// 2.3+
			std::uint16_t speed {};
			StringType    manufacturer {}; // string
			StringType    serialNumber {}; // string
			StringType    assetTag {}; // string
			StringType    partNumber {}; // string

			// 2.6+
			std::uint8_t  attributes {};

			// 2.7+
			std::uint32_t extendedSize {};
			std::uint16_t configuredMemorySpeed {};

			// 2.8+
			struct {
				std::uint16_t minimum {};
				std::uint16_t maximum {};
				std::uint16_t configured {};
			} voltage {};

			// 3.2+
			std::uint16_t memoryOperatingModeCapability {}; // bit field
			StringType    firmwareVersion {}; // string
			struct {
				std::uint16_t manufacturerId {};
				std::uint16_t productId {};
			} module {};
			struct {
				std::uint16_t manufacturerId {};
				std::uint16_t productId {};
			} memorySubsystemController {};
			struct {
				std::uint64_t nonVolatile {};
				std::uint64_t _volatile {};
				std::uint64_t cache {};
				std::uint64_t logical {};
			} sizes {};

			// 3.3+
			struct {
				std::uint32_t actual {};
				std::uint32_t configured {};
			} extendedSpeed {};
		};
		struct MemoryArrayMappedAddress: Header { // required
			// 2.1+
			struct {
				std::uint32_t starting {};
				std::uint32_t ending {};
			} address {};
			std::uint16_t memoryArrayHandle {};
			std::uint8_t  partitionWidth {};
			
			// 2.7+
			struct {
				std::uint64_t starting {};
				std::uint64_t ending {};
			} extendedAddress {};
		};
		struct SystemBootInformation: Header { // required
			std::uint8_t reserved[6] {};
			std::uint8_t bootStatus[10] {};
		};
		#pragma pack(pop)
	}

	namespace parser {
		struct Structure {
			explicit Structure(const structures::Header *header) noexcept:
				header {header} {}
			
			[[nodiscard]] structures::Type type() const noexcept;
			[[nodiscard]] std::string_view string(std::size_t index) const noexcept;
			[[nodiscard]] auto operator[](const std::size_t index) const noexcept {
				return this->string(index);
			}
			
			const structures::Header *header {};
		};

		std::size_t parse(std::uint8_t *data, std::size_t size, std::function<void(Structure&&)> &&callback) noexcept;
	}
	PHYSICAL_ADDRESS physicalAddress() noexcept;
	PHYSICAL_ADDRESS wmipSmBiosTablePhysicalAddress() noexcept;
	std::uint16_t    wmipSmBiosTableLength() noexcept;
	std::uint32_t    wmipSmBiosVersionInfo() noexcept;

	bool valid(void *virtualAddress, std::uint32_t version) noexcept;
}
