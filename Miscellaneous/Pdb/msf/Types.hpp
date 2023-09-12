// ReSharper disable CppClangTidyClangDiagnosticUnusedPrivateField
#pragma once

#include <cstdint>

#include <Framework/Utilities/Strings/Fnv1A.hpp>

namespace msf {
	// Our types
	using HashType = Framework::Utilities::Strings::Fnv1A::Hash;
	enum struct UnderlyingType {
		NONE,
		VOID_,
		BOOL,
		CHAR, UCHAR, WCHAR, CHAR16, CHAR32,
		INT8, UINT8, INT16, UINT16, INT32, UINT32, INT64, UINT64, INT128, UINT128,
		LONG32, ULONG32, LONG64, ULONG64,
		FLOAT, DOUBLE,

		STRUCTURE, UNION, ENUM, ARRAY, BIT_FIELD, PROCEDURE
	};

	// RawTypes.h
	using Int8   = std::int8_t;
	using UInt8  = std::uint8_t;
	using Int16  = std::int16_t;
	using UInt16 = std::uint16_t;
	using Int32  = std::int32_t;
	using UInt32 = std::uint32_t;
	using Int64  = std::int64_t;
	using UInt64 = std::uint64_t;
	using Guid   = UInt8[16];

	// msf types
	struct SuperBlock {
		UInt8  magicBytes[32] {};
		UInt32 blockSize {};
		// The index of the free block map
		UInt32 freeBlockMapBlock {};
		// Number of blocks (numberOfBlocks * blockSize == sizeof(MSF file)
		UInt32 numberOfBlocks {};
		// Number of bytes which make up the directory stream table
		UInt32 numberOfDirectoryBytes {};
	private:
		UInt32 unknown {};
	public:
		// Contains the block offset of the block map
		UInt32 blockMapAddress {};
	};
	static_assert(sizeof(SuperBlock) == 56, "Invalid SuperBlock size!");
	namespace dbiFlags {
		constexpr UInt16 incrementalMask {0x0001};
		constexpr UInt16 strippedMask    {0x0002};
		constexpr UInt16 hasCTypes       {0x0004};
	}
	enum struct PdbMachineType: UInt16 {
		INVALID     = 0xFFFF,
		UNKNOWN     = 0x0000,
		AM33        = 0x0013,
		AMD64_      = 0x8664,
		ARM         = 0x01C0,
		ARM64       = 0xAA64,
		ARM_NT      = 0x01C4,
		EBC         = 0x0EBC,
		X86         = 0x014C,
		IA64        = 0x0200,
		M32R        = 0x9041,
		MIPS16      = 0x0266,
		MIPS_FPU    = 0x0366,
		MIPS_FPU16  = 0x0466,
		POWERPC     = 0x01F0,
		POWERPC_FP  = 0x01F1,
		R4000       = 0x0166,
		SH3         = 0x01A2,
		SH3_DSP     = 0x01A3,
		SH4         = 0x01A6,
		SH5         = 0x01A8,
		THUMB       = 0x01C2,
		WCE_MIPS_V2 = 0x0169
	};
	struct DbiStreamHeader {
		Int32  versionSignature {};
		UInt32 versionHeader {};

		// Age of the DBI Stream -> should match the age of the PDB InfoStream
		UInt32 age {};

		// Global symbol stream number
		UInt16 globalSymbolStreamIndex {};

		// DbiBuildNo
		UInt16 buildNumber {};

		// Public symbol stream number
		UInt16 publicSymbolStreamIndex {};

		// Version of the associated module
		UInt16 pdbDllVersion {};

		// Symbol records stream number
		UInt16 symbolRecordStreamIndex {};

		// Rbld number of the associated module
		UInt16 pdbDllRbld {};

		// Size of the module info stream
		Int32  moduleInfoSubstreamSize {};

		// Size of the section contribution stream
		Int32  sectionContributionSubstreamSize {};

		// Size of the section map substream
		Int32  sectionMapSize {};

		// Size of the file info substream
		Int32  fileInfoSize {};

		// Size of the type server map
		Int32  typeServerSize {};

		// Index of the MFC Type Server
		UInt32 mfcTypeServerIndex {};

		// Size of the DbgHeader info
		Int32  optionalDbgHeaderSize {};

		// Size of the EC stream
		Int32  ecSubstreamSize {};

		// DbiFlags
		UInt16 flags {};

		// PdbMachineType enum
		UInt16 machineType {};
	private:
		UInt32 reserved {};
	};
	static_assert(sizeof(DbiStreamHeader) == 64, "Invalid DbiStreamHeader size!");
	constexpr UInt16 invalidStreamIndex {0xFFFF};
	enum struct DbgHeaderType {
		FPO,
		EXCEPTION,
		FIXUP,
		OMAP_TO_SRC,
		OMAP_FROM_SRC,
		SECTION_HEADER,
		TOKEN_RID_MAP,
		XDATA,
		PDATA,
		NEW_FPO,
		SECTION_HEADER_ORIGINAL
	};

	// The header preceding the global PDB stream (Stream 1)
	struct InfoStreamHeader {
		UInt32 version {};
		UInt32 signature {};
		UInt32 age {};
		Guid   guid {};
	};
	struct PublicSymbolsStreamHeader {
		UInt32 symbolHash {};
		UInt32 addressMap {};
		UInt32 numberOfThunks {};
		UInt32 sizeOfThunk {};
		UInt16 sectionThunkTableIndex {};
	private:
		UInt8  padding[2] {};
	public:
		UInt32 thunkTableOffset {};
		UInt32 numberOfSections {};
	};
	enum struct GsiHashHeaderVersion: UInt32 {
		SIGNATURE = ~0u,
		VERSION   = 0xEFFE0000 + 19990810
	};
	struct GsiHashHeader {
		UInt32 versionSignature {};
		UInt32 versionHeader {};
		UInt32 hashRecordsSize {};
		UInt32 numberOfBuckets {};
	};
	struct PsHashRecord {
		UInt32 offset {}; // Offset in the symbol record stream
		UInt32 cref {};
	};
	struct TpiStreamHeader {
		static constexpr UInt32 tpiMinimumBucketCount = 0x01000;
		static constexpr UInt32 tpiMaximumBucketCount = 0x40000;

		struct EmbeddedBuffer {
			Int32  offset {};
			UInt32 length {};
		};

		UInt32 version {};
		UInt32 headerSize {};
		UInt32 typeIndexBegin {};
		UInt32 typeIndexEnd {};
		UInt32 typeRecordBytes {};

		// The following members correspond to `TpiHash`
		UInt16 hashStreamIndex {};
		UInt16 hashAuxStreamIndex {};
		UInt32 hashKeySize {};
		UInt32 numberOfHashBuckets {};

		EmbeddedBuffer hashValueBuffer {};
		EmbeddedBuffer indexOffsetBuffer {};
		EmbeddedBuffer hashAdjustmentBuffer {};
	};

	// The header preceding the /names stream
	struct PdbStringTableHeader {
		UInt32 signature {};
		UInt32 hashVersion {}; // 1 or 2
		UInt32 numberOfBytes {}; // Number of bytes in the names buffer
	};
	enum struct SrcHeaderBlockVersion: UInt32 {
		VERSION_ONE = 19980827
	};
	// The header preceding the /src/headerblock stream
	struct SrcHeaderBlockHeader {
		UInt32 version {}; // SrcHeaderBlockVersion enum
		UInt32 size {};
		UInt64 fileTime {};
		UInt32 age {};
	private:
		UInt8  padding[44] {};
	};
	static_assert(sizeof(SrcHeaderBlockHeader) == 64, "Incorrect struct size!");

	enum struct SourceCompression: UInt8 {
		NONE,
		RUN_LENGTH_ENCODED,
		HUFFMAN,
		LZ,
		DOTNET
	};
	struct SrcHeaderBlockEntry {
		UInt32 size {}; // Record length
		UInt32 version {}; // SrcHeaderBlockVersion enum
		UInt32 crc {};
		UInt32 fileSize {};
		UInt32 fileNumberIndex {};        // String table index of the file name
		UInt32 objectNumberIndex {};      // String table index of the object name
		UInt32 virtualFileNumberIndex {}; // String able index of the virtual file name;
		UInt8  compression {};            // SourceCompression enum
		UInt8  isVirtual {};              // Is this a virtual file
	private:
		UInt16 padding {};
		UInt8  reserved[8] {};
	};
	static_assert(sizeof(SrcHeaderBlockEntry) == 40, "Incorrect struct size!");

	enum struct StreamIndex: std::size_t {
		OLD_MSF_DIRECTORY,
		PDB,
		TPI,
		DBI,
		IPI
	};
	enum struct PdbImplementationVersion: UInt32 {
		VC2   = 19941610,
		VC4   = 19950623,
		VC41  = 19950814,
		VC50  = 19960307,
		VC98  = 19970604,
		VC70_DEPRECATED = 19990604, // deprecated
		VC70  = 20000404,
		VC80  = 20030901,
		VC110 = 20091201,
		VC140 = 20140508
	};
	enum struct TpiImplementationVersion: UInt32 {
		V40 = 19950410,
		V41 = 19951122,
		V50 = 19961031,
		V70 = 19990903,
		V80 = 20040203,
	};
	enum struct FeatureSignature: UInt32 {
		VC110 = static_cast<std::underlying_type_t<PdbImplementationVersion>>(PdbImplementationVersion::VC110),
		VC140 = static_cast<std::underlying_type_t<PdbImplementationVersion>>(PdbImplementationVersion::VC140),
		NO_TYPE_MERGE = 0x4D544F4E,
		MINIMAL_DEBUG_INFO = 0x494E494D
	};
	namespace featureFlags {
		constexpr UInt32 none {0};
		constexpr UInt32 containsIdStream {1};
		constexpr UInt32 minimalDebugInfo {2};
		constexpr UInt32 noTypeMerging {4};
	}

	namespace coff {
		struct SectionHeader {
			static constexpr std::size_t maximumNameSize {8};

			char name[maximumNameSize] {};
			UInt32 virtualSize {};
			UInt32 virtualAddress {};
			UInt32 sizeOfRawData {};
			UInt32 pointerToRawData {};
			UInt32 pointerToRelocations {};
			UInt32 pointerToLineNumbers {};
			UInt16 numberOfRelocations {};
			UInt16 numberOfLineNumbers {};
			UInt32 characteristics {};
		};
	}

	struct SectionContribution {
		UInt16 sectionIndex {};
	private:
		UInt8  padding[2] {};
	public:
		Int32  offset {};
		Int32  size {};
		UInt32 characteristics {};
		UInt16 moduleIndex {};
	private:
		UInt8  padding2[2] {};
	public:
		UInt32 dataCrc {};
		UInt32 relocCrc {};
	};
	struct SectionContribution2: SectionContribution {
		UInt32 sectionContributionOffsetIndex {};
	};
	enum struct SectionContributionVersion: UInt32 {
		VERSION_60 = 0xEFFE0000 + 19970605,
		VERSION_2  = 0xEFFE0000 + 20140516
	};
	namespace moduleInfoFlags {
		// uint16_t fWritten   : 1; // True if DbiModuleDescriptor is dirty
		// uint16_t fECEnabled : 1; // Is EC symbolic info present?  (What is EC?)
		// uint16_t unused     : 6; // Reserved
		// uint16_t iTSM       : 8; // Type Server Index for this module
		constexpr UInt16 hasEcFlag            {0x2};
		constexpr UInt16 typeServerIndexMask  {0xFF00};
		constexpr UInt16 typeServerIndexShift {8};

	}
	struct ModuleInfoHeader {
		// Pointer to the currently opened module
		UInt32 module {};

		// First section contribution of this module
		SectionContribution sectionContribution {};

		// ModuleInfo Flags
		UInt16 flags {};

		// Module Debug Info stream number
		UInt16 moduleDebugInfoStreamIndex {};

		// Size of the local symbol debug info for the stream above
		UInt32 moduleDebugInfoStreamSize {};

		// Size of the C11 line number info for the stream above
		UInt32 c11Bytes {};

		// Size of the C13 line number info for the stream above
		UInt32 c13Bytes {};

		// Number of files contributing to this module
		UInt16 files {};
	private:
		UInt8 padding[2] {};
	public:
		// Array of [0..files) DBI name buffer offsets
		UInt32 fileNameOffsets {};

		// Name Index for the source file name
		UInt32 sourceFileNameIndex {};

		// Name Index for the path to the compiler PDB
		UInt32 pdbFilePathNumberIndex {};

		// After the header there are two zero terminated strings
		// char moduleName[];
		// char objectFileName[];
	};
	struct SectionOffset {
		UInt32 offset {};
		UInt16 sectionIndex {};
	private:
		UInt8  padding[2] {};
	};
	struct HashTable {
		UInt32 size {};
		UInt32 capacity {};
	};

	struct SegmentMapHeader {
		UInt16 numberOfSegmentDescriptors {};
		UInt16 numberOfLogicalSegmentDescriptors {};
	};
	struct SegmentMapEntry {
		UInt16 flags {}; // Descriptor flags (SegmentDescriptorFlags enum)
		UInt16 ov1 {};   // Logical overlay number
		UInt16 group {}; // Group index into the descriptor array
		UInt16 frame {};
		UInt16 segmentName {};       // Byte index of the segment or group name in the sstSegName table, or 0xFFFF
		UInt16 className {};         // Byte index of the class name in the sstSegName table, or 0xFFFF
		UInt32 offset {};            // Byte offset of the logical segment within the specified physical segment (if the group is set in flags, offset is the offset of the group)
		UInt16 segmentByteLength {}; // Byte count of the segment or group
	};

	// Variable-specific types
	// CV_fldattr_t
	enum struct MemberAccess: UInt8 {
		NONE = 0,
		PRIVATE = 1,
		PROTECTED = 2,
		PUBLIC = 3
	};
	enum struct MethodType: UInt8 {
		VANILLA,
		VIRTUAL,
		STATIC,
		FRIEND,
		INTRODUCING_VIRTUAL,
		PURE_VIRTUAL,
		PURE_INTRODUCING_VIRTUAL
	};
	struct FieldAttributes {
		MemberAccess access: 2 {};
		MethodType methodProperties: 3 {};
		bool pseudo: 1 {};
		bool noInherit: 1 {};
		bool noConstruct: 1 {};
		bool compilerGenerated: 1 {};
		bool sealed: 1 {};
	};
	static_assert(sizeof(FieldAttributes) == sizeof(UInt16));
}