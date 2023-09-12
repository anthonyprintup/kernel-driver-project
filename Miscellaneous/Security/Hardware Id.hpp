#pragma once

#include <cstddef>

#include "../Net IO/TLS/Array.hpp"

namespace KM::Miscellaneous::hwid {
	constexpr std::size_t sha512HashSize {64ull};
	using HashBuffer = tls::Array<sha512HashSize>;
	struct HardwareId {
		HashBuffer
			// All smbios entries combined
			genericSmbios {},
			// Specific smbios entries
			biosInformation {}, systemInformation {},
			systemEnclosure {}, processorInformation {},
			cacheInformation {}, systemSlots {}, memoryDevice {},
			// efi
			efi {};

		[[nodiscard]] HardwareId();
	};
	__declspec(noinline) HashBuffer efi() noexcept;
}
