#pragma once

#include "Nt/Definitions.hpp"

namespace KM::Utilities {
	struct Mutex {
		FAST_MUTEX mutex {};

		Mutex() noexcept;

		void acquire() noexcept;
		bool tryAcquire() noexcept;
		void release() noexcept;
	};
}
