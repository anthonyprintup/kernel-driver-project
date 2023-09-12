#pragma once

#include <sal.h>

namespace detail {
	struct AtExitEntry {
		using DestructorType = void(__cdecl*)();

		AtExitEntry(__in DestructorType destructor,
					__in AtExitEntry *next);
		~AtExitEntry();

		[[nodiscard]] AtExitEntry *next() const noexcept;
	private:
		DestructorType  _destructor;
		AtExitEntry    *_next;
	};

	static AtExitEntry *gTopAtExitEntry {};
}

extern "C" {
	int  __cdecl cc_atexit(__in detail::AtExitEntry::DestructorType destructor);
	int  __cdecl cc_init(__in int);
	void __cdecl cc_doexit(__in int, __in int, __in int);
}