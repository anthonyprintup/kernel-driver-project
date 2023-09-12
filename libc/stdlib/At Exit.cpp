#include "At Exit.hpp"

#include "../Memory.hpp"

#pragma region Sections
#pragma section(".CRT$XCA", long, read)
	__declspec(allocate(".CRT$XCA")) void(*__ctors_begin__[1])() {};
	#pragma section(".CRT$XCZ", long, read)
	__declspec(allocate(".CRT$XCZ")) void(*__ctors_end__[1])() {};
#pragma data_seg()

#pragma data_seg(".STL$A")
	void(*___StlStartInitCalls__[1])() {};
	#pragma data_seg(".STL$L")
	void(*___StlEndInitCalls__[1])() {};
	#pragma data_seg(".STL$M")
	void(*___StlStartTerminateCalls__[1])() {};
	#pragma data_seg(".STL$Z")
	void(*___StlEndTerminateCalls__[1])() {};
#pragma data_seg()
#pragma endregion Sections

namespace detail {
	AtExitEntry::AtExitEntry(const DestructorType destructor, AtExitEntry *next) {
		this->_destructor = destructor;
		this->_next       = next;
	}

	AtExitEntry::~AtExitEntry() {
		this->_destructor();
	}

	AtExitEntry *AtExitEntry::next() const noexcept {
		return this->_next;
	}

}

using DestructorType = detail::AtExitEntry::DestructorType;
extern "C" int __cdecl atexit(__in const DestructorType destructor) {
	if (!destructor)
		return 0;

	const auto entry = new detail::AtExitEntry {destructor, detail::gTopAtExitEntry};
	if (!entry)
		return 0;

	detail::gTopAtExitEntry = entry;
	return 1;
}

void cc_doexit(__in int, __in int, __in int) {
	for (auto entry = detail::gTopAtExitEntry; entry;) {
		const auto next = entry->next();
		delete entry;

		entry = next;
	}
}

int cc_init(__in int) {
	for (auto constructor = __ctors_begin__ + 1;
		 *constructor && constructor < __ctors_end__;
		 constructor++)
		(*constructor)();

	return 0;
}