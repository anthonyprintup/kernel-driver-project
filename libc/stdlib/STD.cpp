#include <ctime>
#include <ntddk.h>
#include <exception>

namespace impl {
	
}

namespace std {
	void __cdecl _Xbad_alloc() {
		DbgBreakPoint();
	}

	void __cdecl _Xlength_error(__in const char*) {
		DbgBreakPoint();
	}

	void __cdecl _Xout_of_range(__in const char*) {
		DbgBreakPoint();
	}

	const char *__cdecl _Syserror_map(__in int) {
		DbgBreakPoint();
		return nullptr;
	}

	const char *__cdecl _Winerror_map(__in int) {
		DbgBreakPoint();
		return nullptr;
	}

	void __cdecl _Xinvalid_argument(char const*){
		DbgBreakPoint();
	}

	void __cdecl _Xbad_function_call() {
		DbgBreakPoint();
	}

	void __cdecl handler(const std::exception&) { DbgBreakPoint(); }
	void(__cdecl *_Raise_handler)(const std::exception&) {&handler};
}

extern "C" {
	long long __cdecl _Query_perf_counter() {
		return KeQueryPerformanceCounter(nullptr).QuadPart;
	}

	long long __cdecl _Query_perf_frequency() {
		LARGE_INTEGER li;
		KeQueryPerformanceCounter(&li);
		return li.QuadPart;
	}

	int lastError {};
	int *__cdecl _errno() {
		return &lastError;
	}

	DECLSPEC_NORETURN void __cdecl _invalid_parameter_noinfo_noreturn() {
		DbgBreakPoint(); 
	}

	void __std_terminate() {
		DbgBreakPoint();
	}

	typedef long long time64_t;
	static const int days[4][13] = {
		{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
		{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
		{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
		{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366},
	};
	
	#define LEAP_CHECK(n)    ((!(((n) + 1900) % 400) || (!(((n) + 1900) % 4) && (((n) + 1900) % 100))) != 0)
	#define WRAP(a,b,m)    ((a) = ((a) <  0  ) ? ((b)--, (a) + (m)) : (a))
	
	_Check_return_opt_ _ACRTIMP __time64_t __cdecl _mktime64(_Inout_ struct tm * t) {
		int i, y;
		long day = 0;
		__time64_t r;
		if (t->tm_year < 70) {
			y = 69;
			do {
				day -= 365 + LEAP_CHECK (y);
				y--;
			} while (y >= t->tm_year);
		} else {
			y = 70;
			while (y < t->tm_year) {
				day += 365 + LEAP_CHECK (y);
				y++;
			}
		}
		for (i = 0; i < t->tm_mon; i++)
			day += days[LEAP_CHECK (t->tm_year)][i];
		day += t->tm_mday - 1;
		t->tm_wday = static_cast<int>((day + 4) % 7);
		r = static_cast<__time64_t>(day) *86400;
		r += t->tm_hour * 3600;
		r += t->tm_min * 60;
		r += t->tm_sec;
		return r;
	}
}