#pragma once

#include <memory>

#include "../../../Utilities/NT/Definitions.hpp"

namespace KM::Miscellaneous::NetIo::WinsockKernel {
	template<class T>
	requires std::is_same_v<T, ADDRINFOEXW> || std::is_same_v<T, ADDRINFOW> || std::is_same_v<T, ADDRINFOEXA> || std::is_same_v<T, ADDRINFOA>
	struct AddressInformation {
		using BaseType = T;
		using UnderlyingStringType = std::conditional_t<std::is_same_v<char*, decltype(T::ai_canonname)>, char[], wchar_t[]>;
		
		std::unique_ptr<BaseType> base {};
		struct {
			std::unique_ptr<UnderlyingStringType> buffer {};
			std::size_t length {};
		} name {};
		std::unique_ptr<AddressInformation<BaseType>> next {};

		__forceinline [[nodiscard]] BaseType *release() noexcept {
			if (this->next) {
				this->base->ai_next = this->next->release();
				this->next.reset();
			}

			this->name.buffer.release();
			return this->base.release();
		}
	};

	namespace detail {
		AddressInformation<ADDRINFOEXW> convert(const addrinfo    *information);
		AddressInformation<addrinfo>    convert(const ADDRINFOEXW *information);
	}
}
