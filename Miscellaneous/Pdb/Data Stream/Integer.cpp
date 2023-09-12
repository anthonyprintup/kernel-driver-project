#include "Integer.hpp"

using namespace stream;

#include "../msf/Types.hpp"
using namespace msf;

#include "../../../Configuration.hpp"

SignAwareInteger::operator std::size_t() const noexcept {
	VM_SIZE_SPEED_BEGIN
	if (this->data.size_bytes() > sizeof(unsigned long long))
		return {};

	if (this->data.size_bytes() == sizeof(Int8) && !this->isUnsigned)
		return static_cast<std::size_t>(*reinterpret_cast<const Int8*>(this->data.data()));
	if (this->data.size_bytes() == sizeof(UInt8) && this->isUnsigned)
		return static_cast<std::size_t>(*this->data.data());

	if (this->data.size_bytes() == sizeof(Int16) && !this->isUnsigned)
		return static_cast<std::size_t>(*reinterpret_cast<const Int16*>(this->data.data()));
	if (this->data.size_bytes() == sizeof(UInt16) && this->isUnsigned)
		return static_cast<std::size_t>(*reinterpret_cast<const UInt16*>(this->data.data()));

	if (this->data.size_bytes() == sizeof(Int32) && !this->isUnsigned)
		return static_cast<std::size_t>(*reinterpret_cast<const UInt32*>(this->data.data()));
	if (this->data.size_bytes() == sizeof(UInt32) && this->isUnsigned)
		return static_cast<std::size_t>(*reinterpret_cast<const UInt32*>(this->data.data()));

	if (this->data.size_bytes() == sizeof(Int64) && !this->isUnsigned)
		return static_cast<std::size_t>(*reinterpret_cast<const Int64*>(this->data.data()));
	if (this->data.size_bytes() == sizeof(UInt64) && this->isUnsigned)
		return static_cast<std::size_t>(*reinterpret_cast<const UInt64*>(this->data.data()));
	VM_SIZE_SPEED_END
	return {};
}
