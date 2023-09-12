#include "Reader.hpp"

using namespace stream;

#include "../msf/Leaf Type.hpp"
using namespace msf;

#include "../../../Configuration.hpp"

Reader::Reader(const SpanType data) noexcept:
	_data {data} {}

Reader::Reader(const SpanType::const_pointer pointer, const SpanType::size_type size) noexcept:
	_data {pointer, size} {}

Reader::Reader(const void *pointer, SpanType::size_type size) noexcept:
	_data {static_cast<SpanType::const_pointer>(pointer), size} {}

SpanType::const_pointer Reader::data() const noexcept {
	return this->_data.data();
}

SpanType::size_type Reader::size() const noexcept {
	return this->_data.size_bytes();
}

DifferenceType &Reader::offset() noexcept {
	return this->_offset;
}

DifferenceType Reader::offset() const noexcept {
	return this->_offset;
}

bool Reader::empty() const noexcept {
	return static_cast<SpanType::size_type>(this->offset()) >= this->size();
}

std::size_t Reader::remaining() const noexcept {
	if (this->empty())
		return {};
	return this->size() - static_cast<SpanType::size_type>(this->offset());
}

Reader &Reader::advance(const DifferenceType distance) noexcept {
	this->offset() += distance;
	return *this;
}

Reader &Reader::skip(const std::size_t distance) noexcept {
	this->offset() += static_cast<DifferenceType>(distance);
	return *this;
}

Reader Reader::slice(const std::size_t offset, const SpanType::size_type size) const noexcept {
	return this->_data.subspan(offset ? offset : this->offset(), size);
}

std::uint8_t Reader::peek() const noexcept {
	return *(this->data() + this->offset());
}

void Reader::skipPadding() noexcept {
	if (this->empty())
		return;

	const auto leaf = this->peek();
	if (leaf < LeafType::PAD0)
		return;

	const auto bytesToAdvance = leaf & 0x0F;
	this->advance(bytesToAdvance);
}

SignAwareInteger Reader::parseInteger() noexcept {
	VM_SIZE_SPEED_BEGIN
	const auto value = this->read<const UInt16*>();
	const auto type = static_cast<LeafType>(*value);

	SpanType data {};
	bool isSigned {};
	if (type < LeafType::NUMERIC) {
		data = {reinterpret_cast<const UInt8*>(value), sizeof(UInt16)};
		isSigned = false;
	} else if (type == LeafType::CHAR) {
		data = {reinterpret_cast<const UInt8*>(value) + sizeof(*value), sizeof(Int8)};
		isSigned = true;
	} else if (type == LeafType::SHORT) {
		data = {reinterpret_cast<const UInt8*>(value) + sizeof(*value), sizeof(Int16)};
		isSigned = true;
	} else if (type == LeafType::USHORT) {
		data = {reinterpret_cast<const UInt8*>(value) + sizeof(*value), sizeof(UInt16)};
		isSigned = false;
	} else if (type == LeafType::LONG) {
		data = {reinterpret_cast<const UInt8*>(value) + sizeof(*value), sizeof(Int32)};
		isSigned = true;
	} else if (type == LeafType::ULONG) {
		data = {reinterpret_cast<const UInt8*>(value) + sizeof(*value), sizeof(UInt32)};
		isSigned = false;
	} else if (type == LeafType::QUADWORD) {
		data = {reinterpret_cast<const UInt8*>(value) + sizeof(*value), sizeof(Int64)};
		isSigned = true;
	} else if (type == LeafType::UQUADWORD) {
		data = {reinterpret_cast<const UInt8*>(value) + sizeof(*value), sizeof(UInt64)};
		isSigned = false;
	}

	if (type >= LeafType::NUMERIC)
		this->advance(static_cast<DifferenceType>(data.size_bytes()));

	const SignAwareInteger result {{data, data.size_bytes() * CHAR_BIT, isSigned}, !isSigned};
	VM_SIZE_SPEED_END
	return result;
}
