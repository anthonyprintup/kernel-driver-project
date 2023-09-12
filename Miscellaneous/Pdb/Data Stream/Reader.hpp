#pragma once

#include "Stream.hpp"
#include "Integer.hpp"

namespace stream {
	struct Reader {
		Reader() = default;
		Reader(SpanType data) noexcept;
		Reader(SpanType::const_pointer pointer, SpanType::size_type size) noexcept;
		Reader(const void *pointer, SpanType::size_type size) noexcept;

		[[nodiscard]] SpanType::const_pointer data() const noexcept;
		[[nodiscard]] SpanType::size_type size() const noexcept;
		[[nodiscard]] DifferenceType &offset() noexcept;
		[[nodiscard]] DifferenceType offset() const noexcept;
		[[nodiscard]] bool empty() const noexcept;
		[[nodiscard]] std::size_t remaining() const noexcept;
		Reader &advance(DifferenceType distance) noexcept;
		Reader &skip(std::size_t distance) noexcept;
		[[nodiscard]] Reader slice(std::size_t offset = 0ull, SpanType::size_type size = SpanType::extent) const noexcept;

		template<class T>
		requires std::is_integral_v<T> || std::is_enum_v<T>
		[[nodiscard]] T read() noexcept {
			T value {};

			auto &offset = this->offset();
			std::memcpy(&value, this->data() + offset, sizeof(T));
			offset += sizeof(T);

			return value;
		}

		template<class T, class ValueType = std::remove_pointer_t<T>, class PointerType = std::add_const_t<ValueType>*>
		requires (std::is_pointer_v<T> && !std::is_pointer_v<ValueType>)
		[[nodiscard]] PointerType read() noexcept {
			auto &offset = this->offset();
			const auto pointer = reinterpret_cast<PointerType>(this->data() + offset);
			offset += sizeof(ValueType);

			return pointer;
		}

		template<class T>
		requires std::is_same_v<T, std::string_view>
		[[nodiscard]] std::string_view read() noexcept {
			auto &offset = this->offset();
			const auto string = reinterpret_cast<const char*>(this->data() + offset);
			const auto stringLength = std::strlen(string);
			offset += static_cast<DifferenceType>(stringLength + sizeof('\0'));

			return {string, stringLength};
		}

		template<class T>
		requires std::is_same_v<T, SignAwareInteger>
		[[nodiscard]] SignAwareInteger read() noexcept {
			return this->parseInteger();
		}

		[[nodiscard]] std::uint8_t peek() const noexcept;
		void skipPadding() noexcept;
	private:
		SpanType _data {};
		DifferenceType _offset {};

		[[nodiscard]] SignAwareInteger parseInteger() noexcept;
	};
}
