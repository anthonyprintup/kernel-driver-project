#pragma once

#include <Framework/Utilities/Random Number Generator.hpp>

#include <array>
#include <emmintrin.h>

#ifndef PTROBF_FORCEINLINE
#ifdef _MSC_VER
#define PTROBF_FORCEINLINE __forceinline
#else
#define PTROBF_FORCEINLINE __attribute__((always_inline)) inline
#endif
#endif

namespace KM::Utilities::Obfuscation {
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto positionIndicatorKey() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::uint8_t, Seed + 9>(0x01, 0xFF);
	}
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto positionIndicatorRotateImmediate() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::uint8_t, Seed + 10>(0x10, 0xFF);
	}
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto pointerRotateImmediate() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::uint8_t, Seed + 11>(3, 58);
	}
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto pointerLoopImmediate() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::uint8_t, Seed + 12>(7, 81);
	}

	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto key0() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::size_t, Seed + 16>(0x1111111111111111, 0xEEEEEEEEEEEEEEEE);
	}
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto key1() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::size_t, Seed + 18>(0x1111111111111111, 0xEEEEEEEEEEEEEEEE);
	}
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto key2() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::size_t, Seed + 20>(0x1111111111111111, 0xEEEEEEEEEEEEEEEE);
	}
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto key3() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::size_t, Seed + 22>(0x1111111111111111, 0xEEEEEEEEEEEEEEEE);
	}
	template<std::size_t Seed>
	PTROBF_FORCEINLINE [[nodiscard]] constexpr auto key4() noexcept {
		return Framework::Utilities::RandomNumberGenerators::compileTimeGenerator<std::size_t, Seed + 24>(0x1111111111111111, 0xEEEEEEEEEEEEEEEE);
	}

	__declspec(noinline) void randomBytesImplementation(std::uint8_t *buffer, std::size_t size);
	template<std::size_t Size>
	PTROBF_FORCEINLINE std::array<std::uint8_t, Size> randomBytes() noexcept {
		std::array<std::uint8_t, Size> buffer {};
		randomBytesImplementation(buffer.data(), buffer.size());
		return buffer;
	}

	#pragma pack(push, 1)
	template<class T, std::size_t Seed>
	struct Pointer {
		using PointerType = const T*;
		using MutablePointerType = T*;
		using ValueType = T;

		template<class... Arguments>
		PTROBF_FORCEINLINE Pointer(Arguments &&...arguments) noexcept {
			*this = new (std::nothrow) ValueType {std::forward<Arguments>(arguments)...}; 
		}
		Pointer(const Pointer&) = delete;
		Pointer(Pointer&&) = delete;
		PTROBF_FORCEINLINE ~Pointer() {
			this->free();
		}

		auto operator =(const Pointer&) = delete;
		auto operator =(Pointer&&) = delete;

		PTROBF_FORCEINLINE void free() noexcept {
			auto pointer = this->decrypt();
			std::memset(pointer, 0, sizeof(ValueType));
			delete pointer;
			*this = nullptr;
		}
		PTROBF_FORCEINLINE void operator =(PointerType pointer) noexcept {
			// [indicator][padding][ptr: 8 bytes][padding]
			// 00112233445566778899AABBCCDDEEFF
			// ..|||||||||XXXXXXXXXXXX|||||||||
			// ..|||||||||XXXXXXXXXXXX|||||||||

			// Override the storage buffer
			{
				const auto randomBuffer = randomBytes<storageBytes>();
				std::memcpy(this->storage, randomBuffer.data(), randomBuffer.size());
			}

			// [1, 255]
			auto positionIndicator = randomBytes<sizeof(std::uint8_t)>().front();
			while (!positionIndicator || positionIndicator % 9 == 0) positionIndicator = randomBytes<sizeof(std::uint8_t)>().front();
			const auto obfuscatedPositionIndicator = _rotr8(positionIndicator ^ positionIndicatorKey<Seed>(), positionIndicatorRotateImmediate<Seed>());

			// Obfuscated pointer value
			auto obfuscatedPointerValue = reinterpret_cast<std::uintptr_t>(pointer);
			for (std::size_t i {}; i < pointerLoopImmediate<Seed>(); ++i)
				obfuscatedPointerValue = (_rotr64(obfuscatedPointerValue ^ key0<Seed>(), pointerRotateImmediate<Seed>()) ^ positionIndicator) + key3<Seed>();
			if constexpr (Seed % 2 == 0)
				obfuscatedPointerValue = _byteswap_uint64(obfuscatedPointerValue);
			if constexpr (Seed % 3 == 0)
				obfuscatedPointerValue -= key4<Seed>();

			alignas(sizeof(__m128i)) auto randomBuffer = randomBytes<storageBytes>();
			std::memcpy(randomBuffer.data() + positionIndicator % 9, &obfuscatedPointerValue, sizeof(obfuscatedPointerValue));
			randomBuffer[0] = obfuscatedPositionIndicator;

			*reinterpret_cast<__m128i*>(&this->storage) = _mm_xor_si128(*reinterpret_cast<__m128i*>(randomBuffer.data()), _mm_set_epi64x(key1<Seed>(), key2<Seed>()));
		}
		PTROBF_FORCEINLINE ValueType &operator =(const ValueType value) noexcept {
			const auto pointer = this->decrypt();
			*pointer = value;

			return *pointer;
		}
		PTROBF_FORCEINLINE [[nodiscard]] MutablePointerType decrypt() noexcept {
			const auto buffer = _mm_xor_si128(*reinterpret_cast<__m128i*>(this->storage), _mm_set_epi64x(key1<Seed>(), key2<Seed>()));
			const auto positionIndicator = _rotl8(reinterpret_cast<const std::uint8_t*>(&buffer)[0], positionIndicatorRotateImmediate<Seed>()) ^ positionIndicatorKey<Seed>();

			auto obfuscatedPointer = *reinterpret_cast<const std::uintptr_t*>(reinterpret_cast<const std::uint8_t*>(&buffer) + positionIndicator % 9);
			if constexpr (Seed % 3 == 0)
				obfuscatedPointer += key4<Seed>();
			if constexpr (Seed % 2 == 0)
				obfuscatedPointer = _byteswap_uint64(obfuscatedPointer);
			for (std::size_t i {}; i < pointerLoopImmediate<Seed>(); ++i)
				obfuscatedPointer = _rotl64(obfuscatedPointer - key3<Seed>() ^ positionIndicator, pointerRotateImmediate<Seed>()) ^ key0<Seed>();

			const auto pointer = reinterpret_cast<MutablePointerType>(obfuscatedPointer);
			*this = pointer;
			return pointer;
		}
		PTROBF_FORCEINLINE [[nodiscard]] MutablePointerType operator ->() noexcept {
			return this->decrypt();
		}
		PTROBF_FORCEINLINE [[nodiscard]] ValueType &operator *() noexcept {
			return *this->decrypt();
		}
	private:
		static constexpr std::size_t storageBytes {16};
		alignas(storageBytes) std::uint8_t storage[storageBytes] {};
	};
	#pragma pack(pop)
}
