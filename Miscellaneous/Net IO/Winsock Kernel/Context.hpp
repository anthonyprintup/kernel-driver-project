// ReSharper disable CppNonExplicitConvertingConstructor
#pragma once

#include <memory>
#include <cstdint>

#include "../../../Utilities/NT/Definitions.hpp"

namespace KM::Miscellaneous::NetIo::WinsockKernel {
	namespace detail {
		void irpDeleter(PIRP irp) noexcept;
		NTSTATUS irpCompletionRoutine(PDEVICE_OBJECT, PIRP, PVOID event) noexcept;
	}
	
	struct Context {
		using EventPointer = std::unique_ptr<KEVENT>;
		using IrpPointer   = std::unique_ptr<IRP, decltype(&detail::irpDeleter)>;

		EventPointer  event {};
		IrpPointer    irp   {nullptr, &detail::irpDeleter};
		std::int64_t  _timeout {-30ll * 1'000'000'000 / 100}; // Default timeout is 30s, which should leave enough time for most operations (units of 100ns)

		Context(std::uint8_t stackSize = 1) noexcept;
		void reuse() const noexcept;
		void timeout(std::int64_t value) noexcept;
		[[nodiscard]] NTSTATUS wait() const noexcept;
		[[nodiscard]] explicit operator bool() const noexcept;
	};

	template<class T>
	requires std::is_same_v<T, Context>
	Context create() noexcept { return {}; }
}
