// ReSharper disable CppNonExplicitConvertingConstructor
// ReSharper disable CppInconsistentNaming
// ReSharper disable CppDoxygenUndocumentedParameter
#pragma once

#include <functional>
#include <optional>
#include <string_view>
#include <array>
#include <span>

#include "Definitions.hpp"
#include <Framework/Declarations.hpp>

namespace KM::Utilities::NT {
	namespace Kernel {
		namespace detail {
			void dereference(PVOID object) noexcept;
			auto resolveDriverObject(std::wstring_view name) noexcept;
		}
		
		struct Driver {
			Driver() noexcept = default;
			Driver(std::wstring_view driverName) noexcept;
			~Driver() noexcept;
			
			explicit operator bool() const noexcept;

			PDRIVER_OBJECT driver {};
		};
		template<class T>
		struct Referenced {
			using Type = std::conditional_t<std::is_pointer_v<T>, T, T*>;
			Type object {};

			~Referenced() noexcept {
				if (this->object)
					detail::dereference(this->object);
			}
			explicit operator bool() const noexcept {
				return this->object != nullptr;
			}
			explicit operator Type() const noexcept {
				return this->object;
			}
		};
		
		Driver driver(std::wstring_view name) noexcept;
		std::uintptr_t ntoskrnl() noexcept;
		std::uintptr_t keServiceDescriptorTableShadow() noexcept;
		std::pair<std::uintptr_t, std::size_t> module(Hash hash) noexcept;

		Referenced<PEPROCESS> process(Hash hash) noexcept;
		Referenced<PEPROCESS> process(std::uint32_t processId) noexcept;

		NTSTATUS protectMemory(PEPROCESS process, std::uintptr_t virtualAddress, std::size_t size, std::uint32_t newProtection, std::uint32_t &oldProtection) noexcept;

		void iterateThreads(std::function<bool(PEPROCESS, PETHREAD)> &&callback);

		std::pair<NTSTATUS, std::vector<std::uint8_t>> readFile(std::wstring_view path);
		NTSTATUS writeFile(std::wstring_view path, std::span<const std::uint8_t> buffer, bool append = false);
	}
	namespace User {
		std::optional<MemoryBasicInformationType> memoryInformation(PEPROCESS process, std::uintptr_t virtualAddress);
		bool validMemory(const MemoryBasicInformationType &memoryInformation) noexcept;
		bool validMemory(PEPROCESS process, std::uintptr_t virtualAddress, std::size_t size = 0) noexcept;
		
		/**
		 * \brief Copies memory from a process' VA to a another process' VA
		 * \param from The process where the buffer resides in (destination)
		 * \param to The process where the virtual address resides in (origin)
		 * \param fromVirtualAddress The virtual address in the target process where the data is copied from
		 * \param toVirtualAddress The virtual address in the base process where the data is copied to
		 * \param size The size of the buffer/data
		 */
		NTSTATUS copyMemory(PEPROCESS from, std::uintptr_t fromVirtualAddress, PEPROCESS to, std::uintptr_t toVirtualAddress,
							std::size_t size, bool ignorePageProtection = false) noexcept;
		std::pair<NTSTATUS, std::uintptr_t>
		allocateMemory(PEPROCESS process, std::uint64_t zeroBits, std::size_t size, std::uint32_t type, std::uint32_t protection) noexcept;
		NTSTATUS freeMemory(PEPROCESS process, std::uintptr_t virtualAddress, std::size_t size, std::uint32_t type) noexcept;
		
		bool queueApc(PETHREAD thread, std::uintptr_t virtualAddress, std::array<std::uint64_t, 3> arguments, bool force = false) noexcept;

		bool terminating(PEPROCESS process) noexcept;

		void iterateEnvironmentVariables(PEPROCESS process, std::function<bool(std::wstring_view, std::wstring_view)> &&visitor);
	}
	namespace PE {
		struct CodeViewInformation {
			std::uint32_t signature {};
			GUID guid {};
			std::uint32_t age {};
			const char name[1] {};
		};

		std::uintptr_t exported(std::uintptr_t base, Hash hash) noexcept;
		std::pair<std::uintptr_t, std::size_t> section(std::uintptr_t base, Hash hash) noexcept;
		const CodeViewInformation *codeViewDebugInformation(std::uintptr_t base) noexcept;
		std::optional<std::string> generatePdbUrlPath(const CodeViewInformation *codeViewDebugInformation);
	}
}
