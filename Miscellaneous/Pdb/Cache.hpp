#pragma once

#include "msf/Pdb.hpp"
#include "Container.hpp"

#include <Framework/Utilities/Strings/Fnv1A.hpp>
using Hash = Framework::Utilities::Strings::Fnv1A::Hash;

namespace pdb {
	struct Cache {
		Cache(const msf::Pdb &pdb);
	
		[[nodiscard]] const msf::types::Structure *structure(Hash hash) const noexcept;
		[[nodiscard]] const msf::types::Structure *structure(const msf::types::Variable *variable) const noexcept;
		[[nodiscard]] const msf::types::Union *unions(Hash hash) const noexcept;
		[[nodiscard]] const msf::types::Union *unions(const msf::types::Variable *variable) const noexcept;
		[[nodiscard]] const msf::types::Enum *enums(Hash hash) const noexcept;
		[[nodiscard]] const msf::types::Enum *enums(const msf::types::Variable *variable) const noexcept;
		[[nodiscard]] const msf::types::BitField *bitField(const msf::types::Variable *variable) const noexcept;
		[[nodiscard]] const msf::types::Array *array(const msf::types::Variable *variable) const noexcept;
	private:
		Container container {};
	};
}
