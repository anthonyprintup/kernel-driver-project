#include "Public Symbol.hpp"

using namespace msf::types;

std::string_view PublicSymbol32::name() const noexcept {
	return reinterpret_cast<const char*>(this->_name);
}
