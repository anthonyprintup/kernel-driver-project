#pragma once

#include <string>

namespace KM::Utilities::Strings {
	std::wstring unicode(std::string_view asciiString);
	std::string  ascii(std::wstring_view wideString);
}
