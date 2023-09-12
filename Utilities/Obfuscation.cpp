#include "Obfuscation.hpp"

using namespace KM::Utilities;

#include "../Miscellaneous/Globals.hpp"

extern "C" bool generateRandomData(void*, std::size_t);
void Obfuscation::randomBytesImplementation(std::uint8_t *buffer, const std::size_t size) {
	VM_SIZE_SPEED_BEGIN
	generateRandomData(buffer, size);
	VM_SIZE_SPEED_END
}
