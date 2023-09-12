#include "Symbol Records.hpp"

using namespace msf::streams;

SymbolRecords::SymbolRecords(std::unique_ptr<MappedBlockStream> stream) noexcept:
	Stream {std::move(stream)} {}
