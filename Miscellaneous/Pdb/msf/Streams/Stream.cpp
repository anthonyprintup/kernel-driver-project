#include "Stream.hpp"

using namespace msf::streams;

Stream::Stream(std::unique_ptr<MappedBlockStream> blockStream) noexcept:
	stream {std::move(blockStream)}, reader {this->stream->bytes.data(), this->stream->bytes.size()} {}
