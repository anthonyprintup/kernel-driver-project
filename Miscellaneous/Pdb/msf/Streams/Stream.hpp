#pragma once

#include "Mapped Block.hpp"
#include "../../Data Stream/Reader.hpp"

#include <memory>

namespace msf::streams {
	class Stream {
		std::unique_ptr<MappedBlockStream> stream {};
	public:
		stream::Reader reader {};

		explicit Stream(std::unique_ptr<MappedBlockStream> blockStream) noexcept;
	};
}
