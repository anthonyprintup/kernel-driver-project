#pragma once

#include "Msf Layouts.hpp"
#include "../../Data Stream/Stream.hpp"

namespace msf::streams {
	struct MappedBlockStream {
		const UInt32 blockSize {};
		const MsfStreamLayout streamLayout {};
		std::vector<UInt8> bytes {};

		void readBlocks(const MsfLayout &msf, stream::SpanType bytes);
	};
}
