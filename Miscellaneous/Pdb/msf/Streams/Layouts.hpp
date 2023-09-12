#pragma once

#include <memory>

#include "Mapped Block.hpp"

namespace msf::streams {
	[[nodiscard]] std::unique_ptr<MappedBlockStream> createStream(UInt32 blockSize, const MsfStreamLayout &layout);
	[[nodiscard]] std::unique_ptr<MappedBlockStream> createIndexedStream(const MsfLayout &msf, UInt32 streamIndex);

	[[nodiscard]] UInt32 getFpmIntervals(const MsfLayout &msf) noexcept;
	[[nodiscard]] UInt32 getFpmInternalLength(const MsfLayout &msf) noexcept;
	[[nodiscard]] MsfStreamLayout fpmStreamLayout(const MsfLayout &msf, bool alternateFpm = false);
	[[nodiscard]] std::unique_ptr<MappedBlockStream> fpmStream(const MsfLayout &msf, stream::SpanType bytes);
	[[nodiscard]] std::unique_ptr<MappedBlockStream> directoryStream(const MsfLayout &msf, stream::SpanType bytes);
}
