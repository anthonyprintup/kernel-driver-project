#include "Client.hpp"

using namespace http;

#include <Framework/Utilities/Strings/XorStr.hpp>
#include "../../Globals.hpp"
namespace nt = KM::Miscellaneous::Globals::NT;

#include <intrin.h>
#include <charconv>

Request::Request(const RequestMethod method, const std::string_view uri):
	_method {method} {
	VM_SIZE_SPEED_BEGIN
	const auto [host, data] = parseUri(uri);
	if (!data.empty())
		this->data(data);
	if (!host.empty())
		this->header(HeaderType::HOST, host);
	VM_SIZE_SPEED_END
}
Request::Request(const RequestMethod method, const std::string_view host, const std::string_view data):
	_method {method}, _data {data} {
	VM_SIZE_SPEED_BEGIN
	this->header(HeaderType::HOST, host);
	VM_SIZE_SPEED_END
}

void Request::method(const RequestMethod method) noexcept {
	this->_method = method;
}
void Request::data(const std::string_view data) noexcept {
	this->_data = data;
}
void Request::header(const HeaderType headerType, const std::string_view value) {
	VM_SIZE_SPEED_BEGIN
	if (const auto iterator = std::ranges::find_if(this->_headers, [&](const decltype(this->_headers)::value_type &entry) {
		return entry.header == headerType;
	}); iterator != this->_headers.end())
		iterator->value = value;
	else
		this->_headers.emplace_back(headerType, value);
	VM_SIZE_SPEED_END
	__nop(); // Prevent tailcall optimizations
}

void Request::set(const SpanType data) {
	VM_SIZE_SPEED_BEGIN
	if (data.empty())
		return;

	this->_content.clear();
	this->_content.reserve(data.size());

	this->_content.insert(this->_content.begin(), data.begin(), data.end());

	tls::Array<20> buffer {};
	const auto bufferData = reinterpret_cast<char*>(buffer.data());
	if (const auto [pointer, error] = std::to_chars(bufferData, bufferData + buffer.size(), this->_content.size());
		error != std::errc {})
		this->header(HeaderType::CONTENT_LENGTH, bufferData);
	VM_SIZE_SPEED_END
}
void Request::set(const std::string_view data) {
	this->set(SpanType {reinterpret_cast<const UnderlyingDataType*>(data.data()), data.size()});
}

void Request::append(const SpanType data) {
	VM_SIZE_SPEED_BEGIN
	if (data.empty())
		return;

	this->_content.reserve(this->_content.size() + data.size());
	this->_content.insert(this->_content.begin(), data.begin(), data.end());

	tls::Array<20> buffer {};
	const auto bufferData = reinterpret_cast<char*>(buffer.data());
	if (const auto [pointer, error] = std::to_chars(bufferData, bufferData + buffer.size(), this->_content.size());
		error != std::errc {})
		this->header(HeaderType::CONTENT_LENGTH, bufferData);
	VM_SIZE_SPEED_END
}
void Request::append(const std::string_view data) {
	this->append(SpanType {reinterpret_cast<const UnderlyingDataType*>(data.data()), data.size()});
}

Request::BufferType Request::build() {
	VM_SIZE_SPEED_BEGIN
	constexpr std::string_view crlf {"\r\n"};

	if (this->_method == RequestMethod::UNKNOWN)
		return {};

	BufferType buffer {};

	// Method + data + HTTP Protocol Version + CRLF
	{
		const auto format = xorstr_(R"(%s %s HTTP/1.1%s)");
		const auto formatMethod = [&](const char *method) {
			const auto defaultData = xorstr_("/");
			const auto data = this->_data.empty() ? defaultData : this->_data.data();
			
			// ReSharper disable once CppDeprecatedEntity
			const auto requiredSize = nt::_snprintf(nullptr, 0, format, method, data, crlf.data()) + 1;
			buffer.resize(buffer.size() + requiredSize);
			nt::_snprintf_s(reinterpret_cast<char*>(buffer.data()), requiredSize, _TRUNCATE, format, method, data, crlf.data());
			buffer.resize(buffer.size() - 1);
		};
		
		if (this->_method == RequestMethod::CONNECT)
			formatMethod(xorstr_("CONNECT"));
		else if (this->_method == RequestMethod::DELETE_)
			formatMethod(xorstr_("DELETE"));
		else if (this->_method == RequestMethod::GET)
			formatMethod(xorstr_("GET"));
		else if (this->_method == RequestMethod::HEAD)
			formatMethod(xorstr_("HEAD"));
		else if (this->_method == RequestMethod::OPTIONS)
			formatMethod(xorstr_("OPTIONS"));
		else if (this->_method == RequestMethod::PATCH)
			formatMethod(xorstr_("PATCH"));
		else if (this->_method == RequestMethod::POST)
			formatMethod(xorstr_("POST"));
		else if (this->_method == RequestMethod::PUT)
			formatMethod(xorstr_("PUT"));
		else if (this->_method == RequestMethod::TRACE)
			formatMethod(xorstr_("TRACE"));
	}

	// Headers
	{
		this->header(HeaderType::CONNECTION, xorstr_("close")); // set `Connection: close`

		const auto format = xorstr_(R"(%s: %s%s)");
		const auto formatHeader = [&](const char *header, const std::string_view value) {
			const auto previousSize = buffer.size();
			// ReSharper disable once CppDeprecatedEntity
			const auto requiredSize = nt::_snprintf(nullptr, 0, format, header, value.data(), crlf.data()) + 1;
			buffer.resize(previousSize + requiredSize);
			nt::_snprintf_s(reinterpret_cast<char*>(buffer.data() + previousSize), requiredSize, _TRUNCATE, format, header, value.data(), crlf.data());
			buffer.resize(buffer.size() - 1);
		};
		
		for (const auto &[header, value] : this->_headers) {
			if (header == HeaderType::ACCEPT_CH)
				formatHeader(xorstr_("Accept-CH"), value);
			else if (header == HeaderType::ACCEPT_CHARSET)
				formatHeader(xorstr_("Accept-Charset"), value);
			else if (header == HeaderType::ACCEPT_ENCODING)
				formatHeader(xorstr_("Accept-Encoding"), value);
			else if (header == HeaderType::ACCEPT_LANGUAGE)
				formatHeader(xorstr_("Accept-Language"), value);
			else if (header == HeaderType::ACCEPT_PATCH)
				formatHeader(xorstr_("Accept-Patch"), value);
			else if (header == HeaderType::ACCEPT_POST)
				formatHeader(xorstr_("Accept-Post"), value);
			else if (header == HeaderType::ACCEPT_RANGES)
				formatHeader(xorstr_("Accept-Ranges"), value);
			else if (header == HeaderType::ACCEPT)
				formatHeader(xorstr_("Accept"), value);
			else if (header == HeaderType::ACCESS_CONTROL_ALLOW_CREDENTIALS)
				formatHeader(xorstr_("Access-Control-Allow-Credentials"), value);
			else if (header == HeaderType::ACCESS_CONTROL_ALLOW_HEADERS)
				formatHeader(xorstr_("Access-Control-Allow-Headers"), value);
			else if (header == HeaderType::ACCESS_CONTROL_ALLOW_METHODS)
				formatHeader(xorstr_("Access-Control-Allow-Methods"), value);
			else if (header == HeaderType::ACCESS_CONTROL_ALLOW_ORIGIN)
				formatHeader(xorstr_("Access-Control-Allow-Origin"), value);
			else if (header == HeaderType::ACCESS_CONTROL_EXPOSE_HEADERS)
				formatHeader(xorstr_("Access-Control-Expose-Headers"), value);
			else if (header == HeaderType::ACCESS_CONTROL_MAX_AGE)
				formatHeader(xorstr_("Access-Control-Max-Age"), value);
			else if (header == HeaderType::ACCESS_CONTROL_REQUEST_HEADERS)
				formatHeader(xorstr_("Access-Control-Request-Headers"), value);
			else if (header == HeaderType::ACCESS_CONTROL_REQUEST_METHOD)
				formatHeader(xorstr_("Access-Control-Request-Method"), value);
			else if (header == HeaderType::AGE)
				formatHeader(xorstr_("Age"), value);
			else if (header == HeaderType::ALLOW)
				formatHeader(xorstr_("Allow"), value);
			else if (header == HeaderType::ALT_SVC)
				formatHeader(xorstr_("Alt-Svc"), value);
			else if (header == HeaderType::AUTHORIZATION)
				formatHeader(xorstr_("Authorization"), value);
			else if (header == HeaderType::CACHE_CONTROL)
				formatHeader(xorstr_("Cache-Control"), value);
			else if (header == HeaderType::CLEAR_SITE_DATA)
				formatHeader(xorstr_("Clear-Site-Data"), value);
			else if (header == HeaderType::CONNECTION)
				formatHeader(xorstr_("Connection"), value);
			else if (header == HeaderType::CONTENT_DISPOSITION)
				formatHeader(xorstr_("Content-Disposition"), value);
			else if (header == HeaderType::CONTENT_ENCODING)
				formatHeader(xorstr_("Content-Encoding"), value);
			else if (header == HeaderType::CONTENT_LANGUAGE)
				formatHeader(xorstr_("Content-Language"), value);
			else if (header == HeaderType::CONTENT_LENGTH)
				formatHeader(xorstr_("Content-Length"), value);
			else if (header == HeaderType::CONTENT_LOCATION)
				formatHeader(xorstr_("Content-Location"), value);
			else if (header == HeaderType::CONTENT_RANGE)
				formatHeader(xorstr_("Content-Range"), value);
			else if (header == HeaderType::CONTENT_SECURITY_POLICY_REPORT_ONLY)
				formatHeader(xorstr_("Content-Security-Policy-Report-Only"), value);
			else if (header == HeaderType::CONTENT_SECURITY_POLICY)
				formatHeader(xorstr_("Content-Security-Policy"), value);
			else if (header == HeaderType::CONTENT_TYPE)
				formatHeader(xorstr_("Content-Type"), value);
			else if (header == HeaderType::COOKIE)
				formatHeader(xorstr_("Cookie"), value);
			else if (header == HeaderType::CROSS_ORIGIN_EMBEDDER_POLICY)
				formatHeader(xorstr_("Cross-Origin-Embedder-Policy"), value);
			else if (header == HeaderType::CROSS_ORIGIN_OPENER_POLICY)
				formatHeader(xorstr_("Cross-Origin-Opener-Policy"), value);
			else if (header == HeaderType::CROSS_ORIGIN_RESOURCE_POLICY)
				formatHeader(xorstr_("Cross-Origin-Resource-Policy"), value);
			else if (header == HeaderType::DATE)
				formatHeader(xorstr_("Date"), value);
			else if (header == HeaderType::DEVICE_MEMORY)
				formatHeader(xorstr_("Device-Memory"), value);
			else if (header == HeaderType::DIGEST)
				formatHeader(xorstr_("Digest"), value);
			else if (header == HeaderType::DNT)
				formatHeader(xorstr_("DNT"), value);
			else if (header == HeaderType::DOWNLINK)
				formatHeader(xorstr_("Downlink"), value);
			else if (header == HeaderType::EARLY_DATA)
				formatHeader(xorstr_("Early-Data"), value);
			else if (header == HeaderType::ECT)
				formatHeader(xorstr_("ECT"), value);
			else if (header == HeaderType::ETAG)
				formatHeader(xorstr_("ETag"), value);
			else if (header == HeaderType::EXPECT_CT)
				formatHeader(xorstr_("Expect-CT"), value);
			else if (header == HeaderType::EXPECT)
				formatHeader(xorstr_("Expect"), value);
			else if (header == HeaderType::EXPIRES)
				formatHeader(xorstr_("Expires"), value);
			else if (header == HeaderType::FEATURE_POLICY)
				formatHeader(xorstr_("Feature-Policy"), value);
			else if (header == HeaderType::FORWARDED)
				formatHeader(xorstr_("Forwarded"), value);
			else if (header == HeaderType::FROM)
				formatHeader(xorstr_("From"), value);
			else if (header == HeaderType::HOST)
				formatHeader(xorstr_("Host"), value);
			else if (header == HeaderType::IF_MATCH)
				formatHeader(xorstr_("If-Match"), value);
			else if (header == HeaderType::IF_MODIFIED_SINCE)
				formatHeader(xorstr_("If-Modified-Since"), value);
			else if (header == HeaderType::IF_NONE_MATCH)
				formatHeader(xorstr_("If-None-Match"), value);
			else if (header == HeaderType::IF_RANGE)
				formatHeader(xorstr_("If-Range"), value);
			else if (header == HeaderType::IF_UNMODIFIED_SINCE)
				formatHeader(xorstr_("If-Unmodified-Since"), value);
			else if (header == HeaderType::KEEP_ALIVE)
				formatHeader(xorstr_("Keep-Alive"), value);
			else if (header == HeaderType::LARGE_ALLOCATION)
				formatHeader(xorstr_("Large-Allocation"), value);
			else if (header == HeaderType::LAST_MODIFIED)
				formatHeader(xorstr_("Last-Modified"), value);
			else if (header == HeaderType::LINK)
				formatHeader(xorstr_("Link"), value);
			else if (header == HeaderType::LOCATION)
				formatHeader(xorstr_("Location"), value);
			else if (header == HeaderType::NEL)
				formatHeader(xorstr_("NEL"), value);
			else if (header == HeaderType::ORIGIN)
				formatHeader(xorstr_("Origin"), value);
			else if (header == HeaderType::PROXY_AUTHENTICATE)
				formatHeader(xorstr_("Proxy-Authenticate"), value);
			else if (header == HeaderType::PROXY_AUTHORIZATION)
				formatHeader(xorstr_("Proxy-Authorization"), value);
			else if (header == HeaderType::RANGE)
				formatHeader(xorstr_("Range"), value);
			else if (header == HeaderType::REFERER)
				formatHeader(xorstr_("Referer"), value);
			else if (header == HeaderType::REFERRER_POLICY)
				formatHeader(xorstr_("Referrer-Policy"), value);
			else if (header == HeaderType::RETRY_AFTER)
				formatHeader(xorstr_("Retry-After"), value);
			else if (header == HeaderType::RTT)
				formatHeader(xorstr_("RTT"), value);
			else if (header == HeaderType::SAVE_DATA)
				formatHeader(xorstr_("Save-Data"), value);
			else if (header == HeaderType::SEC_FETCH_DEST)
				formatHeader(xorstr_("Sec-Fetch-Dest"), value);
			else if (header == HeaderType::SEC_FETCH_MODE)
				formatHeader(xorstr_("Sec-Fetch-Mode"), value);
			else if (header == HeaderType::SEC_FETCH_SITE)
				formatHeader(xorstr_("Sec-Fetch-Site"), value);
			else if (header == HeaderType::SEC_FETCH_USER)
				formatHeader(xorstr_("Sec-Fetch-User"), value);
			else if (header == HeaderType::SEC_WEBSOCKET_ACCEPT)
				formatHeader(xorstr_("Sec-WebSocket-Accept"), value);
			else if (header == HeaderType::SERVER_TIMING)
				formatHeader(xorstr_("Server-Timing"), value);
			else if (header == HeaderType::SERVER)
				formatHeader(xorstr_("Server"), value);
			else if (header == HeaderType::SET_COOKIE)
				formatHeader(xorstr_("Set-Cookie"), value);
			else if (header == HeaderType::SOURCEMAP)
				formatHeader(xorstr_("SourceMap"), value);
			else if (header == HeaderType::STRICT_TRANSPORT_SECURITY)
				formatHeader(xorstr_("Strict-Transport-Security"), value);
			else if (header == HeaderType::TE)
				formatHeader(xorstr_("TE"), value);
			else if (header == HeaderType::TIMING_ALLOW_ORIGIN)
				formatHeader(xorstr_("Timing-Allow-Origin"), value);
			else if (header == HeaderType::TK)
				formatHeader(xorstr_("Tk"), value);
			else if (header == HeaderType::TRAILER)
				formatHeader(xorstr_("Trailer"), value);
			else if (header == HeaderType::TRANSFER_ENCODING)
				formatHeader(xorstr_("Transfer-Encoding"), value);
			else if (header == HeaderType::UPGRADE_INSECURE_REQUESTS)
				formatHeader(xorstr_("Upgrade-Insecure-Requests"), value);
			else if (header == HeaderType::UPGRADE)
				formatHeader(xorstr_("Upgrade"), value);
			else if (header == HeaderType::USER_AGENT)
				formatHeader(xorstr_("User-Agent"), value);
			else if (header == HeaderType::VARY)
				formatHeader(xorstr_("Vary"), value);
			else if (header == HeaderType::VIA)
				formatHeader(xorstr_("Via"), value);
			else if (header == HeaderType::WANT_DIGEST)
				formatHeader(xorstr_("Want-Digest"), value);
			else if (header == HeaderType::WARNING)
				formatHeader(xorstr_("Warning"), value);
			else if (header == HeaderType::WWW_AUTHENTICATE)
				formatHeader(xorstr_("WWW_Authenticate"), value);
			else if (header == HeaderType::X_CONTENT_TYPE_OPTIONS)
				formatHeader(xorstr_("X_Content-Type-Options"), value);
			else if (header == HeaderType::X_DNS_PREFETCH_CONTROL)
				formatHeader(xorstr_("X_DNS_Prefetch-Control"), value);
			else if (header == HeaderType::X_FORWARDED_FOR)
				formatHeader(xorstr_("X_Forwarded-For"), value);
			else if (header == HeaderType::X_FORWARDED_HOST)
				formatHeader(xorstr_("X_Forwarded-Host"), value);
			else if (header == HeaderType::X_FORWARDED_PROTO)
				formatHeader(xorstr_("X_Forwarded-Proto"), value);
			else if (header == HeaderType::X_FRAME_OPTIONS)
				formatHeader(xorstr_("X_Frame-Options"), value);
			else if (header == HeaderType::X_XSS_PROTECTION)
				formatHeader(xorstr_("X_XSS_Protection"), value);
		}
	}

	// Append last CRLF
	buffer.resize(buffer.size() + crlf.size());
	std::memcpy(buffer.data() + buffer.size() - crlf.size(), crlf.data(), crlf.size());

	// Content
	if (!this->_content.empty()) {
		buffer.resize(buffer.size() + this->_content.size());
		std::memcpy(buffer.data() + buffer.size() - this->_content.size(), this->_content.data(), this->_content.size());
	}
	VM_SIZE_SPEED_END
	return buffer;
}

std::string_view Response::header(const HeaderType headerType) {
	VM_SIZE_SPEED_BEGIN
	if (const auto iterator = std::ranges::find_if(std::as_const(this->_headers), [&](const decltype(this->_headers)::value_type &entry) {
		return entry.header == headerType;
	}); iterator != this->_headers.cend())
		return iterator->value;
	VM_SIZE_SPEED_END
	return {};
}

std::pair<std::size_t, std::size_t> Response::parse(const SpanType buffer) {
	VM_SIZE_SPEED_BEGIN
	constexpr std::string_view crlf {"\r\n"};
	const std::string_view response {reinterpret_cast<const char*>(buffer.data()), buffer.size()};

	// HTTP protocol version + status (error code + message) + CRLF
	{
		if (!response.starts_with(xorstr_("HTTP/1.1")))
			return {};

		const auto statusCodeStartOffset = response.find(' ');
		if (statusCodeStartOffset == std::string::npos)
			return {};

		const auto statusCodeEndOffset = response.find(' ', statusCodeStartOffset + 1);
		if (statusCodeEndOffset == std::string::npos)
			return {};

		const auto statusCodeStart = response.data() + statusCodeStartOffset + 1;
		const auto statusCodeEnd   = response.data() + statusCodeEndOffset;

		std::int32_t statusCode {};  // NOLINT(clang-diagnostic-shadow)
		if (const auto [x, ec] = std::from_chars(statusCodeStart, statusCodeEnd, statusCode);
			ec != std::errc {})
			return {};
		this->statusCode = static_cast<StatusCode>(statusCode);
	}

	// Headers
	constexpr tls::Array<4> endBuffer {'\r', '\n', '\r', '\n'};
	const auto begin = response.find(crlf);
	if (begin == std::string_view::npos)
		return {};

	const auto end = response.find({reinterpret_cast<const char*>(endBuffer.data()), 4}, begin + crlf.size());
	{
		constexpr auto headerDelimiter {':'};
		for (auto offset = begin + crlf.size(); offset < end;) {
			const auto next = response.find(crlf, offset);
			const auto headerText = response.substr(offset, next - offset);

			const auto delimiterOffset = headerText.find_first_of(headerDelimiter);
			if (delimiterOffset == std::string_view::npos)
				return {};

			const auto headerType = fromHash(headerText.substr(0, delimiterOffset));

			const auto valueBegin = headerText.find_first_not_of(' ', delimiterOffset + 1);
			const auto value = headerText.substr(valueBegin);
			this->_headers.emplace_back(headerType, value);

			offset = next + crlf.size();
		}
	}

	const auto contentLength = this->header(HeaderType::CONTENT_LENGTH);
	if (contentLength.empty())
		return {};

	std::int32_t value {};
	if (const auto [pointer, error] = std::from_chars(contentLength.data(), contentLength.data() + contentLength.size(), value);
		error == std::errc {})
		return {value, end + endBuffer.size()};
	VM_SIZE_SPEED_END
	return {0, response.size()};
}

std::optional<tls::aes::DecryptedDataType> Response::receive(const SpanType initialResponseBuffer, tls::client::Tls12Client &client) {
	VM_SIZE_SPEED_BEGIN
	const auto [contentLength, headerSize] = this->parse(initialResponseBuffer);
	if (!contentLength || !headerSize)
		return std::nullopt;

	tls::aes::DecryptedDataType decryptedDataBuffer {};
	decryptedDataBuffer.resize(contentLength);

	const auto initialDataSize = initialResponseBuffer.size() - headerSize;
	std::memcpy(decryptedDataBuffer.data(), initialResponseBuffer.data() + headerSize, initialDataSize);

	auto offset {initialDataSize};
	while (offset < contentLength) {
		const auto temporary = client.receive();
		std::memcpy(decryptedDataBuffer.data() + offset, temporary.data(), temporary.size());
		offset += temporary.size();
	}
	VM_SIZE_SPEED_END
	return decryptedDataBuffer;  // NOLINT(clang-diagnostic-return-std-move-in-c++11)
}
