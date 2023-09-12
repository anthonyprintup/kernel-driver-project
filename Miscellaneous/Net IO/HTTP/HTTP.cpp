#include "HTTP.hpp"

using namespace http;

#include <Framework/Utilities/Strings/XorStr.hpp>

#include "../../Globals.hpp"
using Hash = Framework::Utilities::Strings::Fnv1A::Hash;

Header::Header(const HeaderType header, const std::string_view value):
	header {header}, value {value} {}

Hash http::toHash(const HeaderType header) noexcept {
	VM_SIZE_SPEED_BEGIN
	[[maybe_unused]] volatile auto meme {true};
	if (header == HeaderType::ACCEPT_CH)
		return Fnv1A("Accept-CH");
	if (header == HeaderType::ACCEPT_CHARSET)
		return Fnv1A("Accept-Charset");
	if (header == HeaderType::ACCEPT_ENCODING)
		return Fnv1A("Accept-Encoding");
	if (header == HeaderType::ACCEPT_LANGUAGE)
		return Fnv1A("Accept-Language");
	if (header == HeaderType::ACCEPT_PATCH)
		return Fnv1A("Accept-Patch");
	if (header == HeaderType::ACCEPT_POST)
		return Fnv1A("Accept-Post");
	if (header == HeaderType::ACCEPT_RANGES)
		return Fnv1A("Accept-Ranges");
	if (header == HeaderType::ACCEPT)
		return Fnv1A("Accept");
	if (header == HeaderType::ACCESS_CONTROL_ALLOW_CREDENTIALS)
		return Fnv1A("Access-Control-Allow-Credentials");
	if (header == HeaderType::ACCESS_CONTROL_ALLOW_HEADERS)
		return Fnv1A("Access-Control-Allow-Headers");
	if (header == HeaderType::ACCESS_CONTROL_ALLOW_METHODS)
		return Fnv1A("Access-Control-Allow-Methods");
	if (header == HeaderType::ACCESS_CONTROL_ALLOW_ORIGIN)
		return Fnv1A("Access-Control-Allow-Origin");
	if (header == HeaderType::ACCESS_CONTROL_EXPOSE_HEADERS)
		return Fnv1A("Access-Control-Expose-Headers");
	if (header == HeaderType::ACCESS_CONTROL_MAX_AGE)
		return Fnv1A("Access-Control-Max-Age");
	if (header == HeaderType::ACCESS_CONTROL_REQUEST_HEADERS)
		return Fnv1A("Access-Control-Request-Headers");
	if (header == HeaderType::ACCESS_CONTROL_REQUEST_METHOD)
		return Fnv1A("Access-Control-Request-Method");
	if (header == HeaderType::AGE)
		return Fnv1A("Age");
	if (header == HeaderType::ALLOW)
		return Fnv1A("Allow");
	if (header == HeaderType::ALT_SVC)
		return Fnv1A("Alt-Svc");
	if (header == HeaderType::AUTHORIZATION)
		return Fnv1A("Authorization");
	if (header == HeaderType::CACHE_CONTROL)
		return Fnv1A("Cache-Control");
	if (header == HeaderType::CLEAR_SITE_DATA)
		return Fnv1A("Clear-Site-Data");
	if (header == HeaderType::CONNECTION)
		return Fnv1A("Connection");
	if (header == HeaderType::CONTENT_DISPOSITION)
		return Fnv1A("Content-Disposition");
	if (header == HeaderType::CONTENT_ENCODING)
		return Fnv1A("Content-Encoding");
	if (header == HeaderType::CONTENT_LANGUAGE)
		return Fnv1A("Content-Language");
	if (header == HeaderType::CONTENT_LENGTH)
		return Fnv1A("Content-Length");
	if (header == HeaderType::CONTENT_LOCATION)
		return Fnv1A("Content-Location");
	if (header == HeaderType::CONTENT_RANGE)
		return Fnv1A("Content-Range");
	if (header == HeaderType::CONTENT_SECURITY_POLICY_REPORT_ONLY)
		return Fnv1A("Content-Security-Policy-Report-Only");
	if (header == HeaderType::CONTENT_SECURITY_POLICY)
		return Fnv1A("Content-Security-Policy");
	if (header == HeaderType::CONTENT_TYPE)
		return Fnv1A("Content-Type");
	if (header == HeaderType::COOKIE)
		return Fnv1A("Cookie");
	if (header == HeaderType::CROSS_ORIGIN_EMBEDDER_POLICY)
		return Fnv1A("Cross-Origin-Embedder-Policy");
	if (header == HeaderType::CROSS_ORIGIN_OPENER_POLICY)
		return Fnv1A("Cross-Origin-Opener-Policy");
	if (header == HeaderType::CROSS_ORIGIN_RESOURCE_POLICY)
		return Fnv1A("Cross-Origin-Resource-Policy");
	if (header == HeaderType::DATE)
		return Fnv1A("Date");
	if (header == HeaderType::DEVICE_MEMORY)
		return Fnv1A("Device-Memory");
	if (header == HeaderType::DIGEST)
		return Fnv1A("Digest");
	if (header == HeaderType::DNT)
		return Fnv1A("DNT");
	if (header == HeaderType::DOWNLINK)
		return Fnv1A("Downlink");
	if (header == HeaderType::EARLY_DATA)
		return Fnv1A("Early-Data");
	if (header == HeaderType::ECT)
		return Fnv1A("ECT");
	if (header == HeaderType::ETAG)
		return Fnv1A("ETag");
	if (header == HeaderType::EXPECT_CT)
		return Fnv1A("Expect-CT");
	if (header == HeaderType::EXPECT)
		return Fnv1A("Expect");
	if (header == HeaderType::EXPIRES)
		return Fnv1A("Expires");
	if (header == HeaderType::FEATURE_POLICY)
		return Fnv1A("Feature-Policy");
	if (header == HeaderType::FORWARDED)
		return Fnv1A("Forwarded");
	if (header == HeaderType::FROM)
		return Fnv1A("From");
	if (header == HeaderType::HOST)
		return Fnv1A("Host");
	if (header == HeaderType::IF_MATCH)
		return Fnv1A("If-Match");
	if (header == HeaderType::IF_MODIFIED_SINCE)
		return Fnv1A("If-Modified-Since");
	if (header == HeaderType::IF_NONE_MATCH)
		return Fnv1A("If-None-Match");
	if (header == HeaderType::IF_RANGE)
		return Fnv1A("If-Range");
	if (header == HeaderType::IF_UNMODIFIED_SINCE)
		return Fnv1A("If-Unmodified-Since");
	if (header == HeaderType::KEEP_ALIVE)
		return Fnv1A("Keep-Alive");
	if (header == HeaderType::LARGE_ALLOCATION)
		return Fnv1A("Large-Allocation");
	if (header == HeaderType::LAST_MODIFIED)
		return Fnv1A("Last-Modified");
	if (header == HeaderType::LINK)
		return Fnv1A("Link");
	if (header == HeaderType::LOCATION)
		return Fnv1A("Location");
	if (header == HeaderType::NEL)
		return Fnv1A("NEL");
	if (header == HeaderType::ORIGIN)
		return Fnv1A("Origin");
	if (header == HeaderType::PROXY_AUTHENTICATE)
		return Fnv1A("Proxy-Authenticate");
	if (header == HeaderType::PROXY_AUTHORIZATION)
		return Fnv1A("Proxy-Authorization");
	if (header == HeaderType::RANGE)
		return Fnv1A("Range");
	if (header == HeaderType::REFERER)
		return Fnv1A("Referer");
	if (header == HeaderType::REFERRER_POLICY)
		return Fnv1A("Referrer-Policy");
	if (header == HeaderType::RETRY_AFTER)
		return Fnv1A("Retry-After");
	if (header == HeaderType::RTT)
		return Fnv1A("RTT");
	if (header == HeaderType::SAVE_DATA)
		return Fnv1A("Save-Data");
	if (header == HeaderType::SEC_FETCH_DEST)
		return Fnv1A("Sec-Fetch-Dest");
	if (header == HeaderType::SEC_FETCH_MODE)
		return Fnv1A("Sec-Fetch-Mode");
	if (header == HeaderType::SEC_FETCH_SITE)
		return Fnv1A("Sec-Fetch-Site");
	if (header == HeaderType::SEC_FETCH_USER)
		return Fnv1A("Sec-Fetch-User");
	if (header == HeaderType::SEC_WEBSOCKET_ACCEPT)
		return Fnv1A("Sec-WebSocket-Accept");
	if (header == HeaderType::SERVER_TIMING)
		return Fnv1A("Server-Timing");
	if (header == HeaderType::SERVER)
		return Fnv1A("Server");
	if (header == HeaderType::SET_COOKIE)
		return Fnv1A("Set-Cookie");
	if (header == HeaderType::SOURCEMAP)
		return Fnv1A("SourceMap");
	if (header == HeaderType::STRICT_TRANSPORT_SECURITY)
		return Fnv1A("Strict-Transport-Security");
	if (header == HeaderType::TE)
		return Fnv1A("TE");
	if (header == HeaderType::TIMING_ALLOW_ORIGIN)
		return Fnv1A("Timing-Allow-Origin");
	if (header == HeaderType::TK)
		return Fnv1A("Tk");
	if (header == HeaderType::TRAILER)
		return Fnv1A("Trailer");
	if (header == HeaderType::TRANSFER_ENCODING)
		return Fnv1A("Transfer-Encoding");
	if (header == HeaderType::UPGRADE_INSECURE_REQUESTS)
		return Fnv1A("Upgrade-Insecure-Requests");
	if (header == HeaderType::UPGRADE)
		return Fnv1A("Upgrade");
	if (header == HeaderType::USER_AGENT)
		return Fnv1A("User-Agent");
	if (header == HeaderType::VARY)
		return Fnv1A("Vary");
	if (header == HeaderType::VIA)
		return Fnv1A("Via");
	if (header == HeaderType::WANT_DIGEST)
		return Fnv1A("Want-Digest");
	if (header == HeaderType::WARNING)
		return Fnv1A("Warning");
	if (header == HeaderType::WWW_AUTHENTICATE)
		return Fnv1A("WWW_Authenticate");
	if (header == HeaderType::X_CONTENT_TYPE_OPTIONS)
		return Fnv1A("X_Content-Type-Options");
	if (header == HeaderType::X_DNS_PREFETCH_CONTROL)
		return Fnv1A("X_DNS_Prefetch-Control");
	if (header == HeaderType::X_FORWARDED_FOR)
		return Fnv1A("X_Forwarded-For");
	if (header == HeaderType::X_FORWARDED_HOST)
		return Fnv1A("X_Forwarded-Host");
	if (header == HeaderType::X_FORWARDED_PROTO)
		return Fnv1A("X_Forwarded-Proto");
	if (header == HeaderType::X_FRAME_OPTIONS)
		return Fnv1A("X_Frame-Options");
	if (header == HeaderType::X_XSS_PROTECTION)
		return Fnv1A("X_XSS_Protection");
	VM_SIZE_SPEED_END
	return Fnv1A("UNKNOWN");
}
HeaderType http::fromHash(const Hash hash) noexcept {
	VM_SIZE_SPEED_BEGIN
	[[maybe_unused]] volatile auto meme {true};
	if (hash == Fnv1A("Accept-CH"))
		return HeaderType::ACCEPT_CH;
	if (hash == Fnv1A("Accept-Charset"))
		return HeaderType::ACCEPT_CHARSET;
	if (hash == Fnv1A("Accept-Encoding"))
		return HeaderType::ACCEPT_ENCODING;
	if (hash == Fnv1A("Accept-Language"))
		return HeaderType::ACCEPT_LANGUAGE;
	if (hash == Fnv1A("Accept-Patch"))
		return HeaderType::ACCEPT_PATCH;
	if (hash == Fnv1A("Accept-Post"))
		return HeaderType::ACCEPT_POST;
	if (hash == Fnv1A("Accept-Ranges"))
		return HeaderType::ACCEPT_RANGES;
	if (hash == Fnv1A("Accept"))
		return HeaderType::ACCEPT;
	if (hash == Fnv1A("Access-Control-Allow-Credentials"))
		return HeaderType::ACCESS_CONTROL_ALLOW_CREDENTIALS;
	if (hash == Fnv1A("Access-Control-Allow-Headers"))
		return HeaderType::ACCESS_CONTROL_ALLOW_HEADERS;
	if (hash == Fnv1A("Access-Control-Allow-Methods"))
		return HeaderType::ACCESS_CONTROL_ALLOW_METHODS;
	if (hash == Fnv1A("Access-Control-Allow-Origin"))
		return HeaderType::ACCESS_CONTROL_ALLOW_ORIGIN;
	if (hash == Fnv1A("Access-Control-Expose-Headers"))
		return HeaderType::ACCESS_CONTROL_EXPOSE_HEADERS;
	if (hash == Fnv1A("Access-Control-Max-Age"))
		return HeaderType::ACCESS_CONTROL_MAX_AGE;
	if (hash == Fnv1A("Access-Control-Request-Headers"))
		return HeaderType::ACCESS_CONTROL_REQUEST_HEADERS;
	if (hash == Fnv1A("Access-Control-Request-Method"))
		return HeaderType::ACCESS_CONTROL_REQUEST_METHOD;
	if (hash == Fnv1A("Age"))
		return HeaderType::AGE;
	if (hash == Fnv1A("Allow"))
		return HeaderType::ALLOW;
	if (hash == Fnv1A("Alt-Svc"))
		return HeaderType::ALT_SVC;
	if (hash == Fnv1A("Authorization"))
		return HeaderType::AUTHORIZATION;
	if (hash == Fnv1A("Cache-Control"))
		return HeaderType::CACHE_CONTROL;
	if (hash == Fnv1A("Clear-Site-Data"))
		return HeaderType::CLEAR_SITE_DATA;
	if (hash == Fnv1A("Connection"))
		return HeaderType::CONNECTION;
	if (hash == Fnv1A("Content-Disposition"))
		return HeaderType::CONTENT_DISPOSITION;
	if (hash == Fnv1A("Content-Encoding"))
		return HeaderType::CONTENT_ENCODING;
	if (hash == Fnv1A("Content-Language"))
		return HeaderType::CONTENT_LANGUAGE;
	if (hash == Fnv1A("Content-Length"))
		return HeaderType::CONTENT_LENGTH;
	if (hash == Fnv1A("Content-Location"))
		return HeaderType::CONTENT_LOCATION;
	if (hash == Fnv1A("Content-Range"))
		return HeaderType::CONTENT_RANGE;
	if (hash == Fnv1A("Content-Security-Policy-Report-Only"))
		return HeaderType::CONTENT_SECURITY_POLICY_REPORT_ONLY;
	if (hash == Fnv1A("Content-Security-Policy"))
		return HeaderType::CONTENT_SECURITY_POLICY;
	if (hash == Fnv1A("Content-Type"))
		return HeaderType::CONTENT_TYPE;
	if (hash == Fnv1A("Cookie"))
		return HeaderType::COOKIE;
	if (hash == Fnv1A("Cross-Origin-Embedder-Policy"))
		return HeaderType::CROSS_ORIGIN_EMBEDDER_POLICY;
	if (hash == Fnv1A("Cross-Origin-Opener-Policy"))
		return HeaderType::CROSS_ORIGIN_OPENER_POLICY;
	if (hash == Fnv1A("Cross-Origin-Resource-Policy"))
		return HeaderType::CROSS_ORIGIN_RESOURCE_POLICY;
	if (hash == Fnv1A("Date"))
		return HeaderType::DATE;
	if (hash == Fnv1A("Device-Memory"))
		return HeaderType::DEVICE_MEMORY;
	if (hash == Fnv1A("Digest"))
		return HeaderType::DIGEST;
	if (hash == Fnv1A("DNT"))
		return HeaderType::DNT;
	if (hash == Fnv1A("Downlink"))
		return HeaderType::DOWNLINK;
	if (hash == Fnv1A("Early-Data"))
		return HeaderType::EARLY_DATA;
	if (hash == Fnv1A("ECT"))
		return HeaderType::ECT;
	if (hash == Fnv1A("ETag"))
		return HeaderType::ETAG;
	if (hash == Fnv1A("Expect-CT"))
		return HeaderType::EXPECT_CT;
	if (hash == Fnv1A("Expect"))
		return HeaderType::EXPECT;
	if (hash == Fnv1A("Expires"))
		return HeaderType::EXPIRES;
	if (hash == Fnv1A("Feature-Policy"))
		return HeaderType::FEATURE_POLICY;
	if (hash == Fnv1A("Forwarded"))
		return HeaderType::FORWARDED;
	if (hash == Fnv1A("From"))
		return HeaderType::FROM;
	if (hash == Fnv1A("Host"))
		return HeaderType::HOST;
	if (hash == Fnv1A("If-Match"))
		return HeaderType::IF_MATCH;
	if (hash == Fnv1A("If-Modified-Since"))
		return HeaderType::IF_MODIFIED_SINCE;
	if (hash == Fnv1A("If-None-Match"))
		return HeaderType::IF_NONE_MATCH;
	if (hash == Fnv1A("If-Range"))
		return HeaderType::IF_RANGE;
	if (hash == Fnv1A("If-Unmodified-Since"))
		return HeaderType::IF_UNMODIFIED_SINCE;
	if (hash == Fnv1A("Keep-Alive"))
		return HeaderType::KEEP_ALIVE;
	if (hash == Fnv1A("Large-Allocation"))
		return HeaderType::LARGE_ALLOCATION;
	if (hash == Fnv1A("Last-Modified"))
		return HeaderType::LAST_MODIFIED;
	if (hash == Fnv1A("Link"))
		return HeaderType::LINK;
	if (hash == Fnv1A("Location"))
		return HeaderType::LOCATION;
	if (hash == Fnv1A("NEL"))
		return HeaderType::NEL;
	if (hash == Fnv1A("Origin"))
		return HeaderType::ORIGIN;
	if (hash == Fnv1A("Proxy-Authenticate"))
		return HeaderType::PROXY_AUTHENTICATE;
	if (hash == Fnv1A("Proxy-Authorization"))
		return HeaderType::PROXY_AUTHORIZATION;
	if (hash == Fnv1A("Range"))
		return HeaderType::RANGE;
	if (hash == Fnv1A("Referer"))
		return HeaderType::REFERER;
	if (hash == Fnv1A("Referrer-Policy"))
		return HeaderType::REFERRER_POLICY;
	if (hash == Fnv1A("Retry-After"))
		return HeaderType::RETRY_AFTER;
	if (hash == Fnv1A("RTT"))
		return HeaderType::RTT;
	if (hash == Fnv1A("Save-Data"))
		return HeaderType::SAVE_DATA;
	if (hash == Fnv1A("Sec-Fetch-Dest"))
		return HeaderType::SEC_FETCH_DEST;
	if (hash == Fnv1A("Sec-Fetch-Mode"))
		return HeaderType::SEC_FETCH_MODE;
	if (hash == Fnv1A("Sec-Fetch-Site"))
		return HeaderType::SEC_FETCH_SITE;
	if (hash == Fnv1A("Sec-Fetch-User"))
		return HeaderType::SEC_FETCH_USER;
	if (hash == Fnv1A("Sec-WebSocket-Accept"))
		return HeaderType::SEC_WEBSOCKET_ACCEPT;
	if (hash == Fnv1A("Server-Timing"))
		return HeaderType::SERVER_TIMING;
	if (hash == Fnv1A("Server"))
		return HeaderType::SERVER;
	if (hash == Fnv1A("Set-Cookie"))
		return HeaderType::SET_COOKIE;
	if (hash == Fnv1A("SourceMap"))
		return HeaderType::SOURCEMAP;
	if (hash == Fnv1A("Strict-Transport-Security"))
		return HeaderType::STRICT_TRANSPORT_SECURITY;
	if (hash == Fnv1A("TE"))
		return HeaderType::TE;
	if (hash == Fnv1A("Timing-Allow-Origin"))
		return HeaderType::TIMING_ALLOW_ORIGIN;
	if (hash == Fnv1A("Tk"))
		return HeaderType::TK;
	if (hash == Fnv1A("Trailer"))
		return HeaderType::TRAILER;
	if (hash == Fnv1A("Transfer-Encoding"))
		return HeaderType::TRANSFER_ENCODING;
	if (hash == Fnv1A("Upgrade-Insecure-Requests"))
		return HeaderType::UPGRADE_INSECURE_REQUESTS;
	if (hash == Fnv1A("Upgrade"))
		return HeaderType::UPGRADE;
	if (hash == Fnv1A("User-Agent"))
		return HeaderType::USER_AGENT;
	if (hash == Fnv1A("Vary"))
		return HeaderType::VARY;
	if (hash == Fnv1A("Via"))
		return HeaderType::VIA;
	if (hash == Fnv1A("Want-Digest"))
		return HeaderType::WANT_DIGEST;
	if (hash == Fnv1A("Warning"))
		return HeaderType::WARNING;
	if (hash == Fnv1A("WWW_Authenticate"))
		return HeaderType::WWW_AUTHENTICATE;
	if (hash == Fnv1A("X_Content-Type-Options"))
		return HeaderType::X_CONTENT_TYPE_OPTIONS;
	if (hash == Fnv1A("X_DNS_Prefetch-Control"))
		return HeaderType::X_DNS_PREFETCH_CONTROL;
	if (hash == Fnv1A("X_Forwarded-For"))
		return HeaderType::X_FORWARDED_FOR;
	if (hash == Fnv1A("X_Forwarded-Host"))
		return HeaderType::X_FORWARDED_HOST;
	if (hash == Fnv1A("X_Forwarded-Proto"))
		return HeaderType::X_FORWARDED_PROTO;
	if (hash == Fnv1A("X_Frame-Options"))
		return HeaderType::X_FRAME_OPTIONS;
	if (hash == Fnv1A("X_XSS_Protection"))
		return HeaderType::X_XSS_PROTECTION;
	VM_SIZE_SPEED_END
	return HeaderType::UNKNOWN;
}

std::pair<std::string_view, std::string_view> http::parseUri(const std::string_view uri) noexcept {
	VM_SIZE_SPEED_BEGIN
	constexpr std::size_t protocolDelimiterLength {3};
	const auto protocolDelimiter = xorstr_("://");

	if (const auto hostOffset = uri.find(protocolDelimiter);
		hostOffset != std::string_view::npos) {
		if (const auto dataOffset = uri.find_first_of('/', hostOffset + protocolDelimiterLength);
			dataOffset != std::string_view::npos)
			return {uri.substr(hostOffset + protocolDelimiterLength, dataOffset - hostOffset - protocolDelimiterLength), uri.substr(dataOffset)};
		return {uri.substr(hostOffset + protocolDelimiterLength), {}};
	}
	if (const auto dataOffset = uri.find_first_of('/');
		dataOffset != std::string_view::npos)
		return {uri.substr(0, dataOffset), uri.substr(dataOffset)};
	VM_SIZE_SPEED_END
	return {uri, {}};
}
