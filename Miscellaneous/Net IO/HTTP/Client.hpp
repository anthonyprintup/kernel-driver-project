#pragma once

#include <vector>

#include "HTTP.hpp"
#include "../TLS/Client/Client.hpp"

namespace http {
	using UnderlyingDataType = tls::UnderlyingDataType;
	using SpanType = tls::SpanType;
	using HeadersContainerType = std::vector<Header>;
	using ContentContainerType = std::vector<UnderlyingDataType>;

	struct Request {
		using BufferType = std::vector<tls::UnderlyingDataType>;

		Request() = default;
		Request(RequestMethod method, std::string_view uri);
		Request(RequestMethod method, std::string_view host, std::string_view data);

		void method(RequestMethod method) noexcept;
		void data(std::string_view data) noexcept;
		void header(HeaderType headerType, std::string_view value);

		// Content specific functions
		void set(tls::SpanType data);
		void set(std::string_view data);
		void append(tls::SpanType data);
		void append(std::string_view data);

		// Builder
		BufferType build();

		HeadersContainerType &headers() noexcept;
		[[nodiscard]] const HeadersContainerType &headers() const noexcept;
		ContentContainerType &content() noexcept;
		[[nodiscard]] const ContentContainerType &content() const noexcept;
	private:
		RequestMethod _method {RequestMethod::UNKNOWN};
		std::string_view _data {};

		HeadersContainerType _headers {};
		ContentContainerType _content {};
	};
	struct Response {
		std::string_view header(HeaderType headerType);

		std::pair<std::size_t, std::size_t> parse(tls::SpanType buffer);
		[[nodiscard]] std::optional<tls::aes::DecryptedDataType> receive(tls::SpanType initialResponseBuffer, tls::client::Tls12Client &client);

		StatusCode statusCode {};
		HeadersContainerType _headers {};
	};
}
