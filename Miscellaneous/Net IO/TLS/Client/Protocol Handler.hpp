#pragma once

#include <optional>

#include "../../Socket.hpp"
#include "../Parser/Parser.hpp"
#include "../Crypto/Algorithms.hpp"

namespace libtomcrypt {
	#include <tomcrypt.h>
}

namespace tls::client {
	using MasterSecretBuffer = Array<48>;
	using RandomBuffer       = Array<32>;

	template<std::size_t KeySizeInBits, std::size_t HashSizeInBits, std::size_t CurveSecretKeySizeInBits, std::size_t CurvePublicKeySizeInBits>
	struct CipherData {
		static constexpr auto keySizeInBits  {KeySizeInBits};
		static constexpr auto hashSizeInBits {HashSizeInBits};
		using HashBuffer = BitArray<HashSizeInBits>;

		BitArray<CurveSecretKeySizeInBits> secretKey {};
		BitArray<CurvePublicKeySizeInBits> clientPublicKey {}, serverPublicKey {};
		aes::ClientEncryptionKeys<KeySizeInBits, HashSizeInBits> keys {};
	};

	using Aes128Sha256Secp256R1 = CipherData<128, 256, 256, 520>;
	using Aes256Sha384Secp256R1 = CipherData<256, 384, 256, 520>;
	using CipherDataVariant = std::variant<Aes128Sha256Secp256R1, Aes256Sha384Secp256R1>;

	void registerCiphers() noexcept;
	void unregisterCiphers() noexcept;

	void registerHashes() noexcept;
	void unregisterHashes() noexcept;

	void registerPrngs() noexcept;
	void unregisterPrngs() noexcept;

	struct Tls12ProtocolHandler {
		Tls12ProtocolHandler(KM::Miscellaneous::NetIo::Socket &socket, ProtocolVersion protocolVersion) noexcept;

		template<class T>
		requires std::is_same_v<T, Aes128Sha256Secp256R1>
		void add() {
			this->cipherData.emplace_back(Aes128Sha256Secp256R1 {});
		}
		template<class T>
		requires std::is_same_v<T, Aes256Sha384Secp256R1>
		void add() {
			this->cipherData.emplace_back(Aes256Sha384Secp256R1 {});
		}

		[[nodiscard]] bool performHandshake(std::string_view hostname);

		[[nodiscard]] bool send(SpanType data);
		[[nodiscard]] aes::DecryptedDataType receive();

		[[nodiscard]] ProtocolVersion version() const noexcept;
	private:
		[[nodiscard]] VectorType receiveRecord() const;
		void hashHandshake(SpanType data) noexcept;
		Array<12> generateVerifyData(bool local);

		[[nodiscard]] std::optional<stream::Writer> sendClientHello(std::string_view hostname) const;
		[[nodiscard]] parser::MessageVariant parseHandshakeMessages(SpanType clientHelloStream, std::string_view hostname);
		void initializeCipherData(const handshakes::ServerKeyExchange *serverKeyExchange);
		[[nodiscard]] bool sendClientKeyExchange();
		[[nodiscard]] bool sendCipherChangeSpec() const;
		[[nodiscard]] bool sendFinished();
		[[nodiscard]] bool receiveServerFinished();

		[[nodiscard]] stream::Writer encrypt(SpanType data, ContentType &&type) const;
		[[nodiscard]] aes::DecryptedDataType decrypt(SpanType data, Array<8> decryptionIv, ContentType &&type) const;

		KM::Miscellaneous::NetIo::Socket &socket;
		ProtocolVersion _version {};
		std::vector<CipherDataVariant> cipherData {};
		libtomcrypt::hash_state hashState {};
		std::size_t clientSequenceNumber {}, serverSequenceNumber {};

		Cipher negotiatedCipher {};
		RandomBuffer clientRandom {}, serverRandom {};
	};
}
