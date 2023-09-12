#include "Protocol Handler.hpp"

using namespace tls;
using namespace client;

#include "../../../Globals.hpp"

#include <Framework/Utilities/Strings/Fnv1A.hpp>
#include <Framework/Utilities/Strings/XorStr.hpp>

namespace libtomcrypt {
	int aesCipherIdentifier {-1};
	int sha256HashIdentifier {-1}, sha384HashIdentifier {-1}, sha512HashIdentifier {-1};

	int chacha20PrngIdentifier {-1};
}
#include "../Crypto/Hashes.hpp"

#include "../Content/Handshakes/Messages/Client Hello.hpp"
#include "../Content/Handshakes/Messages/Client Key Exchange.hpp"
#include "../Content/Change Cipher Specification.hpp"

#include <algorithm>

#include <intrin.h>
template<class ...Arguments>
void print(const char *format, Arguments ...arguments) {
	if constexpr (::Configuration::print) {
		VM_SIZE_BEGIN
			namespace nt = KM::Miscellaneous::Globals::NT;
		nt::DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, (std::string {format} + '\n').c_str(), arguments...);
		VM_SIZE_END
		__nop(); // Prevent tailcall optimizations
	}
}

template<std::size_t SizeLeft, std::size_t SizeRight>
auto operator +(const std::array<std::uint8_t, SizeLeft> &left, const std::array<std::uint8_t, SizeRight> &right) noexcept {
	std::array<std::uint8_t, SizeLeft + SizeRight> buffer {};
	std::memcpy(buffer.data(), left.data(), SizeLeft);
	std::memcpy(buffer.data() + SizeLeft, right.data(), SizeRight);

	return buffer;
}

namespace internal {
	template<std::size_t Bytes>
	Array<Bytes> randomBytes() {
		namespace nt = KM::Miscellaneous::Globals::NT;
		VM_MINIMUM_BEGIN
		Array<Bytes> entropy {};
		const auto status = nt::BCryptGenRandom(nullptr, entropy.data(), entropy.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		VM_MINIMUM_END

		return entropy;
	}

	const libtomcrypt::ltc_ecc_curve *findEccCurve(const Hash hash) {
		VM_SIZE_SPEED_BEGIN
		const libtomcrypt::ltc_ecc_curve *result {};
		for (auto curve = libtomcrypt::ltc_ecc_curves; curve->prime; ++curve) {
			if (hash == Fnv1A("SECP256R1") && Hash {curve->OID} == Fnv1A("1.2.840.10045.3.1.7")) {
				result = curve;
				break;
			}
			if (hash == Fnv1A("SECP384R1") && Hash {curve->OID} == Fnv1A("1.3.132.0.34")) {
				result = curve;
				break;
			}
			if (hash == Fnv1A("SECP521R1") && Hash {curve->OID} == Fnv1A("1.3.132.0.35")) {
				result = curve;
				break;
			}
		}
		VM_SIZE_SPEED_END
		return result;
	}
	namespace secp256r1 {
		using PreMasterSecretBuffer = BitArray<256>; // Specific to the curve's prime size (256)

		__declspec(noinline) void generateKeys(const MutableSpanType secretKey, const MutableSpanType publicKey) {
			VM_SIZE_SPEED_BEGIN
			const auto entropy = randomBytes<64>();

			libtomcrypt::prng_state prngState {};
			libtomcrypt::chacha20_prng_start(&prngState);
			libtomcrypt::chacha20_prng_add_entropy(entropy.data(), static_cast<unsigned long>(entropy.size()), &prngState);
			libtomcrypt::chacha20_prng_ready(&prngState);

			libtomcrypt::ecc_key key {};
			libtomcrypt::ecc_make_key_ex(&prngState, libtomcrypt::chacha20PrngIdentifier, &key, findEccCurve(Fnv1A("SECP256R1")));
			libtomcrypt::chacha20_prng_done(&prngState);

			auto privateKeyOutputLength = static_cast<unsigned long>(secretKey.size()), publicKeyOutputLength = static_cast<unsigned long>(publicKey.size());
			libtomcrypt::ecc_get_key(secretKey.data(), &privateKeyOutputLength, libtomcrypt::PK_PRIVATE, &key);
			libtomcrypt::ecc_get_key(publicKey.data(), &publicKeyOutputLength, libtomcrypt::PK_PUBLIC, &key);
			libtomcrypt::ecc_free(&key);
			VM_SIZE_SPEED_END
		}
		__declspec(noinline) PreMasterSecretBuffer generatePreMasterSecret(const SpanType secretKey, const SpanType serverPublicKey) noexcept {
			VM_SIZE_SPEED_BEGIN
			PreMasterSecretBuffer buffer {};

			libtomcrypt::ecc_key privateKey {}, publicKey {};
			const auto curve = findEccCurve(Fnv1A("SECP256R1"));
			
			libtomcrypt::ecc_set_curve(curve, &privateKey);
			libtomcrypt::ecc_set_curve(curve, &publicKey);
			libtomcrypt::ecc_set_key(secretKey.data(), static_cast<unsigned long>(secretKey.size()), libtomcrypt::PK_PRIVATE, &privateKey);
			libtomcrypt::ecc_set_key(serverPublicKey.data(), static_cast<unsigned long>(serverPublicKey.size()), libtomcrypt::PK_PUBLIC, &publicKey);

			auto preMasterSecretSize = static_cast<unsigned long>(buffer.size());
			libtomcrypt::ecc_shared_secret(&privateKey, &publicKey, buffer.data(), &preMasterSecretSize);

			libtomcrypt::ecc_free(&privateKey);
			libtomcrypt::ecc_free(&publicKey);
			VM_SIZE_SPEED_END

			return buffer;
		}
	}
	namespace sha {
		template<std::size_t HmacHashSizeInBits>
		__declspec(noinline) MasterSecretBuffer generateMasterSecret(const secp256r1::PreMasterSecretBuffer &preMasterSecret, const RandomBuffer &clientRandom, const RandomBuffer &serverRandom) noexcept {
			VM_SIZE_SPEED_BEGIN
			auto masterSecret = xorstr("master secret");
			masterSecret.crypt();
			const SpanType data {reinterpret_cast<const unsigned char*>(masterSecret.get()), 13};
			
			const Array<13> masterSecretSeedArray {data};
			masterSecret.crypt();
			const auto seed = masterSecretSeedArray + clientRandom + serverRandom;

			const auto a1 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, seed);
			const auto p1 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, a1 + seed);

			const auto a2 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, a1);
			const auto p2 = tls::hmacSha<HmacHashSizeInBits>(preMasterSecret, a2 + seed);
			VM_SIZE_SPEED_END

			return p1 + p2;
		}
		template<std::size_t HmacHashSizeInBits>
		__declspec(noinline) auto generateKeys(const MasterSecretBuffer &masterSecret, const RandomBuffer &clientRandom, const RandomBuffer &serverRandom) noexcept {
			VM_SIZE_SPEED_BEGIN
			auto keyExpansion = xorstr("key expansion");
			keyExpansion.crypt();
			const SpanType data {reinterpret_cast<const unsigned char*>(keyExpansion.get()), 13};
			
			const Array<13> keyExpansionArray {data};
			keyExpansion.crypt();
			const auto seed = keyExpansionArray + serverRandom + clientRandom;

			const auto a1 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, seed);
			const auto a2 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, a1);

			const auto p1 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, a1 + seed);
			const auto p2 = tls::hmacSha<HmacHashSizeInBits>(masterSecret, a2 + seed);
			VM_SIZE_SPEED_END

			return p1 + p2;
		}
	}
}

void client::registerCiphers() noexcept {
	VM_MINIMUM_BEGIN
	libtomcrypt::aesCipherIdentifier = libtomcrypt::register_cipher(&libtomcrypt::aes_desc);
	VM_MINIMUM_END
	__nop(); // Prevent tailcall optimizations
}
void client::unregisterCiphers() noexcept {
	VM_MINIMUM_BEGIN
	libtomcrypt::unregister_cipher(&libtomcrypt::aes_desc);
	libtomcrypt::aesCipherIdentifier = -1;
	VM_MINIMUM_END
	__nop(); // Prevent tailcall optimizations
}

void client::registerHashes() noexcept {
	VM_MINIMUM_BEGIN
	libtomcrypt::sha256HashIdentifier = register_hash(&libtomcrypt::sha256_desc);
	libtomcrypt::sha384HashIdentifier = register_hash(&libtomcrypt::sha384_desc);
	libtomcrypt::sha512HashIdentifier = register_hash(&libtomcrypt::sha512_desc);
	VM_MINIMUM_END
	__nop(); // Prevent tailcall optimizations
}
void client::unregisterHashes() noexcept {
	VM_MINIMUM_BEGIN
	unregister_hash(&libtomcrypt::sha256_desc);
	libtomcrypt::sha256HashIdentifier = -1;
	unregister_hash(&libtomcrypt::sha384_desc);
	libtomcrypt::sha384HashIdentifier = -1;
	unregister_hash(&libtomcrypt::sha512_desc);
	libtomcrypt::sha512HashIdentifier = -1;
	VM_MINIMUM_END
	__nop(); // Prevent tailcall optimizations
}

void client::registerPrngs() noexcept {
	VM_MINIMUM_BEGIN
	libtomcrypt::init_LTM();
	libtomcrypt::chacha20PrngIdentifier = register_prng(&libtomcrypt::chacha20_prng_desc);
	VM_MINIMUM_END
	__nop(); // Prevent tailcall optimizations
}
void client::unregisterPrngs() noexcept {
	VM_MINIMUM_BEGIN
	unregister_prng(&libtomcrypt::chacha20_prng_desc);
	libtomcrypt::chacha20PrngIdentifier = -1;
	VM_MINIMUM_END
	__nop(); // Prevent tailcall optimizations
}

Tls12ProtocolHandler::Tls12ProtocolHandler(KM::Miscellaneous::NetIo::Socket &socket, const ProtocolVersion protocolVersion) noexcept:
	socket {socket}, _version {protocolVersion},
	clientRandom {internal::randomBytes<32>()} {}

bool Tls12ProtocolHandler::performHandshake(const std::string_view hostname) {
	using namespace handshakes;
	VM_MINIMUM_BEGIN
	volatile auto result {true};

	const auto clientHelloStream = this->sendClientHello(hostname);
	if (!clientHelloStream) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Failed to send ClientHello to %s"), hostname.data());
		result = false;
	}

	if (result)
		if (const auto messageVariant = this->parseHandshakeMessages(clientHelloStream.value(), hostname);
			messageVariant.error()) {
			if constexpr (::Configuration::debug)
				print(xorstr_("Failed to parse handshake messages when communicating with %s (%i)"), hostname.data(), std::get<parser::ErrorType>(messageVariant));
			result = false;
		}

	if (result && !this->sendClientKeyExchange()) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Failed to send client key exchange to %s"), hostname.data());
		result = false;
	}
	if (result && !this->sendCipherChangeSpec()) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Failed to send cipher change spec to %s"), hostname.data());
		result = false;
	}
	if (result && !this->sendFinished()) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Failed to send finished to %s"), hostname.data());
		result = false;
	}
	if (result && !this->receiveServerFinished()) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Failed to receive server finished from %s"), hostname.data());
		result = false;
	}
	VM_MINIMUM_END
	return result;
}
bool Tls12ProtocolHandler::send(const SpanType data) {
	VM_MINIMUM_BEGIN
	stream::Writer writer {};

	const auto encryptedData = this->encrypt(data, ContentType::APPLICATION_DATA);

	writer.write<std::uint8_t>(static_cast<std::uint8_t>(ContentType::APPLICATION_DATA));
	writer.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
	writer.write<std::uint16_t>(static_cast<std::uint16_t>(encryptedData.size()));
	writer.write(encryptedData);

	volatile auto result {true};
	if (const auto [status, size] = this->socket.send(writer.data(), writer.size()); status != STATUS_SUCCESS)
		result = false;

	if (result)
		++this->clientSequenceNumber;
	VM_MINIMUM_END
	return result;
}
aes::DecryptedDataType Tls12ProtocolHandler::receive() {
	VM_MINIMUM_BEGIN
	const auto response = this->receiveRecord();
	if (response.empty())
		return {};

	stream::Reader messageReader {response};
	messageReader.advance(TlsPlaintext::sizeInBytes);
	const auto iv = messageReader.read<8>();
	const auto encryptedServerData = messageReader.read(response.size() - TlsPlaintext::sizeInBytes - sizeof(iv));

	auto decryptedServerData = this->decrypt(encryptedServerData, iv, ContentType::APPLICATION_DATA);
	++this->serverSequenceNumber;
	VM_MINIMUM_END
	return decryptedServerData;
}

ProtocolVersion Tls12ProtocolHandler::version() const noexcept {
	return this->_version;
}

VectorType Tls12ProtocolHandler::receiveRecord() const {
	VM_MINIMUM_BEGIN
	VectorType response {};
	response.resize(TlsPlaintext::sizeInBytes);

	if (const auto [status, size] = this->socket.receive(response.data(), TlsPlaintext::sizeInBytes); status != STATUS_SUCCESS)
		return {};

	stream::Reader reader {response};
	reader.advance(TlsPlaintext::sizeInBytes - sizeof(std::uint16_t));
	const auto remainingPacketSize = static_cast<std::size_t>(reader.read<std::uint16_t>());

	response.resize(TlsPlaintext::sizeInBytes + remainingPacketSize);
	if (const auto [status, size] = this->socket.receive(response.data() + TlsPlaintext::sizeInBytes, remainingPacketSize); status != STATUS_SUCCESS)
		return {};

	VM_MINIMUM_END
	return response;
}
void Tls12ProtocolHandler::hashHandshake(const SpanType data) noexcept {
	if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
		libtomcrypt::sha384_process(&this->hashState, data.data(), static_cast<unsigned long>(data.size()));
	else if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		libtomcrypt::sha256_process(&this->hashState, data.data(), static_cast<unsigned long>(data.size()));
}
Array<12> Tls12ProtocolHandler::generateVerifyData(const bool local) {
	VM_MINIMUM_BEGIN
	auto clientFinished = xorstr("client finished");
	clientFinished.crypt();
	const Array<15> clientFinishedArray {SpanType {reinterpret_cast<const UnderlyingDataType*>(clientFinished.get()), 15}};
	clientFinished.crypt();

	auto serverFinished = xorstr("server finished");
	serverFinished.crypt();
	const Array<15> serverFinishedArray {SpanType {reinterpret_cast<const UnderlyingDataType*>(serverFinished.get()), 15}};
	serverFinished.crypt();
	
	const auto previousHashState = this->hashState;

	Array<12> result {};
	const auto &selectedCipherVariant = this->cipherData.front();
	if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
		Array<32> hashedMessages {};
		libtomcrypt::sha256_done(&this->hashState, hashedMessages.data());
		if (local)
			this->hashState = previousHashState;

		const auto seed = (local ? clientFinishedArray : serverFinishedArray) + hashedMessages;
		const auto a1 = tls::hmacSha<256>(aes128Sha256->keys.masterSecret, seed);
		const auto p1 = tls::hmacSha<256>(aes128Sha256->keys.masterSecret, a1 + seed);

		result = p1.subarray<12>();
	} else if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
		Array<48> hashedMessages {};
		libtomcrypt::sha384_done(&this->hashState, hashedMessages.data());
		if (local)
			this->hashState = previousHashState;

		const auto seed = (local ? clientFinishedArray : serverFinishedArray) + hashedMessages;
		const auto a1 = tls::hmacSha<384>(aes256Sha384->keys.masterSecret, seed);
		const auto p1 = tls::hmacSha<384>(aes256Sha384->keys.masterSecret, a1 + seed);

		result = p1.subarray<12>();
	}
	VM_MINIMUM_END
	return result;
}

std::optional<stream::Writer> Tls12ProtocolHandler::sendClientHello(const std::string_view hostname) const {
	VM_MINIMUM_BEGIN
	using namespace handshakes;
	ClientHello clientHello {this->version()};
	{
		// Random data
		clientHello.random.data = this->clientRandom;

		// Ciphers
		for (const auto &variant : this->cipherData)
			if (std::get_if<Aes256Sha384Secp256R1>(&variant))
				clientHello.ciphers.emplace_back(Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
			else if (std::get_if<Aes128Sha256Secp256R1>(&variant))
				clientHello.ciphers.emplace_back(Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

		// Compression methods
		clientHello.compressionMethods.emplace_back(CompressionMethod::NONE);

		// extensions
		clientHello.extensions.emplace_back(ServerNameIndication {.hostNames = {hostname}});
		clientHello.extensions.emplace_back(SupportedVersions {.versions = {this->version()}});

		clientHello.extensions.emplace_back(SignatureAlgorithms {.algorithms = {
			SignatureScheme::ECDSA_SECP256R1_SHA256,
			SignatureScheme::ECDSA_SECP384R1_SHA384,
			SignatureScheme::ECDSA_SECP521R1_SHA512,
			SignatureScheme::RSA_PSS_RSAE_SHA256,
			SignatureScheme::RSA_PSS_RSAE_SHA384,
			SignatureScheme::RSA_PSS_RSAE_SHA512,
			SignatureScheme::RSA_PKCS1_SHA256,
			SignatureScheme::RSA_PKCS1_SHA384,
			SignatureScheme::RSA_PKCS1_SHA512,
			SignatureScheme::ECDSA_SHA1,
			SignatureScheme::RSA_PKCS_SHA1}});
		clientHello.extensions.emplace_back(NegotiatedGroups {.groups = {NamedGroup::SECP256R1}});
		//clientHello.extensions.emplace_back(ApplicationLayerProtocolNegotiation {.protocols = {"http/1.1"}});
	}
	auto clientHelloStream = clientHello.build();
	if (const auto [status, size] = this->socket.send(clientHelloStream.data(), clientHelloStream.size()); status != STATUS_SUCCESS)
		return std::nullopt;
	VM_MINIMUM_END
	return clientHelloStream;  // NOLINT(clang-diagnostic-return-std-move-in-c++11)
}
parser::MessageVariant Tls12ProtocolHandler::parseHandshakeMessages(const SpanType clientHelloStream, const std::string_view hostname) {
	VM_MINIMUM_BEGIN
	using namespace handshakes;

	parser::MessageVariant messages {};
	auto serverHelloReceived {false}, certificatesReceived {false}, serverKeyExchangeReceived {false};
	do {
		const auto response = this->receiveRecord();

		parser::parseHandshakeMessages(messages, response);
		if (messages.error())
			return messages;

		if (!serverHelloReceived) {
			const auto serverHello = messages.find<ServerHello>();
			if (!serverHello)
				return parser::ErrorType::NO_SERVER_HELLO_MESSAGE;

			this->negotiatedCipher = serverHello->cipher;
			this->serverRandom = serverHello->random.data;
			if (serverHello->cipher == Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
				libtomcrypt::sha384_init(&this->hashState);
			else if (serverHello->cipher == Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
				libtomcrypt::sha256_init(&this->hashState);

			// Hash ClientHello
			this->hashHandshake(clientHelloStream.subspan(TlsPlaintext::sizeInBytes));
			serverHelloReceived = true;
		}
		if (const auto handshakeType = static_cast<HandshakeType>(stream::Reader {response}.advance(TlsPlaintext::sizeInBytes).read<std::uint8_t>());
			handshakeType != HandshakeType::HELLO_REQUEST && handshakeType != HandshakeType::HELLO_VERIFY_REQUEST)
			this->hashHandshake(static_cast<SpanType>(response).subspan(TlsPlaintext::sizeInBytes));

		if (!certificatesReceived) {
			const auto serverCertificates = messages.find<handshakes::Certificate>();
			if (!serverCertificates)
				continue;

			if (!serverCertificates->verifyCertificateChains(hostname))
				return parser::ErrorType::CERTIFICATE_INVALID_CERTIFICATE_CHAIN;

			certificatesReceived = true;
		}
		if (!serverKeyExchangeReceived) {
			const auto serverKeyExchange = messages.find<ServerKeyExchange>();
			if (!serverKeyExchange)
				continue;

			this->initializeCipherData(serverKeyExchange);
			serverKeyExchangeReceived = true;
		}
	} while (!messages.find<ServerHelloDone>());
	VM_MINIMUM_END
	return messages;
}
void Tls12ProtocolHandler::initializeCipherData(const handshakes::ServerKeyExchange *serverKeyExchange) {
	VM_MINIMUM_BEGIN
	using namespace handshakes;
	std::erase_if(this->cipherData, [&](const CipherDataVariant &variant) noexcept {
		if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
			return std::get_if<Aes128Sha256Secp256R1>(&variant) == nullptr;
		if (this->negotiatedCipher == Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
			return std::get_if<Aes256Sha384Secp256R1>(&variant) == nullptr;
		return true;
	});

	auto &selectedCipherVariant = this->cipherData.front();
	if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
		internal::secp256r1::generateKeys(aes128Sha256->secretKey, aes128Sha256->clientPublicKey);
		aes128Sha256->serverPublicKey = serverKeyExchange->publicKey;

		const auto preMasterSecret = internal::secp256r1::generatePreMasterSecret(aes128Sha256->secretKey, aes128Sha256->serverPublicKey);
		const auto masterSecret = internal::sha::generateMasterSecret<256>(preMasterSecret, this->clientRandom, this->serverRandom);
		const auto generatedKeys = internal::sha::generateKeys<256>(masterSecret, this->clientRandom, this->serverRandom);

		aes128Sha256->keys.masterSecret = masterSecret;
		aes128Sha256->keys.keys = generatedKeys;
	} else if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
		internal::secp256r1::generateKeys(aes256Sha384->secretKey, aes256Sha384->clientPublicKey);
		aes256Sha384->serverPublicKey = serverKeyExchange->publicKey;

		const auto preMasterSecret = internal::secp256r1::generatePreMasterSecret(aes256Sha384->secretKey, aes256Sha384->serverPublicKey);
		const auto masterSecret = internal::sha::generateMasterSecret<384>(preMasterSecret, this->clientRandom, this->serverRandom);
		const auto generatedKeys = internal::sha::generateKeys<384>(masterSecret, this->clientRandom, this->serverRandom);

		aes256Sha384->keys.masterSecret = masterSecret;
		aes256Sha384->keys.keys = generatedKeys;
	}
	VM_MINIMUM_END
	__nop(); // Prevent tailcall optimizations
}
bool Tls12ProtocolHandler::sendClientKeyExchange() {
	VM_SIZE_SPEED_BEGIN
	using namespace handshakes;

	SpanType clientPublicKey {};
	const auto &selectedCipherVariant = this->cipherData.front();
	if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr)
		clientPublicKey = aes128Sha256->clientPublicKey;
	else if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr)
		clientPublicKey = aes256Sha384->clientPublicKey;

	ClientKeyExchange clientKeyExchange {this->version(), clientPublicKey};
	const auto clientKeyExchangeStream = clientKeyExchange.build();
	if (const auto [status, size] = this->socket.send(clientKeyExchangeStream.data(), clientKeyExchangeStream.size()); status != STATUS_SUCCESS)
		return false;

	this->hashHandshake(clientKeyExchangeStream.subspan(TlsPlaintext::sizeInBytes));
	VM_SIZE_SPEED_END
	return true;
}
bool Tls12ProtocolHandler::sendCipherChangeSpec() const {
	VM_SIZE_SPEED_BEGIN
	using namespace handshakes;

	ChangeCipherSpecification changeCipherSpec {this->version()};
	const auto changeCipherSpecStream = changeCipherSpec.build();
	if (const auto [status, size] = this->socket.send(changeCipherSpecStream.data(), changeCipherSpecStream.size()); status != STATUS_SUCCESS)
		return false;

	VM_SIZE_SPEED_END
	return true;
}
bool Tls12ProtocolHandler::sendFinished() {
	VM_SIZE_SPEED_BEGIN
	using namespace handshakes;
	
	volatile bool result {};
	Finished finished {this->version()};
	const auto &selectedCipherVariant = this->cipherData.front();
	if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
		stream::Writer handshakeStream {};
		handshakeStream.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeType::FINISHED));
		handshakeStream.write<stream::UnsignedInt24>(12);
		handshakeStream.write(this->generateVerifyData(true));

		const auto encryptedHandshake = this->encrypt(handshakeStream, ContentType::HANDSHAKE);
		finished.iv = encryptedHandshake.subspan(0, 8);
		finished.handshake = encryptedHandshake.subspan(8);

		const auto finishedStream = finished.build();
		if (const auto [status, size] = this->socket.send(finishedStream.data(), finishedStream.size()); status != STATUS_SUCCESS)
			return false;

		this->hashHandshake(handshakeStream);
		++this->clientSequenceNumber;
		result = true;
	} else if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
		stream::Writer handshakeStream {};
		handshakeStream.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeType::FINISHED));
		handshakeStream.write<stream::UnsignedInt24>(12);
		handshakeStream.write(this->generateVerifyData(true));

		const auto encryptedHandshake = this->encrypt(handshakeStream, ContentType::HANDSHAKE);
		finished.iv = encryptedHandshake.subspan(0, 8);
		finished.handshake = encryptedHandshake.subspan(8);

		const auto finishedStream = finished.build();
		if (const auto [status, size] = this->socket.send(finishedStream.data(), finishedStream.size()); status != STATUS_SUCCESS)
			return false;

		this->hashHandshake(handshakeStream);
		++this->clientSequenceNumber;
		result = true;
	}
	
	VM_SIZE_SPEED_END
	return result;
}
bool Tls12ProtocolHandler::receiveServerFinished() {
	VM_SIZE_SPEED_BEGIN
	using namespace handshakes;
	// Expect a change cipher spec message
	const auto changeCipherSpecMessage = this->receiveRecord();
	if (changeCipherSpecMessage.empty()) { // Error occurred
		if constexpr (::Configuration::debug)
			print(xorstr_("Change Cipher Spec response was empty!"));
		return false;
	}

	volatile auto result {true};
	stream::Reader changeCipherSpecReader {changeCipherSpecMessage};
	if (const auto contentType = static_cast<ContentType>(changeCipherSpecReader.read<std::uint8_t>());
		contentType != ContentType::CHANGE_CIPHER_SPEC) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Received content type was not as expected (CHANGE_CIPHER_SPEC): %i"), contentType);
		return false;
	}

	// Expect a finished message
	const auto finishedMessage = this->receiveRecord();
	if (finishedMessage.empty()) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Finished message response was empty."));
		return false;
	}

	stream::Reader finishedReader {finishedMessage};
	finishedReader.advance(TlsPlaintext::sizeInBytes);
	const auto iv = finishedReader.read<8>();
	const auto encryptedData = finishedReader.read(finishedMessage.size() - TlsPlaintext::sizeInBytes - sizeof(iv));

	const auto decryptedData = this->decrypt(encryptedData, iv, ContentType::HANDSHAKE);
	if (decryptedData.empty()) { // Error occurred
		if constexpr (::Configuration::debug)
			print(xorstr_("Unable to decrypt encrypted handshake bytes"));
		return false;
	}

	stream::Reader dataReader {decryptedData};
	if (const auto handshakeType = static_cast<HandshakeType>(dataReader.read<std::uint8_t>());
		handshakeType != HandshakeType::FINISHED) {
		if constexpr (::Configuration::debug)
			print(xorstr_("Unexpected handshake type (FINISHED): %i"), handshakeType);
		return false;
	}

	const auto length = dataReader.read<stream::UnsignedInt24>();
	const auto serverVerifyData = dataReader.read(length);

	if (const auto calculatedVerifyData = this->generateVerifyData(false);
		serverVerifyData != calculatedVerifyData) {
		if constexpr (::Configuration::debug)
			print(xorstr_("VerifyData comparison failed!"));
		return false;
	}

	++this->serverSequenceNumber;
	VM_SIZE_SPEED_END
	return result;
}

stream::Writer Tls12ProtocolHandler::encrypt(const SpanType data, ContentType &&type) const {
	VM_SIZE_SPEED_BEGIN
	const auto &selectedCipherVariant = this->cipherData.front();
	if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
		stream::Writer aadStream {};
		aadStream.reserve(13);
		const auto clientSequenceNumberPosition = aadStream.write<std::uint64_t>(this->clientSequenceNumber);
		aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size()));

		const auto streamIv = aadStream.subarray<8>(clientSequenceNumberPosition);
		const aes::GcmInitializationVectorType iv = aes128Sha256->keys.clientIv() + streamIv;
		const auto encryptedData = aes::encrypt<aes::CipherMode::GCM>(data, aes128Sha256->keys.clientKey(), iv, aadStream);

		stream::Writer writer {};
		writer.write(streamIv);
		writer.write(encryptedData);
		return writer;
	}
	if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
		stream::Writer aadStream {};
		aadStream.reserve(13);
		const auto clientSequenceNumberPosition = aadStream.write<std::uint64_t>(this->clientSequenceNumber);
		aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size()));

		const auto streamIv = aadStream.subarray<8>(clientSequenceNumberPosition);
		const aes::GcmInitializationVectorType iv = aes256Sha384->keys.clientIv() + streamIv;
		const auto encryptedData = aes::encrypt<aes::CipherMode::GCM>(data, aes256Sha384->keys.clientKey(), iv, aadStream);

		stream::Writer writer {};
		writer.write(streamIv);
		writer.write(encryptedData);
		return writer;
	}
	VM_SIZE_SPEED_END
	return {};
}
aes::DecryptedDataType Tls12ProtocolHandler::decrypt(const SpanType data, const Array<8> decryptionIv, ContentType &&type) const {
	VM_SIZE_SPEED_BEGIN
	const auto &selectedCipherVariant = this->cipherData.front();
	if (const auto aes128Sha256 = std::get_if<Aes128Sha256Secp256R1>(&selectedCipherVariant); aes128Sha256 != nullptr) {
		stream::Writer aadStream {};
		aadStream.reserve(13);
		aadStream.write<std::uint64_t>(this->serverSequenceNumber);
		aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size()));

		const aes::GcmInitializationVectorType iv = aes128Sha256->keys.serverIv() + decryptionIv;
		return aes::decrypt<aes::CipherMode::GCM>(data, aes128Sha256->keys.serverKey(), iv, aadStream);
	}
	if (const auto aes256Sha384 = std::get_if<Aes256Sha384Secp256R1>(&selectedCipherVariant); aes256Sha384 != nullptr) {
		stream::Writer aadStream {};
		aadStream.reserve(13);
		aadStream.write<std::uint64_t>(this->serverSequenceNumber);
		aadStream.write<std::uint8_t>(static_cast<std::uint8_t>(type));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(this->version()));
		aadStream.write<std::uint16_t>(static_cast<std::uint16_t>(data.size() - aes::defaultTagLength));

		const aes::GcmInitializationVectorType iv = aes256Sha384->keys.serverIv() + decryptionIv;
		return aes::decrypt<aes::CipherMode::GCM>(data, aes256Sha384->keys.serverKey(), iv, aadStream);
	}
	VM_SIZE_SPEED_END
	return {};
}
