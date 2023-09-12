#include "Certificate.hpp"

using namespace tls::handshakes;

#include "../../../../../../Utilities/Printer.hpp"
namespace printer = KM::Utilities::Printer;

bool Certificate::verifyCertificateChains(const std::string_view hostname) const {
	VM_SIZE_SPEED_BEGIN
	for (auto iterator = this->certificates.cbegin(); iterator != this->certificates.cend(); ++iterator) {
		const auto nextEntry = iterator + 1;

		const tls::Certificate *issuer {};
		if (nextEntry != this->certificates.cend())
			issuer = &*nextEntry;
		
		if (!iterator->valid(issuer, iterator == this->certificates.cbegin() ? hostname : std::string_view {})) {
			if constexpr (Configuration::print) {
				const auto &parsedCertificate = iterator->parsedCertificate;
				const auto subjectCommonName = parsedCertificate.subjectName.commonName;
				const auto issuerCommonName = parsedCertificate.subjectName.commonName;
				printer::print(xorstr_("[!] Failed to verify the certificate chain for %s [subject: %s -> issuer: %s]"),
					hostname,
					subjectCommonName.data(),
					issuerCommonName.data());
			}
			return false;
		}
	}
	VM_SIZE_SPEED_END
	return true;
}
