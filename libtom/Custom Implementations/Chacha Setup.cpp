// ReSharper disable IdentifierTypo
// ReSharper disable CommentTypo
#include "tomcrypt_private.h"

#ifdef LTC_CHACHA
#include <Framework/Utilities/Strings/XorStr.hpp>
#include "../../Configuration.hpp"

extern "C" {
	/**
	Initialize an ChaCha context (only the key)
	@param st        [out] The destination of the ChaCha state
	@param key       The secret key
	@param keylen    The length of the secret key (octets)
	@param rounds    Number of rounds (e.g. 20 for ChaCha20)
	@return CRYPT_OK if successful
	*/

	int chacha_setup(chacha_state *st, const unsigned char *key, const unsigned long keylen, int rounds) {
		VM_SIZE_SPEED_BEGIN
		LTC_ARGCHK(keylen == 32 || keylen == 16);

		if (rounds == 0) rounds = 20;

		const char *constants {};
		const auto tau   = xorstr_("expand 16-byte k");
		const auto sigma = xorstr_("expand 32-byte k");

		LOAD32L(st->input[4], key + 0);
		LOAD32L(st->input[5], key + 4);
		LOAD32L(st->input[6], key + 8);
		LOAD32L(st->input[7], key + 12);
		if (keylen == 32) { /* 256bit */
			key += 16;
			constants = sigma;
		} else { /* 128bit */
			constants = tau;
		}
		LOAD32L(st->input[8],  key + 0);
		LOAD32L(st->input[9],  key + 4);
		LOAD32L(st->input[10], key + 8);
		LOAD32L(st->input[11], key + 12);
		LOAD32L(st->input[0],  constants + 0);
		LOAD32L(st->input[1],  constants + 4);
		LOAD32L(st->input[2],  constants + 8);
		LOAD32L(st->input[3],  constants + 12);
		st->rounds = rounds; /* e.g. 20 for chacha20 */
		st->ivlen = 0; /* will be set later by chacha_ivctr(32|64) */
		VM_SIZE_SPEED_END

		return CRYPT_OK;
	}
}
#endif
