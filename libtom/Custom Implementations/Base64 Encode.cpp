#include "tomcrypt_private.h"

/**
@file base64_encode.c
Compliant base64 encoder donated by Wayne Scott (wscott@bitmover.com)
base64 URL Safe variant (RFC 4648 section 5) by Karel Miko
*/



#if defined(LTC_BASE64) || defined (LTC_BASE64_URL)
#include <Framework/Utilities/Strings/XorStr.hpp>
#include "../../Configuration.hpp"

extern "C" {
	static int s_base64_encode_internal(const unsigned char *in,  unsigned long inlen,
		char *out, unsigned long *outlen,
		const char *codes, int pad) {
		VM_SIZE_SPEED_BEGIN
		unsigned long i, len2, leven;
		char *p;

		LTC_ARGCHK(in     != NULL);
		LTC_ARGCHK(out    != NULL);
		LTC_ARGCHK(outlen != NULL);

		/* valid output size ? */
		len2 = 4 * ((inlen + 2) / 3);
		if (*outlen < len2 + 1) {
			*outlen = len2 + 1;
			return CRYPT_BUFFER_OVERFLOW;
		}
		p = out;
		leven = 3*(inlen / 3);
		for (i = 0; i < leven; i += 3) {
			*p++ = codes[(in[0] >> 2) & 0x3F];
			*p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
			*p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
			*p++ = codes[in[2] & 0x3F];
			in += 3;
		}
		/* Pad it if necessary...  */
		if (i < inlen) {
			unsigned a = in[0];
			unsigned b = (i+1 < inlen) ? in[1] : 0;

			*p++ = codes[(a >> 2) & 0x3F];
			*p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
			if (pad) {
				*p++ = (i+1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
				*p++ = '=';
			}
			else {
				if (i+1 < inlen) *p++ = codes[(((b & 0xf) << 2)) & 0x3F];
			}
		}

		/* append a NULL byte */
		*p = '\0';

		/* return ok */
		*outlen = (unsigned long)(p - out); /* the length without terminating NUL */
		VM_SIZE_SPEED_END
		return CRYPT_OK;
	}

	#if defined(LTC_BASE64)
	/**
	base64 Encode a buffer (NUL terminated)
	@param in      The input buffer to encode
	@param inlen   The length of the input buffer
	@param out     [out] The destination of the base64 encoded data
	@param outlen  [in/out] The max size and resulting size
	@return CRYPT_OK if successful
	*/
	int base64_encode(const unsigned char *in,  unsigned long inlen, char *out, unsigned long *outlen) {
		VM_SIZE_SPEED_BEGIN
		volatile auto result = s_base64_encode_internal(in, inlen, out, outlen, xorstr_("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), 1);
		VM_SIZE_SPEED_END
		return result;
	}
	#endif /* LTC_BASE64 */


	#if defined(LTC_BASE64_URL)
	/**
	base64 (URL Safe, RFC 4648 section 5) Encode a buffer (NUL terminated)
	@param in      The input buffer to encode
	@param inlen   The length of the input buffer
	@param out     [out] The destination of the base64 encoded data
	@param outlen  [in/out] The max size and resulting size
	@return CRYPT_OK if successful
	*/
	int base64url_encode(const unsigned char *in,  unsigned long inlen, char *out, unsigned long *outlen) {
		VM_SIZE_SPEED_BEGIN
		volatile auto result = s_base64_encode_internal(in, inlen, out, outlen, xorstr_("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), 0);
		VM_SIZE_SPEED_END
		return result;
	}

	int base64url_strict_encode(const unsigned char *in,  unsigned long inlen, char *out, unsigned long *outlen) {
		VM_SIZE_SPEED_BEGIN
		volatile auto result = s_base64_encode_internal(in, inlen, out, outlen, xorstr_("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), 1);
		VM_SIZE_SPEED_END
		return result;
	}
	#endif /* LTC_BASE64_URL */
}
#endif
