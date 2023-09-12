#include "tommath_private.h"

#ifdef MP_TO_RADIX_C
#include <Framework/Utilities/Strings/XorStr.hpp>
#include "../../Configuration.hpp"

extern "C" {
	/* reverse an array, used for radix code */
	static void s_reverse(char *s, size_t len) {
		size_t ix = 0, iy = len - 1u;
		while (ix < iy) {
			MP_EXCH(char, s[ix], s[iy]);
			++ix;
			--iy;
		}
	}

	/* stores a bignum as a ASCII string in a given radix (2..64)
	*
	* Stores upto "size - 1" chars and always a NULL byte, puts the number of characters
	* written, including the '\0', in "written".
	*/
	mp_err mp_to_radix(const mp_int *a, char *str, size_t maxlen, size_t *written, int radix) {
		VM_SIZE_SPEED_BEGIN
		size_t  digs;
		mp_err  err;
		mp_int  t;
		mp_digit d;
		char   *_s = str;

		/* check range of radix and size*/
		if (maxlen < 2u) {
			return MP_BUF;
		}
		if ((radix < 2) || (radix > 64)) {
			return MP_VAL;
		}

		/* quick out if its zero */
		if (mp_iszero(a)) {
			*str++ = '0';
			*str = '\0';
			if (written != NULL) {
				*written = 2u;
			}
			return MP_OKAY;
		}

		if ((err = mp_init_copy(&t, a)) != MP_OKAY) {
			return err;
		}

		/* if it is negative output a - */
		if (mp_isneg(&t)) {
			/* we have to reverse our digits later... but not the - sign!! */
			++_s;

			/* store the flag and mark the number as positive */
			*str++ = '-';
			t.sign = MP_ZPOS;

			/* subtract a char */
			--maxlen;
		}
		digs = 0u;

		const auto s_mp_radix_map = xorstr_("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/");
		while (!mp_iszero(&t)) {
			if (--maxlen < 1u) {
				/* no more room */
				err = MP_BUF;
				goto LBL_ERR;
			}
			if ((err = mp_div_d(&t, (mp_digit)radix, &t, &d)) != MP_OKAY) {
				goto LBL_ERR;
			}
			*str++ = s_mp_radix_map[d];
			++digs;
		}
		/* reverse the digits of the string.  In this case _s points
		* to the first digit [excluding the sign] of the number
		*/
		s_reverse(_s, digs);

		/* append a NULL so the string is properly terminated */
		*str = '\0';
		digs++;

		if (written != NULL) {
			*written = mp_isneg(a) ? (digs + 1u): digs;
		}

		LBL_ERR:
		mp_clear(&t);
		VM_SIZE_SPEED_END
		return err;
	}

	/* read a string [ASCII] in a given radix */
	mp_err mp_read_radix(mp_int *a, const char *str, int radix) {
		VM_SIZE_SPEED_BEGIN
		mp_err   err;
		mp_sign  sign = MP_ZPOS;

		/* make sure the radix is ok */
		if ((radix < 2) || (radix > 64)) {
			return MP_VAL;
		}

		/* if the leading digit is a
		* minus set the sign to negative.
		*/
		if (*str == '-') {
			++str;
			sign = MP_NEG;
		}

		/* set the integer to the default of zero */
		mp_zero(a);

		/* process each digit of the string */
		const auto s_mp_radix_map_reverse = xorstr_(
			"\x3e\xff\xff\xff\x3f\x00\x01\x02\x03\x04" /* +,-./01234 */
			"\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff" /* 56789:;<=> */
			"\xff\xff\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11" /* ?@ABCDEFGH */
			"\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b" /* IJKLMNOPQR */
			"\x1c\x1d\x1e\x1f\x20\x21\x22\x23\xff\xff" /* STUVWXYZ[\ */
			"\xff\xff\xff\xff\x24\x25\x26\x27\x28\x29" /* ]^_`abcdef */
			"\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33" /* ghijklmnop */
			"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d" /* qrstuvwxyz */);
		while (*str != '\0') {
			/* if the radix <= 36 the conversion is case insensitive
			* this allows numbers like 1AB and 1ab to represent the same  value
			* [e.g. in hex]
			*/
			uint8_t y;
			char ch = (radix <= 36) ? (char)MP_TOUPPER((int)*str) : *str;
			unsigned pos = (unsigned)(ch - '+');
			if (MP_RADIX_MAP_REVERSE_SIZE <= pos) {
				break;
			}
			y = reinterpret_cast<std::uint8_t*>(s_mp_radix_map_reverse)[pos];

			/* if the char was found in the map
			* and is less than the given radix add it
			* to the number, otherwise exit the loop.
			*/
			if (y >= radix) {
				break;
			}
			if ((err = mp_mul_d(a, (mp_digit)radix, a)) != MP_OKAY) {
				return err;
			}
			if ((err = mp_add_d(a, y, a)) != MP_OKAY) {
				return err;
			}
			++str;
		}

		/* if an illegal character was found, fail. */
		if ((*str != '\0') && (*str != '\r') && (*str != '\n')) {
			return MP_VAL;
		}

		/* set the sign only if a != 0 */
		if (!mp_iszero(a)) {
			a->sign = sign;
		}
		VM_SIZE_SPEED_END
		return MP_OKAY;
	}
}
#endif
