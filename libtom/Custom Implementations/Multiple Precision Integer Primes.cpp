#include "tommath_private.h"

#ifdef S_MP_PRIME_IS_DIVISIBLE_C
/* determines if an integers is divisible by one
* of the first PRIME_SIZE primes or not
*
* sets result to 0 if not, 1 if yes
*/
mp_err s_mp_prime_is_divisible(const mp_int *a, bool *result) {
	int i;
	for (i = 0; i < MP_PRIME_TAB_SIZE; i++) {
		/* what is a mod LBL_prime_tab[i] */
		mp_err err;
		mp_digit res;
		if ((err = mp_mod_d(a, s_mp_prime_tab[i], &res)) != MP_OKAY) {
			return err;
		}

		/* is the residue zero? */
		if (res == 0u) {
			*result = true;
			return MP_OKAY;
		}
	}

	/* default to not */
	*result = false;
	return MP_OKAY;
}
#endif

const mp_digit s_mp_prime_tab[] = {
	0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
	0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
	0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
	0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F, 0x0083,
	0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
	0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
	0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
	0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,

	0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167,
	0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199,
	0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9,
	0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7,
	0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239,
	0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265,
	0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293,
	0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF,

	0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301,
	0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B,
	0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371,
	0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD,
	0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
	0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419,
	0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449,
	0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,

	0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7,
	0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503,
	0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529,
	0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F,
	0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3,
	0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7,
	0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623,
	0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653
};

#ifdef MP_PRIME_IS_PRIME_C
#include <Framework/Utilities/Strings/XorStr.hpp>
#include "../../Configuration.hpp"

extern "C" {
	/* portable integer log of two with small footprint */
	static unsigned int s_floor_ilog2(int value) {
		unsigned int r = 0;
		while ((value >>= 1) != 0) {
		   r++;
		}
		return r;
	}

	mp_err mp_prime_is_prime(const mp_int *a, int t, bool *result) {
		VM_SIZE_SPEED_BEGIN
		mp_int  b;
		int     ix;
		bool    res;
		mp_err  err;

		/* default to no */
		*result = false;

		/* Some shortcuts */
		/* N > 3 */
		if (a->used == 1) {
		   if ((a->dp[0] == 0u) || (a->dp[0] == 1u)) {
			  *result = false;
			  return MP_OKAY;
		   }
		   if (a->dp[0] == 2u) {
			  *result = true;
			  return MP_OKAY;
		   }
		}

		/* N must be odd */
		if (mp_iseven(a)) {
		   return MP_OKAY;
		}
		/* N is not a perfect square: floor(sqrt(N))^2 != N */
		if ((err = mp_is_square(a, &res)) != MP_OKAY) {
		   return err;
		}
		if (res) {
		   return MP_OKAY;
		}

		/* is the input equal to one of the primes in the table? */
		for (ix = 0; ix < MP_PRIME_TAB_SIZE; ix++) {
		   if (mp_cmp_d(a, s_mp_prime_tab[ix]) == MP_EQ) {
			  *result = true;
			  return MP_OKAY;
		   }
		}
		/* first perform trial division */
		if ((err = s_mp_prime_is_divisible(a, &res)) != MP_OKAY) {
		   return err;
		}

		/* return if it was trivially divisible */
		if (res) {
		   return MP_OKAY;
		}

		/*
			Run the Miller-Rabin test with base 2 for the BPSW test.
		 */
		if ((err = mp_init_set(&b, 2uL)) != MP_OKAY) {
		   return err;
		}

		if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
		   goto LBL_B;
		}
		if (!res) {
		   goto LBL_B;
		}
		/*
		   Rumours have it that Mathematica does a second M-R test with base 3.
		   Other rumours have it that their strong L-S test is slightly different.
		   It does not hurt, though, beside a bit of extra runtime.
		*/
		b.dp[0]++;
		if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
		   goto LBL_B;
		}
		if (!res) {
		   goto LBL_B;
		}

		/*
		 * Both, the Frobenius-Underwood test and the the Lucas-Selfridge test are quite
		 * slow so if speed is an issue, define LTM_USE_ONLY_MR to use M-R tests with
		 * bases 2, 3 and t random bases.
		 */
	#ifndef LTM_USE_ONLY_MR
		if (t >= 0) {
	#ifdef LTM_USE_FROBENIUS_TEST
		   err = mp_prime_frobenius_underwood(a, &res);
		   if ((err != MP_OKAY) && (err != MP_ITER)) {
			  goto LBL_B;
		   }
		   if (!res) {
			  goto LBL_B;
		   }
	#else
		   if ((err = mp_prime_strong_lucas_selfridge(a, &res)) != MP_OKAY) {
			  goto LBL_B;
		   }
		   if (!res) {
			  goto LBL_B;
		   }
	#endif
		}
	#endif

		/* run at least one Miller-Rabin test with a random base */
		if (t == 0) {
		   t = 1;
		}

		/*
		   Only recommended if the input range is known to be < 3317044064679887385961981

		   It uses the bases necessary for a deterministic M-R test if the input is
		   smaller than  3317044064679887385961981
		   The caller has to check the size.
		   TODO: can be made a bit finer grained but comparing is not free.
		*/
		if (t < 0) {
		   int p_max = 0;

		   /*
			   Sorenson, Jonathan; Webster, Jonathan (2015).
				"Strong Pseudoprimes to Twelve Prime Bases".
			*/
		   /* 0x437ae92817f9fc85b7e5 = 318665857834031151167461 */
		   if ((err =   mp_read_radix(&b, xorstr_("437ae92817f9fc85b7e5"), 16)) != MP_OKAY) {
			  goto LBL_B;
		   }

		   if (mp_cmp(a, &b) == MP_LT) {
			  p_max = 12;
		   } else {
			  /* 0x2be6951adc5b22410a5fd = 3317044064679887385961981 */
			  if ((err = mp_read_radix(&b, xorstr_("2be6951adc5b22410a5fd"), 16)) != MP_OKAY) {
				 goto LBL_B;
			  }

			  if (mp_cmp(a, &b) == MP_LT) {
				 p_max = 13;
			  } else {
				 err = MP_VAL;
				 goto LBL_B;
			  }
		   }

		   /* we did bases 2 and 3  already, skip them */
		   for (ix = 2; ix < p_max; ix++) {
			  mp_set(&b, s_mp_prime_tab[ix]);
			  if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
				 goto LBL_B;
			  }
			  if (!res) {
				 goto LBL_B;
			  }
		   }
		}
		/*
			Do "t" M-R tests with random bases between 3 and "a".
			See Fips 186.4 p. 126ff
		*/
		else if (t > 0) {
		   unsigned int mask;
		   int size_a;

		   /*
			* The mp_digit's have a defined bit-size but the size of the
			* array a.dp is a simple 'int' and this library can not assume full
			* compliance to the current C-standard (ISO/IEC 9899:2011) because
			* it gets used for small embeded processors, too. Some of those MCUs
			* have compilers that one cannot call standard compliant by any means.
			* Hence the ugly type-fiddling in the following code.
			*/
		   size_a = mp_count_bits(a);
		   mask = (1u << s_floor_ilog2(size_a)) - 1u;
		   /*
			  Assuming the General Rieman hypothesis (never thought to write that in a
			  comment) the upper bound can be lowered to  2*(log a)^2.
			  E. Bach, "Explicit bounds for primality testing and related problems,"
			  Math. Comp. 55 (1990), 355-380.

				 size_a = (size_a/10) * 7;
				 len = 2 * (size_a * size_a);

			  E.g.: a number of size 2^2048 would be reduced to the upper limit

				 floor(2048/10)*7 = 1428
				 2 * 1428^2       = 4078368

			  (would have been ~4030331.9962 with floats and natural log instead)
			  That number is smaller than 2^28, the default bit-size of mp_digit.
		   */

		   /*
			 How many tests, you might ask? Dana Jacobsen of Math::Prime::Util fame
			 does exactly 1. In words: one. Look at the end of _GMP_is_prime() in
			 Math-Prime-Util-GMP-0.50/primality.c if you do not believe it.

			 The function mp_rand() goes to some length to use a cryptographically
			 good PRNG. That also means that the chance to always get the same base
			 in the loop is non-zero, although very low.
			 If the BPSW test and/or the addtional Frobenious test have been
			 performed instead of just the Miller-Rabin test with the bases 2 and 3,
			 a single extra test should suffice, so such a very unlikely event
			 will not do much harm.

			 To preemptivly answer the dangling question: no, a witness does not
			 need to be prime.
		   */
		   for (ix = 0; ix < t; ix++) {
			  unsigned int fips_rand;
			  int len;

			  /* mp_rand() guarantees the first digit to be non-zero */
			  if ((err = mp_rand(&b, 1)) != MP_OKAY) {
				 goto LBL_B;
			  }
			  /*
			   * Reduce digit before casting because mp_digit might be bigger than
			   * an unsigned int and "mask" on the other side is most probably not.
			   */
			  fips_rand = (unsigned int)(b.dp[0] & (mp_digit) mask);
			  if (fips_rand > (unsigned int)(INT_MAX - MP_DIGIT_BIT)) {
				 len = INT_MAX / MP_DIGIT_BIT;
			  } else {
				 len = (((int)fips_rand + MP_DIGIT_BIT) / MP_DIGIT_BIT);
			  }
			  /*  Unlikely. */
			  if (len < 0) {
				 ix--;
				 continue;
			  }
			  if ((err = mp_rand(&b, len)) != MP_OKAY) {
				 goto LBL_B;
			  }
			  /*
			   * That number might got too big and the witness has to be
			   * smaller than "a"
			   */
			  len = mp_count_bits(&b);
			  if (len >= size_a) {
				 len = (len - size_a) + 1;
				 if ((err = mp_div_2d(&b, len, &b, NULL)) != MP_OKAY) {
					goto LBL_B;
				 }
			  }
			  /* Although the chance for b <= 3 is miniscule, try again. */
			  if (mp_cmp_d(&b, 3uL) != MP_GT) {
				 ix--;
				 continue;
			  }
			  if ((err = mp_prime_miller_rabin(a, &b, &res)) != MP_OKAY) {
				 goto LBL_B;
			  }
			  if (!res) {
				 goto LBL_B;
			  }
		   }
		}

		/* passed the test */
		*result = true;
	LBL_B:
		mp_clear(&b);
		VM_SIZE_SPEED_END
		return err;
	}
}
#endif

#ifdef MP_PRIME_NEXT_PRIME_C
extern "C" {
	/* finds the next prime after the number "a" using "t" trials
	* of Miller-Rabin.
	*
	* bbs_style = true means the prime must be congruent to 3 mod 4
	*/
	mp_err mp_prime_next_prime(mp_int *a, int t, bool bbs_style)
	{
		int      x;
		mp_err   err;
		bool  res = false;
		mp_digit res_tab[MP_PRIME_TAB_SIZE], kstep;
		mp_int   b;

		/* force positive */
		a->sign = MP_ZPOS;

		/* simple algo if a is less than the largest prime in the table */
		if (mp_cmp_d(a, s_mp_prime_tab[MP_PRIME_TAB_SIZE-1]) == MP_LT) {
			/* find which prime it is bigger than "a" */
			for (x = 0; x < MP_PRIME_TAB_SIZE; x++) {
				mp_ord cmp = mp_cmp_d(a, s_mp_prime_tab[x]);
				if (cmp == MP_EQ) {
					continue;
				}
				if (cmp != MP_GT) {
					if ((bbs_style) && ((s_mp_prime_tab[x] & 3u) != 3u)) {
						/* try again until we get a prime congruent to 3 mod 4 */
						continue;
					} else {
						mp_set(a, s_mp_prime_tab[x]);
						return MP_OKAY;
					}
				}
			}
			/* fall through to the sieve */
		}

		/* generate a prime congruent to 3 mod 4 or 1/3 mod 4? */
		kstep = bbs_style ? 4 : 2;

		/* at this point we will use a combination of a sieve and Miller-Rabin */

		if (bbs_style) {
			/* if a mod 4 != 3 subtract the correct value to make it so */
			if ((a->dp[0] & 3u) != 3u) {
				if ((err = mp_sub_d(a, (a->dp[0] & 3u) + 1u, a)) != MP_OKAY) {
					return err;
				}
			}
		} else {
			if (mp_iseven(a)) {
				/* force odd */
				if ((err = mp_sub_d(a, 1uL, a)) != MP_OKAY) {
					return err;
				}
			}
		}

		/* generate the restable */
		for (x = 1; x < MP_PRIME_TAB_SIZE; x++) {
			if ((err = mp_mod_d(a, s_mp_prime_tab[x], res_tab + x)) != MP_OKAY) {
				return err;
			}
		}

		/* init temp used for Miller-Rabin Testing */
		if ((err = mp_init(&b)) != MP_OKAY) {
			return err;
		}

		for (;;) {
			mp_digit step = 0;
			bool y;
			/* skip to the next non-trivially divisible candidate */
			do {
				/* y == true if any residue was zero [e.g. cannot be prime] */
				y     = false;

				/* increase step to next candidate */
				step += kstep;

				/* compute the new residue without using division */
				for (x = 1; x < MP_PRIME_TAB_SIZE; x++) {
					/* add the step to each residue */
					res_tab[x] += kstep;

					/* subtract the modulus [instead of using division] */
					if (res_tab[x] >= s_mp_prime_tab[x]) {
						res_tab[x]  -= s_mp_prime_tab[x];
					}

					/* set flag if zero */
					if (res_tab[x] == 0u) {
						y = true;
					}
				}
			} while (y && (step < (((mp_digit)1 << MP_DIGIT_BIT) - kstep)));

			/* add the step */
			if ((err = mp_add_d(a, step, a)) != MP_OKAY) {
				goto LBL_ERR;
			}

			/* if didn't pass sieve and step == MP_MAX then skip test */
			if (y && (step >= (((mp_digit)1 << MP_DIGIT_BIT) - kstep))) {
				continue;
			}

			if ((err = mp_prime_is_prime(a, t, &res)) != MP_OKAY) {
				goto LBL_ERR;
			}
			if (res) {
				break;
			}
		}

		LBL_ERR:
		mp_clear(&b);
		return err;
	}
}
#endif
