/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_unregister_cipher.c
  Unregister a cipher, Tom St Denis
*/

/**
  Unregister a cipher from the descriptor table
  @param cipher   The cipher descriptor to remove
  @return CRYPT_OK on success
*/
int unregister_cipher(const struct ltc_cipher_descriptor *cipher)
{
   int x;

   LTC_ARGCHK(cipher != NULL);

   /* is it already registered? */
   LTC_MUTEX_LOCK(&ltc_cipher_mutex);
   for (x = 0; x < TAB_SIZE; x++) {
       if (XMEMCMP(&cipher_descriptor[x], cipher, sizeof(struct ltc_cipher_descriptor)) == 0) {
          cipher_descriptor[x].min_key_length = 0;
          cipher_descriptor[x].ID   = 255;
          LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
          return CRYPT_OK;
       }
   }
   LTC_MUTEX_UNLOCK(&ltc_cipher_mutex);
   return CRYPT_ERROR;
}