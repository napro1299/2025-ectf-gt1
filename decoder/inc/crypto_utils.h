/**
 * @author GT1: Nicolas Amato
 * 
 * This file defines a common cryptographic interface for AES, BLAKE2, and HMAC.
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>

/**
 * Encrypt with AES-128-CBC.
 * 
 * Data is padded with PKCS#7.
 * 
 * @return 0 on success
 */
int encrypt_cbc_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext);

/**
 * pt_len is length of plaintext - padding
 */
int decrypt_cbc_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *iv, uint8_t *plaintext, int *pt_len);

void blake2s_hash(uint8_t *in, size_t len, uint8_t *digest);

#endif