#include "crypto_utils.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/hmac.h>

/**
 * Verify and unpad bytes. 
 * 
 * Padding consists of bytes of value of the pad size.
 * Padding value must be between [1, 16].
 * 
 * e.g. MESSAGE\x03\x03\x03
 */
static int pkcs7_unpad(uint8_t *in, int *len) {
    int pad_val = in[*len - 1];

    if (pad_val < 1 || pad_val > AES_BLOCK_SIZE) 
        return -1;

    for (int i = 0; i < pad_val; i++) {
        if (in[*len - 1 - i] != pad_val) {
            return -1;
        }
    }

    *len -= pad_val;
    return 0;
}

int encrypt_cbc_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext) {
    Aes aes;
    int result;

    if (len <= 0)
        return -1;

    // Init Aes ctx
    wc_AesInit(&aes, NULL, INVALID_DEVID);

    // Set Aes key
    result = wc_AesSetKey(&aes, key, AES_128_KEY_SIZE, iv, AES_ENCRYPTION);
    if (result != 0)
        return result;

    // Perform PKCS#7 padding
    int pad_size = wc_PKCS7_GetPadSize(len, AES_BLOCK_SIZE);
    size_t padded_pt_size = len + pad_size;
    uint8_t *padded_pt = (uint8_t *) malloc(padded_pt_size);

    result = wc_PKCS7_PadData(plaintext, len, padded_pt, padded_pt_size, AES_BLOCK_SIZE);
    if (result != padded_pt_size) 
        return -1;

    return wc_AesCbcEncrypt(&aes, ciphertext, padded_pt, padded_pt_size);
}

int decrypt_cbc_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *iv, uint8_t *plaintext, int *pt_len) {
    Aes aes;
    int result;

    if (len <= 0)
        return -1;

    // Init Aes ctx
    wc_AesInit(&aes, NULL, INVALID_DEVID);

    // Set Aes key
    result = wc_AesSetKey(&aes, key, AES_128_KEY_SIZE, iv, AES_DECRYPTION);
    if (result != 0)
        return result;

    result = wc_AesCbcDecrypt(&aes, plaintext, ciphertext, len);
    if (result != 0) 
        return result;

    // Remove padding
    result = pkcs7_unpad(plaintext, pt_len);
    if (result != 0) 
        return result;

    return 0;
}

void blake2s_hash(uint8_t *in, size_t len, uint8_t *digest) {
    Blake2s b2s;
    wc_InitBlake2s(&b2s, 32);
    wc_Blake2sUpdate(&b2s, in, len);
    wc_Blake2sFinal(&b2s, digest, 32);
}
