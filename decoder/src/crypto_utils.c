/**
 * @author GT1: Nicolas Amato
 * 
 * This file defines a common cryptographic interface for AES, SHA256, and HMAC.
 */

#include "crypto_utils.h"
#include "host_messaging.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "aes.h"
#include "mxc_errors.h"

#define HMAC_LEN    SHA256_DIGEST_SIZE
#define CRYPTO_ERROR -1

// SDK doesn't define AES regs???
// #define MXC_AES ((mxc_aes_regs_t *) 0x40007400)

/**
 * Verify and unpad bytes. 
 * 
 * Padding consists of bytes of value of the pad size.
 * Padding value must be between [1, 16].
 * 
 * e.g. MESSAGE\x03\x03\x03
 */
static int pkcs7_unpad(uint8_t *in, size_t len, int *pt_len) {
    int pad_val = in[len - 1];

    if (pad_val < 1 || pad_val > AES_BLOCK_SIZE) 
        return CRYPTO_ERROR;

    for (int i = 0; i < pad_val; i++) {
        if (in[len - 1 - i] != pad_val) {
            return CRYPTO_ERROR;
        }
    }

    *pt_len = len - pad_val;
    return 0;
}

/**
 * AES decrypt single block using on-board AES module.
 */
static int aes_block_decrypt(uint8_t *in, uint8_t *out, uint8_t *key, int key_size) {
    mxc_aes_req_t req;
    int result;

    req.length = AES_BLOCK_SIZE;
    req.inputData = (uint32_t *) in;
    req.resultData = (uint32_t *) out;
    if (key_size == AES128) {
        req.keySize = MXC_AES_128BITS;
    } else if (key_size == AES256) {
        req.keySize = MXC_AES_256BITS;
    } else {
        return CRYPTO_ERROR;
    }
    req.encryption = MXC_AES_DECRYPT_EXT_KEY;

    MXC_AES->ctrl = 0x00;
    MXC_AES_SetKeySize(req.keySize);
    MXC_AES_SetExtKey(key, req.keySize);
    MXC_AES->ctrl |= 0x01;

    result = MXC_AES_Decrypt(&req);
    if (result != E_SUCCESS)
        return CRYPTO_ERROR;

    return 0;
}
#pragma pack(push, 1)
typedef struct {
    uint8_t bytes[16];
} channel_key_t;
typedef struct {
    uint32_t device_id;
    uint64_t start;
    uint64_t end;
    uint32_t channel;
    channel_key_t channel_key;
    char padding[8];
} subscription_update_payload_t;
#pragma pack(pop)
int decrypt_cbc_sym(uint8_t *ciphertext, size_t len, uint8_t *key, int key_size, uint8_t *iv, uint8_t *plaintext, int *pt_len) {
    int result;

    if (!ciphertext || !key || !iv || !plaintext || !pt_len)
        return CRYPTO_ERROR;

    if (len <= 0)
        return CRYPTO_ERROR;

    if (key_size != AES128 && key_size != AES256)
        return CRYPTO_ERROR;

    if (len % AES_BLOCK_SIZE != 0)
        return CRYPTO_ERROR;

    // Perform the CBC decryption
    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    uint8_t decrypted_block[AES_BLOCK_SIZE];
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        print_debug("1\n");
        result = aes_block_decrypt(ciphertext + i, decrypted_block, key, key_size);
        if (result != 0)
            return CRYPTO_ERROR;
            
        print_debug("2\n");

        // XOR with previous block (IV for first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            plaintext[i + j] = decrypted_block[j] ^ prev_block[j];
        }
        print_debug("3\n");

        memcpy(prev_block, ciphertext + i, AES_BLOCK_SIZE);
    }
    // char output_buf[128] = {0};
    // sprintf(output_buf, "len: %d\n", len);
    // print_debug(output_buf);
    // // memset output buff 0
    // memset(output_buf, 0, sizeof(output_buf));
    // sprintf(output_buf, "%d\n", *(uint32_t *)(&(((subscription_update_payload_t *)plaintext)->padding[0])));
    // print_debug(output_buf);

    // Remove padding
    result = pkcs7_unpad(plaintext, len, pt_len);
    if (result != 0) 
        return CRYPTO_ERROR;

    print_debug("5\n");
    
    return 0;
}

void sha256_hash(uint8_t *in, size_t len, uint8_t *digest) {
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, in, len);
    wc_Sha256Final(&sha, digest);
}

void hmac_digest(uint8_t *in, size_t len, uint8_t *key, size_t key_size, uint8_t *digest) {
    Hmac hmac;
    wc_HmacSetKey(&hmac, SHA256, key, key_size);
    wc_HmacUpdate(&hmac, in, len);
    wc_HmacFinal(&hmac, digest);
}

int hmac_verify(uint8_t *data, size_t len, uint8_t *hmac, uint8_t *key, size_t key_size) {
    uint8_t our_hmac[HMAC_LEN];

    hmac_digest(data, len, key, key_size, our_hmac);

    if (memcmp(hmac, our_hmac, HMAC_LEN) != 0)
        return CRYPTO_ERROR;

    return 0;
}