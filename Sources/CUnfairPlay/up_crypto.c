//
//  up_crypto.c
//  CUnfairPlay
//

#include "up_crypto.h"

#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>

bool up_aes_cbc(bool encrypt,
                const uint8_t key[16],
                const uint8_t iv[16],
                const uint8_t *input,
                size_t length,
                uint8_t *output) {
    if (length % kCCBlockSizeAES128 != 0) {
        return false;
    }
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(
        encrypt ? kCCEncrypt : kCCDecrypt,
        kCCAlgorithmAES,
        0, /* CBC, no padding */
        key, kCCKeySizeAES128,
        iv,
        input, length,
        output, length,
        &moved);
    return status == kCCSuccess && moved == length;
}

bool up_aes_encrypt_block(const uint8_t key[16], const uint8_t block[16], uint8_t output[16]) {
    static const uint8_t zero_iv[16] = {0};
    return up_aes_cbc(true, key, zero_iv, block, 16, output);
}

bool up_aes_decrypt_block(const uint8_t key[16], const uint8_t block[16], uint8_t output[16]) {
    static const uint8_t zero_iv[16] = {0};
    return up_aes_cbc(false, key, zero_iv, block, 16, output);
}

void up_sha256(const uint8_t *bytes, size_t length, uint8_t output[32]) {
    CC_SHA256(bytes, (CC_LONG)length, output);
}

struct up_sha256_ctx {
    CC_SHA256_CTX ctx;
};

up_sha256_ctx *up_sha256_create(void) {
    up_sha256_ctx *ctx = calloc(1, sizeof(up_sha256_ctx));
    if (ctx == NULL) {
        return NULL;
    }
    CC_SHA256_Init(&ctx->ctx);
    return ctx;
}

void up_sha256_update(up_sha256_ctx *ctx, const uint8_t *bytes, size_t length) {
    if (ctx == NULL || length == 0) {
        return;
    }
    CC_SHA256_Update(&ctx->ctx, bytes, (CC_LONG)length);
}

void up_sha256_final(up_sha256_ctx *ctx, uint8_t output[32]) {
    if (ctx == NULL) {
        return;
    }
    CC_SHA256_Final(output, &ctx->ctx);
}

void up_sha256_release(up_sha256_ctx *ctx) {
    free(ctx);
}

void up_sha1(const uint8_t *bytes, size_t length, uint8_t output[20]) {
    CC_SHA1(bytes, (CC_LONG)length, output);
}

void up_sha384(const uint8_t *bytes, size_t length, uint8_t output[48]) {
    CC_SHA384(bytes, (CC_LONG)length, output);
}
