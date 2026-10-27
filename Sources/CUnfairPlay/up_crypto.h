//
//  up_crypto.h
//  CUnfairPlay
//
//  Thin wrappers over CommonCrypto. The Go upstream only uses AES-CBC without
//  padding and SHA-1/SHA-256/SHA-384, so the surface stays this small.
//

#ifndef UP_CRYPTO_H
#define UP_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// AES-CBC without padding. `input` must be a whole number of 16-byte blocks.
/// `output` may alias `input` for in-place decryption.
bool up_aes_cbc(bool encrypt,
                const uint8_t key[16],
                const uint8_t iv[16],
                const uint8_t *input,
                size_t length,
                uint8_t *output);

/// Single-block AES encryption (CBC with a zero IV is ECB for one block).
bool up_aes_encrypt_block(const uint8_t key[16], const uint8_t block[16], uint8_t output[16]);

/// Single-block AES decryption (CBC with a zero IV is ECB for one block).
bool up_aes_decrypt_block(const uint8_t key[16], const uint8_t block[16], uint8_t output[16]);

/// SHA-256 over a byte range. `output` must hold 32 bytes.
void up_sha256(const uint8_t *bytes, size_t length, uint8_t output[32]);

/// Streaming SHA-256, used while writing an IPA.
typedef struct up_sha256_ctx up_sha256_ctx;

up_sha256_ctx *up_sha256_create(void);
void up_sha256_update(up_sha256_ctx *ctx, const uint8_t *bytes, size_t length);
void up_sha256_final(up_sha256_ctx *ctx, uint8_t output[32]);
void up_sha256_release(up_sha256_ctx *ctx);

/// SHA-1 over a byte range. `output` must hold 20 bytes.
void up_sha1(const uint8_t *bytes, size_t length, uint8_t output[20]);

/// SHA-384 over a byte range. `output` must hold 48 bytes.
void up_sha384(const uint8_t *bytes, size_t length, uint8_t output[48]);

#endif /* UP_CRYPTO_H */
