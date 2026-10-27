//
//  up_pagekey.h
//  CUnfairPlay
//
//  SUPF record → per-page AES key derivation, ported from
//  internal/fairplay/pagekey.go.
//

#ifndef UP_PAGEKEY_H
#define UP_PAGEKEY_H

#include <stdbool.h>
#include <stdint.h>

/// Derives the per-enrollment application mask from the logical key.
void up_app_mask_from_logical_key(const uint8_t logical[16], uint8_t mask[16]);

/// Caches the effective AES key (`fixedPageAESKey ^ appMask`).
typedef struct {
    uint8_t effective[16];
} up_page_deriver;

void up_page_deriver_init(up_page_deriver *deriver, const uint8_t app_mask[16]);

/// Derives the page key for `wrapped` at byte `offset`. `little_endian`
/// selects the little-endian padding used by the audit diagnostic; the
/// decryption path always uses big-endian.
void up_page_key(const up_page_deriver *deriver,
                 const uint8_t wrapped[16],
                 uint64_t offset,
                 bool little_endian,
                 uint8_t key[16]);

/// Derives the page key for an explicit 8-byte padding value.
void up_page_key_with_padding(const up_page_deriver *deriver,
                              const uint8_t wrapped[16],
                              const uint8_t padding[8],
                              uint8_t key[16]);

#endif /* UP_PAGEKEY_H */
