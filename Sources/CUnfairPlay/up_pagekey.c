//
//  up_pagekey.c
//  CUnfairPlay
//
//  Bit-exact port of internal/fairplay/pagekey.go. Every intermediate is kept
//  in the same width the Go source uses, because the fold and square steps
//  rely on wraparound.
//

#include "up_pagekey.h"

#include <string.h>

#include "up_crypto.h"

static const uint8_t up_fixed_page_aes_key[16] = {
    0xf5, 0x88, 0xff, 0xe1, 0x89, 0xf9, 0x89, 0xf8,
    0xe1, 0xf8, 0x89, 0xfe, 0x8a, 0xe1, 0xf4, 0xfe,
};

static const uint8_t up_page_fold_permutation[4][8] = {
    {0, 1, 2, 3, 4, 5, 6, 7},
    {2, 1, 0, 3, 4, 7, 6, 5},
    {2, 0, 4, 1, 6, 3, 7, 5},
    {1, 2, 4, 0, 7, 3, 5, 6},
};

static const uint32_t up_page_fold_pair_xor[4] = {0x1e2a7432, 0x087be9c2, 0xa2eb0b97, 0x7ccc42c1};
static const uint32_t up_page_fold_output_xor[4] = {0x0b770182, 0xbb5b7b69, 0x5f8c31bf, 0xa6e7227a};

static uint8_t up_xtime(uint8_t value) {
    uint8_t reduction = (value & 0x80) != 0 ? 0x1b : 0;
    return (uint8_t)((value << 1) ^ reduction);
}

static void up_mix_column(const uint8_t input[4], uint8_t output[4]) {
    uint8_t doubled[4];
    for (int index = 0; index < 4; index++) {
        doubled[index] = up_xtime(input[index]);
    }
    output[0] = doubled[0] ^ (doubled[1] ^ input[1]) ^ input[2] ^ input[3];
    output[1] = input[0] ^ doubled[1] ^ (doubled[2] ^ input[2]) ^ input[3];
    output[2] = input[0] ^ input[1] ^ doubled[2] ^ (doubled[3] ^ input[3]);
    output[3] = (doubled[0] ^ input[0]) ^ input[1] ^ input[2] ^ doubled[3];
}

static void up_inverse_mix_column(const uint8_t input[4], uint8_t output[4]) {
    uint8_t doubled[4], quadrupled[4], octupled[4];
    for (int index = 0; index < 4; index++) {
        doubled[index] = up_xtime(input[index]);
        quadrupled[index] = up_xtime(doubled[index]);
        octupled[index] = up_xtime(quadrupled[index]);
    }
    uint8_t m09[4], m0b[4], m0d[4], m0e[4];
    for (int index = 0; index < 4; index++) {
        m09[index] = octupled[index] ^ input[index];
        m0b[index] = octupled[index] ^ doubled[index] ^ input[index];
        m0d[index] = octupled[index] ^ quadrupled[index] ^ input[index];
        m0e[index] = octupled[index] ^ quadrupled[index] ^ doubled[index];
    }
    output[0] = m0e[0] ^ m0b[1] ^ m0d[2] ^ m09[3];
    output[1] = m09[0] ^ m0e[1] ^ m0b[2] ^ m0d[3];
    output[2] = m0d[0] ^ m09[1] ^ m0e[2] ^ m0b[3];
    output[3] = m0b[0] ^ m0d[1] ^ m09[2] ^ m0e[3];
}

static uint32_t up_masked_select(uint32_t value, uint32_t gate) {
    return (((value ^ 0x2919f272u) & ~gate) | (gate & 0xd6e60000u)) ^ 0x29192e1eu;
}

static uint32_t up_feed_term(uint32_t value, uint16_t mask_source) {
    uint32_t high = (value << 16) ^ 0xff99de03u;
    uint32_t mask = (uint32_t)mask_source ^ 0xffff2207u;
    uint32_t fallback = (uint32_t)mask_source & 0x21fcu;
    return ((high & mask) | fallback) ^ 0x23f5de6fu;
}

static uint64_t up_post_square(uint32_t value, uint32_t constant) {
    uint64_t product = (uint64_t)value * (uint64_t)value;
    uint64_t high = product >> 32;
    uint64_t correction = high - UINT64_C(0x0d09f9b1421db190) - ((high << 1) & UINT64_C(0x17bc49ce0));
    return product ^ (uint64_t)constant ^ correction;
}

static void up_page_fold(const uint8_t input[16], uint8_t output[16]) {
    uint16_t initial[8], state[8];
    for (int index = 0; index < 8; index++) {
        initial[index] = (uint16_t)(((uint16_t)input[index * 2] << 8) | input[index * 2 + 1]);
        initial[index] = (uint16_t)(initial[index] ^ 0xdc6c);
        state[index] = initial[index];
    }
    for (int round = 0; round < 4; round++) {
        uint16_t next[8];
        for (int pair = 0; pair < 4; pair++) {
            uint32_t left =
                (uint32_t)(state[up_page_fold_permutation[round][pair * 2]] ^ 0xdc6c);
            uint32_t right =
                (uint32_t)(state[up_page_fold_permutation[round][pair * 2 + 1]] ^ 0xdc6c);
            uint32_t sum = left + right;
            uint32_t square = (uint32_t)((uint64_t)sum * (uint64_t)sum) ^ up_page_fold_pair_xor[pair];
            uint32_t carry = sum >> 16;
            next[pair * 2] = (uint16_t)(square ^ carry * carry ^ 0xd470);
            next[pair * 2 + 1] = (uint16_t)((square >> 16) ^ 0xaa12);
        }
        memcpy(state, next, sizeof(state));
    }
    uint32_t gate3 = (uint32_t)(state[3] ^ 0xdc6c) << 16;
    uint32_t gate6 = (uint32_t)(state[6] ^ 0xdc6c) << 16;
    uint32_t gate7 = (uint32_t)(state[7] ^ 0xdc6c) << 16;
    uint32_t combined[4];
    combined[0] = up_masked_select(state[2], gate3) + up_feed_term(state[1], state[0]);
    combined[1] = up_masked_select(state[4], gate6) + up_feed_term(state[2], state[0]);
    combined[2] = up_masked_select(state[5], gate7) + up_feed_term(state[3], state[0]);
    combined[3] = up_masked_select(state[6], gate7) + up_feed_term(state[5], state[4]);
    for (int pair = 0; pair < 4; pair++) {
        uint64_t square = up_post_square(combined[pair], up_page_fold_output_xor[pair]);
        uint16_t low = (uint16_t)(initial[pair * 2] ^ (uint16_t)square ^ 0x0b59);
        uint16_t high = (uint16_t)(initial[pair * 2 + 1] ^ (uint16_t)(square >> 16) ^ 0x3188);
        output[pair * 4] = (uint8_t)(low >> 8);
        output[pair * 4 + 1] = (uint8_t)low;
        output[pair * 4 + 2] = (uint8_t)(high >> 8);
        output[pair * 4 + 3] = (uint8_t)high;
    }
}

void up_app_mask_from_logical_key(const uint8_t logical[16], uint8_t mask[16]) {
    uint8_t encoded[16];
    for (int column = 0; column < 4; column++) {
        const uint8_t *word = logical + column * 4;
        uint8_t reversed[4] = {word[3], word[2], word[1], word[0]};
        uint8_t mixed[4];
        up_mix_column(reversed, mixed);
        memcpy(encoded + column * 4, mixed, 4);
    }
    static const uint32_t writers[4] = {0x1467cdb1u, 0xbea0cbf9u, 0xea98d9d3u, 0x477a1e20u};
    static const uint8_t final_mask[16] = {0xE6, 0x3D, 0xC3, 0x4E, 0x30, 0x8B, 0xB3, 0x1F,
                                           0x0C, 0xB2, 0xA1, 0x33, 0xCA, 0x49, 0x1B, 0xC0};
    uint8_t state[16];
    for (int column = 0; column < 4; column++) {
        uint8_t mixed[4];
        up_inverse_mix_column(encoded + column * 4, mixed);
        uint32_t value = 0;
        for (int pass = 0; pass < 4; pass++) {
            value = ((value & 0x00ffffffu) << 8 | (uint32_t)mixed[pass]) + 0x7db82c18u;
        }
        uint32_t result = (value + (uint32_t)(column + 13) * 0x594ec277u + 0x8603bbe8u) ^
                          0x07d2f11eu ^ writers[column];
        state[column * 4] = (uint8_t)(result >> 24);
        state[column * 4 + 1] = (uint8_t)(result >> 16);
        state[column * 4 + 2] = (uint8_t)(result >> 8);
        state[column * 4 + 3] = (uint8_t)result;
    }
    for (int index = 0; index < 16; index++) {
        state[index] ^= final_mask[index];
    }
    memcpy(mask, state, 16);
}

void up_page_deriver_init(up_page_deriver *deriver, const uint8_t app_mask[16]) {
    for (int index = 0; index < 16; index++) {
        deriver->effective[index] = up_fixed_page_aes_key[index] ^ app_mask[index];
    }
}

void up_page_key_with_padding(const up_page_deriver *deriver,
                              const uint8_t wrapped[16],
                              const uint8_t padding[8],
                              uint8_t key[16]) {
    uint8_t plaintext[3][16];
    memcpy(plaintext[0], wrapped + 8, 8);
    memcpy(plaintext[0] + 8, padding, 8);
    memcpy(plaintext[1], wrapped, 16);
    memcpy(plaintext[2], padding, 8);
    memcpy(plaintext[2] + 8, wrapped, 8);

    uint8_t encrypted[3][16];
    for (int index = 0; index < 3; index++) {
        up_aes_encrypt_block(deriver->effective, plaintext[index], encrypted[index]);
    }
    memset(plaintext, 0, sizeof(plaintext));

    uint8_t state[16];
    up_page_fold(encrypted[0], state);
    for (int index = 0; index < 16; index++) {
        state[index] ^= encrypted[1][index];
    }
    up_page_fold(state, state);
    for (int index = 0; index < 16; index++) {
        state[index] ^= encrypted[2][index];
    }
    up_page_fold(state, key);
    memset(encrypted, 0, sizeof(encrypted));
    memset(state, 0, sizeof(state));
}

void up_page_key(const up_page_deriver *deriver,
                 const uint8_t wrapped[16],
                 uint64_t offset,
                 bool little_endian,
                 uint8_t key[16]) {
    uint8_t padding[8];
    for (int index = 0; index < 8; index++) {
        int shift = little_endian ? index * 8 : (7 - index) * 8;
        padding[index] = (uint8_t)(offset >> shift);
    }
    up_page_key_with_padding(deriver, wrapped, padding, key);
}
