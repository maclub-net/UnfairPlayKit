//
//  up_recovery_frame.c
//  CUnfairPlay
//
//  The semantic frame transform. The recovered mixer is an AES-shaped SPN with
//  ten fixed AddRoundKey values, a MixColumns round every time, and a
//  generated non-AES S-box. The profile then maps the 16-byte core output
//  through learned round and final tables so the native port does not need the
//  large generated dispatcher for the frame exchange.
//

#include "up_recovery.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t up_rec_frame_round_keys[10][16] = {
    {0x45, 0xda, 0x26, 0xeb, 0x35, 0xe7, 0x30, 0x12, 0x1e, 0x00, 0x0c, 0xb3, 0x8f, 0xcb, 0xc0, 0x30},
    {0xf9, 0x6f, 0x5c, 0x1a, 0x51, 0xad, 0x34, 0xa5, 0x18, 0x91, 0x15, 0x60, 0xca, 0xc6, 0x70, 0x9c},
    {0x4f, 0x3e, 0x82, 0x6e, 0x1e, 0x93, 0xb6, 0xcb, 0x06, 0x02, 0xa3, 0xab, 0xcc, 0xc4, 0xd3, 0x37},
    {0x57, 0x58, 0x18, 0x25, 0x49, 0xcb, 0xae, 0xee, 0x4f, 0xc9, 0x0d, 0x45, 0x83, 0x0d, 0xde, 0x72},
    {0x88, 0x45, 0x58, 0xc9, 0xc1, 0x8e, 0xf6, 0x27, 0x8e, 0x47, 0xfb, 0x62, 0x0d, 0x4a, 0x25, 0x10},
    {0x4e, 0x7a, 0x92, 0x1e, 0x8f, 0xf4, 0x64, 0x39, 0x01, 0xb3, 0x9f, 0x5b, 0x0c, 0xf9, 0xba, 0x4b},
    {0xf7, 0x8e, 0x21, 0xe0, 0x78, 0x7a, 0x45, 0xd9, 0x79, 0xc9, 0xda, 0x82, 0x75, 0x30, 0x60, 0xc9},
    {0xb3, 0x5e, 0xfc, 0x7d, 0xcb, 0x24, 0xb9, 0xa4, 0xb2, 0xed, 0x63, 0x26, 0xc7, 0xdd, 0x03, 0xef},
    {0xf2, 0x25, 0x23, 0xbb, 0x39, 0x01, 0x9a, 0x1f, 0x8b, 0xec, 0xf9, 0x39, 0x4c, 0x31, 0xfa, 0xd6},
    {0x2e, 0x08, 0xd5, 0x92, 0x17, 0x09, 0x4f, 0x8d, 0x9c, 0xe5, 0xb6, 0xb4, 0xd0, 0xd4, 0x4c, 0x62},
};

static uint8_t up_rec_frame_gf_mul(uint8_t left, uint8_t right) {
    uint8_t result = 0;
    while (right != 0) {
        if ((right & 1) != 0) {
            result ^= left;
        }
        bool high = (left & 0x80) != 0;
        left = (uint8_t)(left << 1);
        if (high) {
            left ^= 0x1b;
        }
        right = (uint8_t)(right >> 1);
    }
    return result;
}

static uint8_t up_rec_frame_gf_inverse(uint8_t value) {
    if (value == 0) {
        return 0;
    }
    uint8_t result = 1;
    uint8_t base = value;
    int exponent = 254;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = up_rec_frame_gf_mul(result, base);
        }
        base = up_rec_frame_gf_mul(base, base);
        exponent >>= 1;
    }
    return result;
}

static void up_rec_frame_sbox(uint8_t table[256]) {
    for (int input = 0; input < 256; input++) {
        uint8_t inverse = up_rec_frame_gf_inverse((uint8_t)input);
        uint8_t rotated = inverse;
        uint8_t value = inverse;
        for (int round = 0; round < 4; round++) {
            rotated = (uint8_t)(rotated << 1 | rotated >> 7);
            value ^= rotated;
        }
        table[input] = value ^ 0x63;
    }
}

static void up_rec_frame_core(const uint8_t input[16], const uint8_t sbox[256],
                              uint8_t output[16]) {
    static const uint8_t shift[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
    uint8_t state[16];
    memcpy(state, input, sizeof(state));
    for (int round = 0; round < 10; round++) {
        const uint8_t *key = up_rec_frame_round_keys[round];
        uint8_t substituted[16];
        for (int target = 0; target < 16; target++) {
            substituted[target] = sbox[state[shift[target]] ^ key[shift[target]]];
        }
        uint8_t mixed[16];
        for (int column = 0; column < 4; column++) {
            int offset = column * 4;
            uint8_t a = substituted[offset];
            uint8_t b = substituted[offset + 1];
            uint8_t c = substituted[offset + 2];
            uint8_t d = substituted[offset + 3];
            mixed[offset] = up_rec_frame_gf_mul(2, a) ^ up_rec_frame_gf_mul(3, b) ^ c ^ d;
            mixed[offset + 1] = a ^ up_rec_frame_gf_mul(2, b) ^ up_rec_frame_gf_mul(3, c) ^ d;
            mixed[offset + 2] = a ^ b ^ up_rec_frame_gf_mul(2, c) ^ up_rec_frame_gf_mul(3, d);
            mixed[offset + 3] = up_rec_frame_gf_mul(3, a) ^ b ^ c ^ up_rec_frame_gf_mul(2, d);
        }
        memcpy(state, mixed, sizeof(state));
    }
    memcpy(output, state, sizeof(state));
}

bool up_rec_frame_transform(up_rec_state *state, const uint8_t input[16], uint8_t output[16],
                            uint32_t *exit_word) {
    const up_rec_frame_profile *model = state->frame;
    if (model == NULL || !model->loaded) {
        snprintf(state->detail, sizeof(state->detail), "semantic frame profile is unavailable");
        return false;
    }
    uint8_t sbox[256];
    up_rec_frame_sbox(sbox);
    uint8_t core[16];
    up_rec_frame_core(input, sbox, core);

    uint8_t current[16];
    memcpy(current, model->input_constant, sizeof(current));
    for (int bit = 0; bit < 128; bit++) {
        if ((core[bit / 8] & (uint8_t)(1u << (bit % 8))) != 0) {
            for (int index = 0; index < 16; index++) {
                current[index] ^= model->input_columns[bit][index];
            }
        }
    }
    uint32_t word = 0;
    for (int round = 0; round < 9; round++) {
        const up_rec_frame_round *profile = &model->rounds[round];
        if (round == 6) {
            for (int output_byte = 0; output_byte < 4; output_byte++) {
                uint8_t value = model->exit_baseline[output_byte];
                for (int slot = 0; slot < 4; slot++) {
                    value ^= model->exit_contributions[output_byte][slot]
                                                    [current[model->exit_inputs[slot]]];
                }
                word |= (uint32_t)value << (unsigned)(output_byte * 8);
            }
        }
        uint8_t next[16];
        memcpy(next, profile->baseline, sizeof(next));
        for (int position = 0; position < 16; position++) {
            for (int slot = 0; slot < 4; slot++) {
                next[profile->targets[position][slot]] ^=
                    profile->tables[position][current[position]][slot];
            }
        }
        memcpy(current, next, sizeof(current));
    }
    for (int target = 0; target < 16; target++) {
        const up_rec_frame_final *entry = &model->final[target];
        if (entry->input_count == 1) {
            output[target] = entry->direct[current[entry->inputs[0]]];
            continue;
        }
        uint8_t decoded = 0;
        for (int slot = 0; slot < 3; slot++) {
            decoded ^= entry->contributions[slot][current[entry->inputs[slot]]];
        }
        output[target] = entry->baseline ^ entry->encode[decoded];
    }
    *exit_word = word;
    return true;
}
