//
//  up_recovery_engine.c
//  CUnfairPlay
//
//  The compact ARM64 subset interpreter. This is a direct port of the
//  reference `runCompactKernel`: 277 generated opcodes, the same operand-only
//  encoding, and the same flag, division and vector semantics. Every memory
//  access goes through `up_rec_state_*` so the destination-page rules and the
//  read-after-write checks stay identical.
//

#include "up_recovery.h"

#include <string.h>

// MARK: - Opcodes

typedef enum {
    compactAnd32 = 0,
    compactAdd32,
    compactLoadSXTW32,
    compactXor64,
    compactAddLSR64,
    compactUMADDL,
    compactLSRV64,
    compactAddUXTW64,
    compactAndLSL64,
    compactSub64,
    compactAdd64,
    compactXor32,
    compactStoreSXTW32,
    compactAddImm32,
    compactCmp32,
    compactCCmp32LE,
    compactCSet32LT,
    compactMul32,
    compactLoadSXTW64,
    compactMov64,
    compactMovImm64,
    compactStoreSP32,
    compactMovImm32,
    compactMovK32,
    compactUDiv32,
    compactMSub32,
    compactLoadSP32,
    compactUMull32,
    compactLoadUXTW8,
    compactLSRImm64,
    compactMov32,
    compactOr32,
    compactSub32,
    compactAndLSL32,
    compactAddSPShiftImm64,
    compactLoadBaseImm32,
    compactExtract32,
    compactNot32,
    compactLSRImm32,
    compactLoadSP64,
    compactMovImm32High,
    compactAddImmShift32,
    compactLSLImm32,
    compactXorLSL32,
    compactStoreBase32,
    compactLoadUXTW32,
    compactMovNegOne32,
    compactMovK64,
    compactAddLSL32,
    compactXorLSR32,
    compactLSRReg32,
    compactStoreUXTW8,
    compactUMulH64,
    compactMAdd32,
    compactMAdd64,
    compactAdds64,
    compactADC32,
    compactCMN64,
    compactCmpImm32,
    compactCSet32HI,
    compactStoreBaseImm32,
    compactMul64,
    compactSubImmShift32,
    compactXorImm32,
    compactSubLSL32,
    compactMovImm32Wide,
    compactAnd64,
    compactLSLImm64,
    compactMovImm64Shift,
    compactXorLSL64,
    compactCSet32LO,
    compactOrLSL32,
    compactAndImm32,
    compactOrNotLSL32,
    compactRORImm32,
    compactXorROR32,
    compactOrROR32,
    compactCSELZeroEq32,
    compactCSet32EQ,
    compactLoadBase64,
    compactLoadPostIndex8,
    compactLSLReg32,
    compactStoreBase64,
    compactCMNImm32,
    compactOr64,
    compactMovImm64Repeat16,
    compactAddLSL64,
    compactLoadBaseImm64,
    compactAddImm64,
    compactLoadBase32,
    compactStoreSP64,
    compactMovNegImm64,
    compactCmp64,
    compactSubImm64,
    compactStoreXIndex8,
    compactCmpImm64,
    compactOrImm64,
    compactXorImm64,
    compactStoreUXTW32,
    compactNoop,
    compactMovImm48,
    compactAddSPImm,
    compactSubSPImm,
    compactLoadSignedOffset32,
    compactLoadSignedOffset64,
    compactStoreSignedOffset32,
    compactStoreSignedOffset64,
    compactLoadSignedOffset8,
    compactLoadSignedByte32,
    compactStoreSignedOffset8,
    compactBic32,
    compactBic64,
    compactSXT8To32,
    compactSXT32To64,
    compactNeg32,
    compactNeg64,
    compactTst32,
    compactTstImm32,
    compactCSet32,
    compactCSEL32,
    compactCSEL64,
    compactCInc32,
    compactCInc64,
    compactCNeg32,
    compactLoadHalf32,
    compactLoadSignedOffsetHalf32,
    compactStoreHalf32,
    compactStoreSignedOffsetHalf32,
    compactPairLoad32,
    compactPairLoad64,
    compactPairStore32,
    compactPairStore64,
    compactLoadBaseImm8,
    compactLoadSPImm8,
    compactLoadXIndex8,
    compactStoreBaseImm8,
    compactStoreSPImm8,
    compactLoadXIndex32,
    compactLoadXIndex64,
    compactStoreXIndex32,
    compactStoreXIndex64,
    compactLoadUXTW64,
    compactStoreBaseImm64,
    compactAddExt32,
    compactAddExt64,
    compactMovSP,
    compactSubSPFromX,
    compactOrImm32,
    compactOrLSL64,
    compactAndLSR32,
    compactCmpExtByte32,
    compactCmpLSR32,
    compactCCmpReg32,
    compactCCmpReg64,
    compactCCmpImm32,
    compactCCmpImm64,
    compactAdds32,
    compactSubs32,
    compactSubs64,
    compactSubsImm32,
    compactSubsImm64,
    compactSMull32,
    compactUBFIZ32,
    compactUBFIZ64,
    compactUBFX32,
    compactUBFX64,
    compactBFI32,
    compactBFXIL32,
    compactOrNotShift32,
    compactOrNotShift64,
    compactNot64,
    compactLSLReg64,
    compactLSRReg64,
    compactAndImm64,
    compactAndImmShift64,
    compactXorNotImm16Shift64,
    compactAddImmShift64,
    compactSubImmShift64,
    compactMovFromSP,
    compactAddLSR32,
    compactSubLSL64,
    compactSubExt32,
    compactLoadXIndexShift32,
    compactStoreXIndexShift32,
    compactLoadPreIndex32,
    compactStorePreIndex64,
    compactLoadSignedWord64,
    compactAnds32,
    compactBics32,
    compactCCmnImm32,
    compactCLZ32,
    compactCMNImm64,
    compactMovNegImm48,
    compactMovNegImm16Shift64,
    compactMovNegRepeat16PlusOne,
    compactAndNotImm16Shift64,
    compactCASAL32,
    compactStorePostIndex32,
    compactStorePreIndex32,
    compactAddASR32,
    compactAddUXTH64,
    compactXorLSR64,
    compactXorImm16Shift64,
    compactLoadSignedWordBase64,
    compactLoadHalfXIndex32,
    compactLoadSPHalf32,
    compactMNeg64,
    compactMSub64,
    compactSBFIZ64,
    compactStoreUXTW64,
    compactStorePostIndex8,
    compactVectorDup32,
    compactLoadVector,
    compactASRImm32,
    compactAndsLSR32,
    compactBicsLSR32,
    compactCCmnImm64,
    compactCSInc32,
    compactTstImm64,
    compactEon32,
    compactVectorImmediate,
    compactVectorBinary,
    compactVectorMAC,
    compactVectorUnsignedShiftLong,
    compactVectorMove64,
    compactStoreVector,
    compactVectorUnsignedMultiplyLong,
    compactVectorEor3,
    compactPairStoreVector,
    compactVectorTable1,
    compactVectorTable4,
    compactVectorExtractNarrow,
    compactVectorShiftRightNarrow,
    compactVectorUnzipEven,
    compactVectorNegateFloat64,
    compactVectorUnsignedShiftRight,
    compactVectorToW,
    compactVectorUnsignedShift,
    compactVectorMove128,
    compactWToVectorLane,
    compactAndsImm32,
    compactASRReg32,
    compactASRImm64,
    compactBFI64,
    compactBicLSR32,
    compactCMNLSL64,
    compactCmpUXTH32,
    compactEon64,
    compactXorASR32,
    compactLoadPostIndex32,
    compactLoadPostIndex64,
    compactLoadHalfUXTW32,
    compactMovMaxIntMinusOne,
    compactOrLSR32,
    compactOrHigh32Imm64,
    compactRev32,
    compactSBFIZ32,
    compactSBFX32,
    compactStoreSPHalf32,
    compactStorePostIndex64,
    compactMovMaxInt,
    compactLoadPreIndex64,
    compactXorSelectionMask64,
    compactSXT16To32,
    compactStoreHalfPostIndex32,
    compactSubUXTH32,
    compactUDiv64,
    compactLoadHalfXIndexShift32,
    compactSubLSR32,
    compactLogicalMask64,
    compactTestRegister64,
    compactMNeg32,
    compactRORImm64,
    compactXorROR64,
    compactLoadSXTW8,
    compactSubLSR64,
    compactPairLoadVector,
    compactOpcodeCount
} up_rec_opcode;

_Static_assert(compactOpcodeCount == 277, "compact opcode count must match the reference profile");

// Hook actions, in the reference order.
enum {
    up_rec_hook_digest = 0,
    up_rec_hook_optional,
    up_rec_hook_even,
    up_rec_hook_odd,
    up_rec_hook_tail,
    up_rec_hook_writer
};

// Condition codes, in the reference order.
enum {
    up_rec_condition_eq = 0,
    up_rec_condition_ne,
    up_rec_condition_hs,
    up_rec_condition_lo,
    up_rec_condition_mi,
    up_rec_condition_pl,
    up_rec_condition_vs,
    up_rec_condition_vc,
    up_rec_condition_hi,
    up_rec_condition_ls,
    up_rec_condition_ge,
    up_rec_condition_lt,
    up_rec_condition_gt,
    up_rec_condition_le
};

// MARK: - Flags

static uint64_t up_rec_bool_value(bool value) {
    return value ? 1 : 0;
}

static void up_rec_set_nzcv(up_rec_state *state, int value) {
    state->n = (value & 8) != 0;
    state->z = (value & 4) != 0;
    state->c = (value & 2) != 0;
    state->v = (value & 1) != 0;
}

static void up_rec_compare_32(up_rec_state *state, uint32_t left, uint32_t right) {
    uint32_t result = left - right;
    state->n = (result & UINT32_C(0x80000000)) != 0;
    state->z = result == 0;
    state->c = left >= right;
    state->v = ((left ^ right) & (left ^ result) & UINT32_C(0x80000000)) != 0;
}

static void up_rec_compare_64(up_rec_state *state, uint64_t left, uint64_t right) {
    uint64_t result = left - right;
    state->n = (result & UINT64_C(0x8000000000000000)) != 0;
    state->z = result == 0;
    state->c = left >= right;
    state->v = ((left ^ right) & (left ^ result) & UINT64_C(0x8000000000000000)) != 0;
}

static void up_rec_test_32(up_rec_state *state, uint32_t value) {
    state->n = (value & UINT32_C(0x80000000)) != 0;
    state->z = value == 0;
    state->c = false;
    state->v = false;
}

static void up_rec_test_64(up_rec_state *state, uint64_t value) {
    state->n = (value & UINT64_C(0x8000000000000000)) != 0;
    state->z = value == 0;
    state->c = false;
    state->v = false;
}

static uint64_t up_rec_subtract_with_flags(up_rec_state *state, uint64_t left, uint64_t right, int width) {
    if (width == 32) {
        up_rec_compare_32(state, (uint32_t)left, (uint32_t)right);
        return (uint64_t)((uint32_t)left - (uint32_t)right);
    }
    up_rec_compare_64(state, left, right);
    return left - right;
}

static uint64_t up_rec_add_with_carry(up_rec_state *state, uint64_t left, uint64_t right, bool carry, int width) {
    uint64_t carry_value = carry ? 1u : 0u;
    if (width == 32) {
        uint64_t result64 = (uint64_t)(uint32_t)left + (uint64_t)(uint32_t)right + carry_value;
        uint32_t result = (uint32_t)result64;
        state->n = (result & UINT32_C(0x80000000)) != 0;
        state->z = result == 0;
        state->c = (result64 >> 32) != 0;
        state->v = ((~(uint32_t)(left ^ right)) & ((uint32_t)left ^ result) & UINT32_C(0x80000000)) != 0;
        return (uint64_t)result;
    }
    __uint128_t sum = (__uint128_t)left + (__uint128_t)right + (__uint128_t)carry_value;
    uint64_t result = (uint64_t)sum;
    state->n = (result & UINT64_C(0x8000000000000000)) != 0;
    state->z = result == 0;
    state->c = (sum >> 64) != 0;
    state->v = (~(left ^ right) & (left ^ result) & UINT64_C(0x8000000000000000)) != 0;
    return result;
}

/// Returns -1 for an unknown condition code, otherwise the condition result.
int up_rec_condition_matches(up_rec_state *state, uint8_t condition) {
    switch (condition) {
    case up_rec_condition_eq:
        return state->z;
    case up_rec_condition_ne:
        return !state->z;
    case up_rec_condition_hs:
        return state->c;
    case up_rec_condition_lo:
        return !state->c;
    case up_rec_condition_mi:
        return state->n;
    case up_rec_condition_pl:
        return !state->n;
    case up_rec_condition_vs:
        return state->v;
    case up_rec_condition_vc:
        return !state->v;
    case up_rec_condition_hi:
        return state->c && !state->z;
    case up_rec_condition_ls:
        return !state->c || state->z;
    case up_rec_condition_ge:
        return state->n == state->v;
    case up_rec_condition_lt:
        return state->n != state->v;
    case up_rec_condition_gt:
        return !state->z && state->n == state->v;
    case up_rec_condition_le:
        return state->z || state->n != state->v;
    default:
        return -1;
    }
}

// MARK: - Vector helpers

static void up_rec_vector_dup(up_rec_state *state, int reg, int lanes, int bits, uint64_t value) {
    up_rec_vector_clear(state, reg);
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_set_lane(state, reg, lane, bits, value);
    }
}

/// Writes one lane into a 16-byte vector buffer, matching the reference
/// little-endian lane layout.
static void up_rec_lane_write(uint8_t *buffer, int lane, int bits, uint64_t value) {
    size_t offset = (size_t)lane * (size_t)bits / 8;
    switch (bits) {
    case 8:
        buffer[offset] = (uint8_t)value;
        break;
    case 16:
        buffer[offset] = (uint8_t)value;
        buffer[offset + 1] = (uint8_t)(value >> 8);
        break;
    case 32:
        for (int index = 0; index < 4; index++) {
            buffer[offset + (size_t)index] = (uint8_t)(value >> (unsigned)(index * 8));
        }
        break;
    case 64:
        for (int index = 0; index < 8; index++) {
            buffer[offset + (size_t)index] = (uint8_t)(value >> (unsigned)(index * 8));
        }
        break;
    default:
        break;
    }
}

static void up_rec_vector_binary(up_rec_state *state, int operation, int destination,
                                 int left, int right, int lanes, int bits) {
    uint8_t result[16] = {0};
    for (int lane = 0; lane < lanes; lane++) {
        uint64_t left_value = 0;
        uint64_t right_value = 0;
        up_rec_vector_lane(state, left, lane, bits, &left_value);
        up_rec_vector_lane(state, right, lane, bits, &right_value);
        uint64_t value = 0;
        switch (operation) {
        case 0:
            value = left_value + right_value;
            break;
        case 1:
            value = left_value - right_value;
            break;
        case 2:
            value = left_value * right_value;
            break;
        default:
            value = left_value ^ right_value;
            break;
        }
        up_rec_lane_write(result, lane, bits, value);
    }
    memcpy(state->vectors[destination], result, sizeof(result));
}

// MARK: - Kernel errors

static bool up_rec_kernel_fail(up_rec_state *state, uint64_t pc) {
    char inner[sizeof(state->detail)];
    memcpy(inner, state->detail, sizeof(inner));
    inner[sizeof(inner) - 1] = '\0';
    snprintf(state->detail, sizeof(state->detail), "compact kernel %#llx: %s",
             (unsigned long long)pc, inner);
    return false;
}

static bool up_rec_kernel_load(up_rec_state *state, uint64_t pc, uint64_t address,
                               int size, uint64_t *value) {
    if (!up_rec_state_load(state, address, size, value)) {
        return up_rec_kernel_fail(state, pc);
    }
    return true;
}

static bool up_rec_kernel_store_value(up_rec_state *state, uint64_t pc, uint64_t address,
                                      uint64_t value, int size) {
    if (!up_rec_state_store_value(state, address, value, size)) {
        return up_rec_kernel_fail(state, pc);
    }
    return true;
}

static bool up_rec_kernel_load_vector(up_rec_state *state, uint64_t pc, int reg,
                                      uint64_t address, int size) {
    uint8_t data[16] = {0};
    if (!up_rec_state_output_bytes(state, address, data, (size_t)size)) {
        return up_rec_kernel_fail(state, pc);
    }
    up_rec_vector_clear(state, reg);
    memcpy(state->vectors[reg], data, (size_t)size);
    return true;
}

static bool up_rec_kernel_store_vector(up_rec_state *state, uint64_t pc, int reg,
                                       uint64_t address, int size) {
    if (!up_rec_state_store(state, address, state->vectors[reg], (size_t)size)) {
        return up_rec_kernel_fail(state, pc);
    }
    return true;
}

static bool up_rec_kernel_condition(up_rec_state *state, uint64_t pc, uint8_t condition,
                                    bool *matches) {
    int result = up_rec_condition_matches(state, condition);
    if (result < 0) {
        snprintf(state->detail, sizeof(state->detail),
                 "unknown compact block condition %d", (int)condition);
        return up_rec_kernel_fail(state, pc);
    }
    *matches = result != 0;
    return true;
}

static bool up_rec_vector_table(up_rec_state *state, uint64_t pc, int destination,
                                const int *tables, int table_count, int indexes) {
    uint8_t result[16] = {0};
    for (int lane = 0; lane < 16; lane++) {
        int index = state->vectors[indexes][lane];
        if (index < table_count * 16) {
            result[lane] = state->vectors[tables[index / 16]][index % 16];
        }
    }
    memcpy(state->vectors[destination], result, sizeof(result));
    (void)pc;
    return true;
}

static bool up_rec_vector_multiply_accumulate(up_rec_state *state, int destination, int left,
                                              int right, int lanes, int bits, bool subtract) {
    uint8_t previous[16];
    memcpy(previous, state->vectors[destination], sizeof(previous));
    for (int lane = 0; lane < lanes; lane++) {
        uint64_t accumulator = 0;
        size_t offset = (size_t)lane * (size_t)bits / 8;
        switch (bits) {
        case 8:
            accumulator = previous[offset];
            break;
        case 16:
            accumulator = (uint64_t)previous[offset] | (uint64_t)previous[offset + 1] << 8;
            break;
        case 32:
            accumulator = (uint64_t)previous[offset] |
                          (uint64_t)previous[offset + 1] << 8 |
                          (uint64_t)previous[offset + 2] << 16 |
                          (uint64_t)previous[offset + 3] << 24;
            break;
        default:
            accumulator = 0;
            for (int index = 7; index >= 0; index--) {
                accumulator = accumulator << 8 | previous[offset + (size_t)index];
            }
            break;
        }
        uint64_t left_value = 0;
        uint64_t right_value = 0;
        up_rec_vector_lane(state, left, lane, bits, &left_value);
        up_rec_vector_lane(state, right, lane, bits, &right_value);
        uint64_t product = left_value * right_value;
        up_rec_vector_set_lane(state, destination, lane, bits,
                               subtract ? accumulator - product : accumulator + product);
    }
    return true;
}

static void up_rec_vector_unsigned_multiply_long(up_rec_state *state, int destination,
                                                 int left, int right, int lanes,
                                                 int input_bits, bool high) {
    int start = high ? lanes : 0;
    uint64_t left_values[16];
    uint64_t right_values[16];
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_lane(state, left, start + lane, input_bits, &left_values[lane]);
        up_rec_vector_lane(state, right, start + lane, input_bits, &right_values[lane]);
    }
    up_rec_vector_clear(state, destination);
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_set_lane(state, destination, lane, input_bits * 2,
                               left_values[lane] * right_values[lane]);
    }
}

static void up_rec_vector_unsigned_shift_long(up_rec_state *state, int destination,
                                              int source, int lanes, int input_bits,
                                              int amount, bool high) {
    int start = high ? lanes : 0;
    uint64_t values[16];
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_lane(state, source, start + lane, input_bits, &values[lane]);
    }
    up_rec_vector_clear(state, destination);
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_set_lane(state, destination, lane, input_bits * 2,
                               values[lane] << (unsigned)amount);
    }
}

static void up_rec_vector_shift_right_narrow(up_rec_state *state, int destination,
                                             int source, int lanes, int output_bits,
                                             int amount) {
    uint64_t values[16];
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_lane(state, source, lane, output_bits * 2, &values[lane]);
    }
    up_rec_vector_clear(state, destination);
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_set_lane(state, destination, lane, output_bits,
                               values[lane] >> (unsigned)amount);
    }
}

static void up_rec_vector_unsigned_shift_right(up_rec_state *state, int destination,
                                               int source, int lanes, int bits,
                                               int amount) {
    uint64_t values[16];
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_lane(state, source, lane, bits, &values[lane]);
    }
    up_rec_vector_clear(state, destination);
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_set_lane(state, destination, lane, bits,
                               values[lane] >> (unsigned)amount);
    }
}

static void up_rec_vector_unsigned_shift(up_rec_state *state, int destination, int source,
                                         int shifts, int lanes, int bits) {
    uint64_t values[16];
    uint64_t shift_values[16];
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_lane(state, source, lane, bits, &values[lane]);
        up_rec_vector_lane(state, shifts, lane, bits, &shift_values[lane]);
    }
    up_rec_vector_clear(state, destination);
    for (int lane = 0; lane < lanes; lane++) {
        uint64_t value = values[lane];
        int64_t shift = (int64_t)up_rec_sign_extend_bits(shift_values[lane], bits, 64);
        if (shift >= (int64_t)bits || shift <= -(int64_t)bits) {
            value = 0;
        } else if (shift >= 0) {
            value <<= (unsigned)shift;
        } else {
            value >>= (unsigned)(-shift);
        }
        up_rec_vector_set_lane(state, destination, lane, bits, value);
    }
}

static void up_rec_vector_extract_narrow(up_rec_state *state, int destination, int source,
                                         int lanes, int output_bits) {
    uint64_t values[16];
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_lane(state, source, lane, output_bits * 2, &values[lane]);
    }
    up_rec_vector_clear(state, destination);
    for (int lane = 0; lane < lanes; lane++) {
        up_rec_vector_set_lane(state, destination, lane, output_bits, values[lane]);
    }
}

static void up_rec_vector_unzip_even(up_rec_state *state, int destination, int left,
                                     int right, int lanes, int bits) {
    int half = lanes / 2;
    uint64_t left_values[16];
    uint64_t right_values[16];
    for (int lane = 0; lane < half; lane++) {
        up_rec_vector_lane(state, left, lane * 2, bits, &left_values[lane]);
        up_rec_vector_lane(state, right, lane * 2, bits, &right_values[lane]);
    }
    up_rec_vector_clear(state, destination);
    for (int lane = 0; lane < half; lane++) {
        up_rec_vector_set_lane(state, destination, lane, bits, left_values[lane]);
        up_rec_vector_set_lane(state, destination, half + lane, bits, right_values[lane]);
    }
}

static void up_rec_vector_eor3(up_rec_state *state, int destination, int first,
                               int second, int third) {
    for (int index = 0; index < 16; index++) {
        state->vectors[destination][index] =
            state->vectors[first][index] ^ state->vectors[second][index] ^ state->vectors[third][index];
    }
}

// MARK: - Kernel

bool up_rec_run_kernel(up_rec_state *state, const up_rec_kernel *kernel) {
    uint64_t pc = kernel->start;
    size_t segment = 0;
    size_t hook = 0;
    for (size_t index = 0; index < kernel->instruction_count; index++) {
        if (segment < kernel->segment_count && kernel->segments[segment].index == (uint32_t)index) {
            pc = kernel->segments[segment].address;
            segment++;
        }
        const up_rec_instruction instruction = kernel->instructions[index];
        const int d = (int)instruction.destination;
        const int left = (int)instruction.left;
        const int right = (int)instruction.right;
        uint64_t value = 0;
        bool condition = false;
        switch ((up_rec_opcode)instruction.op) {
        case compactAnd32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] & (uint32_t)state->x[right]);
            break;
        case compactAdd32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] + (uint32_t)state->x[right]);
            break;
        case compactLoadSXTW32:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + up_rec_shift_left(up_rec_sign_extend_32((uint32_t)state->x[right]), (int)instruction.shift, 64),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactXor64:
            state->x[d] = state->x[left] ^ state->x[right];
            break;
        case compactAddLSR64:
            state->x[d] = state->x[left] + up_rec_shift_right(state->x[right], (int)instruction.shift, 64);
            break;
        case compactUMADDL:
            state->x[d] = (uint64_t)(uint32_t)state->x[left] * (uint64_t)(uint32_t)state->x[right] +
                          state->x[instruction.accumulator];
            break;
        case compactLSRV64:
            state->x[d] = up_rec_shift_right(state->x[left], (int)state->x[right], 64);
            break;
        case compactAddUXTW64:
            state->x[d] = state->x[left] + (uint64_t)(uint32_t)state->x[right];
            break;
        case compactAndLSL64:
            state->x[d] = state->x[left] & up_rec_shift_left(state->x[right], (int)instruction.shift, 64);
            break;
        case compactLSLImm64:
            state->x[d] = up_rec_shift_left(state->x[left], (int)instruction.shift, 64);
            break;
        case compactMovImm64Shift:
            state->x[d] = (uint64_t)instruction.immediate << instruction.shift;
            break;
        case compactXorLSL64:
            state->x[d] = state->x[left] ^ up_rec_shift_left(state->x[right], (int)instruction.shift, 64);
            break;
        case compactCSet32LO:
            if (!up_rec_kernel_condition(state, pc, up_rec_condition_lo, &condition)) {
                return false;
            }
            state->x[d] = up_rec_bool_value(condition);
            break;
        case compactOrLSL32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] |
                                     (uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactAndImm32: {
            uint32_t immediate = (uint32_t)instruction.immediate |
                                 (uint32_t)instruction.right << 16 |
                                 (uint32_t)instruction.accumulator << 24;
            state->x[d] = (uint64_t)((uint32_t)state->x[left] & immediate);
            break;
        }
        case compactOrNotLSL32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] |
                                     (uint32_t)(~(uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32)));
            break;
        case compactRORImm32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_rotate_right((uint64_t)(uint32_t)state->x[left], (int)instruction.shift, 32);
            break;
        case compactRORImm64:
            state->x[d] = up_rec_rotate_right(state->x[left], (int)instruction.shift, 64);
            break;
        case compactXorROR64:
            state->x[d] = state->x[left] ^ up_rec_rotate_right(state->x[right], (int)instruction.shift, 64);
            break;
        case compactLoadSXTW8:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + (uint64_t)(int64_t)(int32_t)state->x[right],
                                    1, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint8_t)value;
            break;
        case compactSubLSR64:
            state->x[d] = state->x[left] - (state->x[right] >> instruction.shift);
            break;
        case compactPairLoadVector: {
            uint64_t base = instruction.left == 31 ? state->sp : state->x[left];
            uint64_t address = up_rec_add_offset(base, (int64_t)(int16_t)instruction.immediate);
            if (!up_rec_kernel_load_vector(state, pc, d, address, 16)) {
                return false;
            }
            if (!up_rec_kernel_load_vector(state, pc, right, address + 16, 16)) {
                return false;
            }
            break;
        }
        case compactXorROR32:
            state->x[d] = (uint64_t)(uint32_t)((uint32_t)state->x[left] ^
                                               (uint32_t)up_rec_rotate_right((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactOrROR32:
            state->x[d] = (uint64_t)(uint32_t)((uint32_t)state->x[left] |
                                               (uint32_t)up_rec_rotate_right((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactCSELZeroEq32:
            state->x[d] = state->z ? 0 : (uint64_t)(uint32_t)state->x[right];
            break;
        case compactCSet32EQ:
            state->x[d] = up_rec_bool_value(state->z);
            break;
        case compactLoadBase64:
            if (!up_rec_kernel_load(state, pc, state->x[left], 8, &value)) {
                return false;
            }
            state->x[d] = value;
            break;
        case compactLoadPostIndex8:
            if (!up_rec_kernel_load(state, pc, state->x[left], 1, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            state->x[left] += (uint64_t)instruction.immediate;
            break;
        case compactLSLReg32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[left], (int)state->x[right], 32);
            break;
        case compactStoreBase64:
            if (!up_rec_kernel_store_value(state, pc, state->x[left],
                                           instruction.destination < 31 ? state->x[d] : 0, 8)) {
                return false;
            }
            break;
        case compactCMNImm32:
            (void)up_rec_add_with_carry(state, (uint64_t)(uint32_t)state->x[left],
                                        (uint64_t)(uint32_t)instruction.immediate, false, 32);
            break;
        case compactOr64:
            state->x[d] = state->x[left] | state->x[right];
            break;
        case compactMovImm64Repeat16:
            value = (uint64_t)instruction.immediate;
            state->x[d] = value | value << 16 | value << 32 | value << 48;
            break;
        case compactAddLSL64:
            state->x[d] = state->x[left] + up_rec_shift_left(state->x[right], (int)instruction.shift, 64);
            break;
        case compactLoadBaseImm64:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], (int64_t)instruction.immediate),
                                    8, &value)) {
                return false;
            }
            state->x[d] = value;
            break;
        case compactAddImm64:
            state->x[d] = state->x[left] + (uint64_t)instruction.immediate;
            break;
        case compactLoadBase32:
            if (!up_rec_kernel_load(state, pc, state->x[left], 4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactStoreSP64:
            if (!up_rec_kernel_store_value(state, pc, up_rec_add_offset(state->sp, (int64_t)instruction.immediate),
                                           instruction.left < 31 ? state->x[left] : 0, 8)) {
                return false;
            }
            break;
        case compactMovNegImm64:
            state->x[d] = (uint64_t)0 - (uint64_t)instruction.immediate;
            break;
        case compactCmp64:
            up_rec_compare_64(state, state->x[left], state->x[right]);
            break;
        case compactSubImm64:
            state->x[d] = state->x[left] - (uint64_t)instruction.immediate;
            break;
        case compactStoreXIndex8:
            if (!up_rec_kernel_store_value(state, pc, state->x[left] + state->x[right],
                                           instruction.destination < 31 ? (uint64_t)(uint8_t)state->x[d] : 0, 1)) {
                return false;
            }
            break;
        case compactCmpImm64:
            up_rec_compare_64(state, state->x[left], (uint64_t)instruction.immediate);
            break;
        case compactOrImm64:
            state->x[d] = state->x[left] | (uint64_t)instruction.immediate;
            break;
        case compactXorImm64:
            state->x[d] = state->x[left] ^ (uint64_t)instruction.immediate;
            break;
        case compactStoreUXTW32:
            if (!up_rec_kernel_store_value(state, pc,
                                           state->x[left] + up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 64),
                                           (uint64_t)(uint32_t)state->x[d], 4)) {
                return false;
            }
            break;
        case compactNoop:
            break;
        case compactMovImm48:
            state->x[d] = (uint64_t)instruction.immediate |
                          (uint64_t)instruction.left << 16 |
                          (uint64_t)instruction.right << 24 |
                          (uint64_t)instruction.accumulator << 32 |
                          (uint64_t)instruction.shift << 40;
            break;
        case compactAddSPImm:
            state->sp += up_rec_shift_left((uint64_t)instruction.immediate, (int)instruction.shift, 64);
            break;
        case compactSubSPImm:
            state->sp -= up_rec_shift_left((uint64_t)instruction.immediate, (int)instruction.shift, 64);
            break;
        case compactLoadSignedOffset32:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactLoadSignedOffset64:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                    8, &value)) {
                return false;
            }
            state->x[d] = value;
            break;
        case compactStoreSignedOffset32:
            if (!up_rec_kernel_store_value(state, pc,
                                           up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                           instruction.destination < 31 ? (uint64_t)(uint32_t)state->x[d] : 0, 4)) {
                return false;
            }
            break;
        case compactStoreSignedOffset64:
            if (!up_rec_kernel_store_value(state, pc,
                                           up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                           instruction.destination < 31 ? state->x[d] : 0, 8)) {
                return false;
            }
            break;
        case compactLoadSignedOffset8:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                    1, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint8_t)value;
            break;
        case compactLoadSignedByte32:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                    1, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)(int32_t)(int8_t)value;
            break;
        case compactStoreSignedOffset8:
            if (!up_rec_kernel_store_value(state, pc,
                                           up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                           (uint64_t)(uint8_t)state->x[d], 1)) {
                return false;
            }
            break;
        case compactBic32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] &
                                     ~(uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactBic64:
            state->x[d] = state->x[left] & ~up_rec_shift_left(state->x[right], (int)instruction.shift, 64);
            break;
        case compactSXT8To32:
            state->x[d] = (uint64_t)(uint32_t)(int32_t)(int8_t)state->x[left];
            break;
        case compactSXT32To64:
            state->x[d] = (uint64_t)(int64_t)(int32_t)state->x[left];
            break;
        case compactNeg32:
            state->x[d] = (uint64_t)(uint32_t)(UINT32_C(0) - (uint32_t)state->x[left]);
            break;
        case compactNeg64:
            state->x[d] = UINT64_C(0) - state->x[left];
            break;
        case compactTst32:
            up_rec_test_32(state, (uint32_t)state->x[left] & (uint32_t)state->x[right]);
            break;
        case compactTstImm32: {
            uint32_t immediate = (uint32_t)instruction.immediate |
                                 (uint32_t)instruction.right << 16 |
                                 (uint32_t)instruction.accumulator << 24;
            up_rec_test_32(state, (uint32_t)state->x[left] & immediate);
            break;
        }
        case compactCSet32:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            state->x[d] = up_rec_bool_value(condition);
            break;
        case compactCSEL32:
        case compactCSEL64:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            value = instruction.right < 31 ? state->x[right] : 0;
            if (condition) {
                value = instruction.left < 31 ? state->x[left] : 0;
            }
            if ((up_rec_opcode)instruction.op == compactCSEL32) {
                value = (uint64_t)(uint32_t)value;
            }
            state->x[d] = value;
            break;
        case compactCInc32:
        case compactCInc64:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            value = state->x[left];
            if (condition) {
                value++;
            }
            if ((up_rec_opcode)instruction.op == compactCInc32) {
                value = (uint64_t)(uint32_t)value;
            }
            state->x[d] = value;
            break;
        case compactCNeg32:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            value = (uint64_t)(uint32_t)state->x[left];
            if (condition) {
                value = (uint64_t)(UINT32_C(0) - (uint32_t)value);
            }
            state->x[d] = value;
            break;
        case compactLoadHalf32:
        case compactLoadSignedOffsetHalf32: {
            int64_t offset = (up_rec_opcode)instruction.op == compactLoadSignedOffsetHalf32
                                 ? (int64_t)(int16_t)instruction.immediate
                                 : 0;
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], offset), 2, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        }
        case compactStoreHalf32:
        case compactStoreSignedOffsetHalf32: {
            int64_t offset = (up_rec_opcode)instruction.op == compactStoreSignedOffsetHalf32
                                 ? (int64_t)(int16_t)instruction.immediate
                                 : 0;
            if (!up_rec_kernel_store_value(state, pc, up_rec_add_offset(state->x[left], offset),
                                           instruction.destination < 31 ? (uint64_t)(uint16_t)state->x[d] : 0, 2)) {
                return false;
            }
            break;
        }
        case compactPairLoad32:
        case compactPairLoad64:
        case compactPairStore32:
        case compactPairStore64: {
            uint64_t base = instruction.left == 31 ? state->sp : state->x[left];
            int64_t offset = (int64_t)(int16_t)instruction.immediate;
            uint64_t address = base;
            if (instruction.accumulator == 0) {
                address = up_rec_add_offset(base, offset);
            }
            if (instruction.accumulator == 1) {
                base = up_rec_add_offset(base, offset);
                address = base;
                if (instruction.left == 31) {
                    state->sp = base;
                } else {
                    state->x[left] = base;
                }
            }
            int width = ((up_rec_opcode)instruction.op == compactPairLoad32 ||
                         (up_rec_opcode)instruction.op == compactPairStore32)
                            ? 4
                            : 8;
            if ((up_rec_opcode)instruction.op == compactPairLoad32 ||
                (up_rec_opcode)instruction.op == compactPairLoad64) {
                uint64_t first = 0;
                uint64_t second = 0;
                if (!up_rec_kernel_load(state, pc, address, width, &first)) {
                    return false;
                }
                if (!up_rec_kernel_load(state, pc, address + (uint64_t)width, width, &second)) {
                    return false;
                }
                if (instruction.destination < 31) {
                    state->x[d] = first;
                }
                if (instruction.right < 31) {
                    state->x[right] = second;
                }
            } else {
                uint64_t first = instruction.destination < 31 ? state->x[d] : 0;
                uint64_t second = instruction.right < 31 ? state->x[right] : 0;
                if (width == 4) {
                    first = (uint64_t)(uint32_t)first;
                    second = (uint64_t)(uint32_t)second;
                }
                if (!up_rec_kernel_store_value(state, pc, address, first, width)) {
                    return false;
                }
                if (!up_rec_kernel_store_value(state, pc, address + (uint64_t)width, second, width)) {
                    return false;
                }
            }
            if (instruction.accumulator == 2) {
                base = up_rec_add_offset(base, offset);
                if (instruction.left == 31) {
                    state->sp = base;
                } else {
                    state->x[left] = base;
                }
            }
            break;
        }
        case compactLoadBaseImm8:
        case compactLoadSPImm8: {
            uint64_t base = (up_rec_opcode)instruction.op == compactLoadSPImm8 ? state->sp : state->x[left];
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(base, (int64_t)instruction.immediate), 1, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint8_t)value;
            break;
        }
        case compactLoadXIndex8:
        case compactLoadXIndex32:
        case compactLoadXIndex64: {
            int width = 1;
            if ((up_rec_opcode)instruction.op == compactLoadXIndex32) {
                width = 4;
            } else if ((up_rec_opcode)instruction.op == compactLoadXIndex64) {
                width = 8;
            }
            if (!up_rec_kernel_load(state, pc, state->x[left] + state->x[right], width, &value)) {
                return false;
            }
            if (width == 4) {
                value = (uint64_t)(uint32_t)value;
            }
            state->x[d] = value;
            break;
        }
        case compactStoreBaseImm8:
        case compactStoreSPImm8: {
            uint64_t base = (up_rec_opcode)instruction.op == compactStoreSPImm8 ? state->sp : state->x[left];
            if (!up_rec_kernel_store_value(state, pc, up_rec_add_offset(base, (int64_t)instruction.immediate),
                                           instruction.destination < 31 ? (uint64_t)(uint8_t)state->x[d] : 0, 1)) {
                return false;
            }
            break;
        }
        case compactStoreXIndex32:
        case compactStoreXIndex64: {
            int width = (up_rec_opcode)instruction.op == compactStoreXIndex32 ? 4 : 8;
            value = instruction.destination < 31 ? state->x[d] : 0;
            if (width == 4) {
                value = (uint64_t)(uint32_t)value;
            }
            if (!up_rec_kernel_store_value(state, pc, state->x[left] + state->x[right], value, width)) {
                return false;
            }
            break;
        }
        case compactLoadUXTW64:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 64),
                                    8, &value)) {
                return false;
            }
            state->x[d] = value;
            break;
        case compactStoreBaseImm64:
            if (!up_rec_kernel_store_value(state, pc, up_rec_add_offset(state->x[left], (int64_t)instruction.immediate),
                                           instruction.destination < 31 ? state->x[d] : 0, 8)) {
                return false;
            }
            break;
        case compactAddExt32:
        case compactAddExt64: {
            uint64_t extended = (uint64_t)(uint8_t)state->x[right];
            if (instruction.accumulator == 1) {
                extended = (uint64_t)(uint32_t)state->x[right];
            } else if (instruction.accumulator == 2) {
                extended = (uint64_t)(int64_t)(int32_t)state->x[right];
            } else if (instruction.accumulator == 3) {
                extended = (uint64_t)(uint16_t)state->x[right];
            }
            value = state->x[left] + up_rec_shift_left(extended, (int)instruction.shift, 64);
            if ((up_rec_opcode)instruction.op == compactAddExt32) {
                value = (uint64_t)(uint32_t)value;
            }
            state->x[d] = value;
            break;
        }
        case compactMovSP:
            state->sp = state->x[left];
            break;
        case compactSubSPFromX:
            state->sp = state->x[left] - up_rec_shift_left((uint64_t)instruction.immediate, (int)instruction.shift, 64);
            break;
        case compactOrImm32: {
            uint32_t immediate = (uint32_t)instruction.immediate |
                                 (uint32_t)instruction.right << 16 |
                                 (uint32_t)instruction.accumulator << 24;
            state->x[d] = (uint64_t)((uint32_t)state->x[left] | immediate);
            break;
        }
        case compactOrLSL64:
            state->x[d] = state->x[left] | up_rec_shift_left(state->x[right], (int)instruction.shift, 64);
            break;
        case compactAndLSR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] &
                                     (uint32_t)up_rec_shift_right(state->x[right], (int)instruction.shift, 32));
            break;
        case compactCmpExtByte32: {
            uint32_t right_value = (uint32_t)(uint8_t)state->x[right];
            if (instruction.shift != 0) {
                right_value = (uint32_t)(int32_t)(int8_t)state->x[right];
            }
            up_rec_compare_32(state, (uint32_t)state->x[left], right_value);
            break;
        }
        case compactCmpLSR32:
            up_rec_compare_32(state, (uint32_t)state->x[left],
                              (uint32_t)up_rec_shift_right(state->x[right], (int)instruction.shift, 32));
            break;
        case compactCCmpReg32:
        case compactCCmpReg64:
        case compactCCmpImm32:
        case compactCCmpImm64:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            if (!condition) {
                up_rec_set_nzcv(state, (int)instruction.accumulator);
                break;
            }
            value = ((up_rec_opcode)instruction.op == compactCCmpImm32 ||
                     (up_rec_opcode)instruction.op == compactCCmpImm64)
                        ? (uint64_t)instruction.immediate
                        : state->x[right];
            if ((up_rec_opcode)instruction.op == compactCCmpReg32 ||
                (up_rec_opcode)instruction.op == compactCCmpImm32) {
                up_rec_compare_32(state, (uint32_t)state->x[left], (uint32_t)value);
            } else {
                up_rec_compare_64(state, state->x[left], value);
            }
            break;
        case compactAdds32:
            state->x[d] = up_rec_add_with_carry(state, (uint64_t)(uint32_t)state->x[left],
                                                (uint64_t)(uint32_t)state->x[right], false, 32);
            break;
        case compactSubs32:
            state->x[d] = up_rec_subtract_with_flags(state, (uint64_t)(uint32_t)state->x[left],
                                                     (uint64_t)(uint32_t)state->x[right], 32);
            break;
        case compactSubs64:
            state->x[d] = up_rec_subtract_with_flags(state, state->x[left], state->x[right], 64);
            break;
        case compactSubsImm32:
            state->x[d] = up_rec_subtract_with_flags(state, (uint64_t)(uint32_t)state->x[left],
                                                     (uint64_t)instruction.immediate, 32);
            break;
        case compactSubsImm64:
            state->x[d] = up_rec_subtract_with_flags(state, state->x[left],
                                                     (uint64_t)instruction.immediate, 64);
            break;
        case compactSMull32:
            state->x[d] = (uint64_t)((int64_t)(int32_t)state->x[left] * (int64_t)(int32_t)state->x[right]);
            break;
        case compactUBFIZ32:
        case compactUBFIZ64: {
            int width = (up_rec_opcode)instruction.op == compactUBFIZ32 ? 32 : 64;
            state->x[d] = up_rec_shift_left(state->x[left] & up_rec_bit_mask((int)instruction.immediate, width),
                                            (int)instruction.shift, width);
            break;
        }
        case compactUBFX32:
        case compactUBFX64: {
            int width = (up_rec_opcode)instruction.op == compactUBFX32 ? 32 : 64;
            state->x[d] = up_rec_shift_right(state->x[left], (int)instruction.shift, width) &
                          up_rec_bit_mask((int)instruction.immediate, width);
            break;
        }
        case compactBFI32:
            state->x[d] = up_rec_insert_bits((uint64_t)(uint32_t)state->x[d], (uint64_t)(uint32_t)state->x[left],
                                             (int)instruction.shift, (int)instruction.immediate, 32);
            break;
        case compactBFXIL32:
            state->x[d] = up_rec_insert_bits((uint64_t)(uint32_t)state->x[d],
                                             up_rec_shift_right(state->x[left], (int)instruction.shift, 32),
                                             0, (int)instruction.immediate, 32);
            break;
        case compactOrNotShift32:
        case compactOrNotShift64: {
            int width = (up_rec_opcode)instruction.op == compactOrNotShift32 ? 32 : 64;
            uint64_t shifted = up_rec_shift_left(state->x[right], (int)instruction.shift, width);
            if (instruction.accumulator == 1) {
                shifted = up_rec_shift_right(state->x[right], (int)instruction.shift, width);
            }
            value = state->x[left] | ~shifted;
            if (width == 32) {
                value = (uint64_t)(uint32_t)value;
            }
            state->x[d] = value;
            break;
        }
        case compactNot64:
            state->x[d] = ~state->x[left];
            break;
        case compactLSLReg64:
            state->x[d] = up_rec_shift_left(state->x[left], (int)state->x[right], 64);
            break;
        case compactLSRReg64:
            state->x[d] = up_rec_shift_right(state->x[left], (int)state->x[right], 64);
            break;
        case compactAndImm64:
            state->x[d] = state->x[left] & (uint64_t)instruction.immediate;
            break;
        case compactAndImmShift64:
            state->x[d] = state->x[left] & ((uint64_t)instruction.immediate << instruction.shift);
            break;
        case compactXorNotImm16Shift64:
            state->x[d] = state->x[left] ^ ~((uint64_t)instruction.immediate << instruction.shift);
            break;
        case compactAddImmShift64:
            state->x[d] = state->x[left] + up_rec_shift_left((uint64_t)instruction.immediate, (int)instruction.shift, 64);
            break;
        case compactSubImmShift64:
            state->x[d] = state->x[left] - up_rec_shift_left((uint64_t)instruction.immediate, (int)instruction.shift, 64);
            break;
        case compactMovFromSP:
            state->x[d] = state->sp;
            break;
        case compactAddLSR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] +
                                     (uint32_t)up_rec_shift_right(state->x[right], (int)instruction.shift, 32));
            break;
        case compactSubLSL64:
            state->x[d] = state->x[left] - up_rec_shift_left(state->x[right], (int)instruction.shift, 64);
            break;
        case compactSubExt32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] - (uint32_t)(uint8_t)state->x[right]);
            break;
        case compactLoadXIndexShift32:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + up_rec_shift_left(state->x[right], (int)instruction.shift, 64),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactStoreXIndexShift32:
            if (!up_rec_kernel_store_value(state, pc,
                                           state->x[left] + up_rec_shift_left(state->x[right], (int)instruction.shift, 64),
                                           (uint64_t)(uint32_t)state->x[d], 4)) {
                return false;
            }
            break;
        case compactLoadPreIndex32:
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            if (!up_rec_kernel_load(state, pc, state->x[left], 4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactStorePreIndex64:
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            if (!up_rec_kernel_store_value(state, pc, state->x[left],
                                           instruction.destination < 31 ? state->x[d] : 0, 8)) {
                return false;
            }
            break;
        case compactLoadSignedWord64:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(int64_t)(int32_t)value;
            break;
        case compactAnds32:
            value = (uint64_t)((uint32_t)state->x[left] & (uint32_t)state->x[right]);
            state->x[d] = value;
            up_rec_test_32(state, (uint32_t)value);
            break;
        case compactBics32:
            value = (uint64_t)((uint32_t)state->x[left] & ~(uint32_t)state->x[right]);
            if (instruction.destination < 31) {
                state->x[d] = value;
            }
            up_rec_test_32(state, (uint32_t)value);
            break;
        case compactCCmnImm32:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            if (condition) {
                (void)up_rec_add_with_carry(state, (uint64_t)(uint32_t)state->x[left],
                                            (uint64_t)instruction.immediate, false, 32);
            } else {
                up_rec_set_nzcv(state, (int)instruction.accumulator);
            }
            break;
        case compactCLZ32:
            state->x[d] = up_rec_leading_zeros((uint32_t)state->x[left], 32);
            break;
        case compactCMNImm64:
            (void)up_rec_add_with_carry(state, state->x[left], (uint64_t)instruction.immediate, false, 64);
            break;
        case compactMovNegImm48: {
            uint64_t magnitude = (uint64_t)instruction.immediate |
                                 (uint64_t)instruction.left << 16 |
                                 (uint64_t)instruction.right << 24 |
                                 (uint64_t)instruction.accumulator << 32 |
                                 (uint64_t)instruction.shift << 40;
            state->x[d] = UINT64_C(0) - magnitude;
            break;
        }
        case compactMovNegImm16Shift64:
            state->x[d] = UINT64_C(0) - ((uint64_t)instruction.immediate << instruction.shift);
            break;
        case compactMovNegRepeat16PlusOne: {
            uint64_t repeated = (uint64_t)instruction.immediate;
            uint64_t magnitude = repeated | repeated << 16 | repeated << 32 | repeated << 48;
            state->x[d] = UINT64_C(0) - (magnitude + 1);
            break;
        }
        case compactAndNotImm16Shift64:
            state->x[d] = state->x[left] & ~((uint64_t)instruction.immediate << instruction.shift);
            break;
        case compactCASAL32:
            if (!up_rec_kernel_load(state, pc, state->x[instruction.accumulator], 4, &value)) {
                return false;
            }
            if ((uint32_t)value == (uint32_t)state->x[left]) {
                if (!up_rec_kernel_store_value(state, pc, state->x[instruction.accumulator],
                                               (uint64_t)(uint32_t)state->x[right], 4)) {
                    return false;
                }
            }
            state->x[left] = (uint64_t)(uint32_t)value;
            break;
        case compactStorePostIndex32:
            if (!up_rec_kernel_store_value(state, pc, state->x[left], (uint64_t)(uint32_t)state->x[d], 4)) {
                return false;
            }
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            break;
        case compactStorePostIndex64:
            if (!up_rec_kernel_store_value(state, pc, state->x[left], state->x[d], 8)) {
                return false;
            }
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            break;
        case compactMovMaxInt:
            state->x[d] = UINT64_C(0x7fffffffffffffff);
            break;
        case compactLoadPreIndex64:
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            if (!up_rec_kernel_load(state, pc, state->x[left], 8, &value)) {
                return false;
            }
            state->x[d] = value;
            break;
        case compactXorSelectionMask64:
            state->x[d] = state->x[left] ^ UINT64_C(0x3ffffffffffffff0);
            break;
        case compactSXT16To32:
            state->x[d] = (uint64_t)(uint32_t)(int32_t)(int16_t)state->x[left];
            break;
        case compactStoreHalfPostIndex32:
            if (!up_rec_kernel_store_value(state, pc, state->x[left],
                                           (uint64_t)(uint16_t)state->x[d], 2)) {
                return false;
            }
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            break;
        case compactSubUXTH32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] - (uint32_t)(uint16_t)state->x[right]);
            break;
        case compactUDiv64:
            state->x[d] = up_rec_unsigned_divide(state->x[left], state->x[right], 64);
            break;
        case compactLoadHalfXIndexShift32:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + up_rec_shift_left(state->x[right], (int)instruction.shift, 64),
                                    2, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint16_t)value;
            break;
        case compactStorePreIndex32:
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            if (!up_rec_kernel_store_value(state, pc, state->x[left],
                                           (uint64_t)(uint32_t)state->x[d], 4)) {
                return false;
            }
            break;
        case compactAddASR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] +
                                     (uint32_t)up_rec_shift_right_arithmetic(state->x[right], (int)instruction.shift, 32));
            break;
        case compactAddUXTH64:
            state->x[d] = state->x[left] + (uint64_t)(uint16_t)state->x[right];
            break;
        case compactXorLSR64:
            state->x[d] = state->x[left] ^ up_rec_shift_right(state->x[right], (int)instruction.shift, 64);
            break;
        case compactXorImm16Shift64:
            state->x[d] = state->x[left] ^ (uint64_t)instruction.immediate << instruction.shift;
            break;
        case compactLoadSignedWordBase64: {
            uint64_t base = instruction.left == 31 ? state->sp : state->x[left];
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(base, (int64_t)(int16_t)instruction.immediate),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(int64_t)(int32_t)value;
            break;
        }
        case compactLoadHalfXIndex32:
            if (!up_rec_kernel_load(state, pc, state->x[left] + state->x[right], 2, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint16_t)value;
            break;
        case compactLoadSPHalf32:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->sp, (int64_t)instruction.immediate),
                                    2, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint16_t)value;
            break;
        case compactMNeg32:
            state->x[d] = (uint64_t)(uint32_t)(UINT32_C(0) - (uint32_t)state->x[left] * (uint32_t)state->x[right]);
            break;
        case compactMNeg64:
            state->x[d] = UINT64_C(0) - state->x[left] * state->x[right];
            break;
        case compactMSub64:
            state->x[d] = state->x[instruction.accumulator] - state->x[left] * state->x[right];
            break;
        case compactSBFIZ64:
            state->x[d] = up_rec_shift_left(up_rec_sign_extend_bits(state->x[left], (int)instruction.immediate, 64),
                                            (int)instruction.shift, 64);
            break;
        case compactStoreUXTW64:
            if (!up_rec_kernel_store_value(state, pc,
                                           state->x[left] + up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 64),
                                           instruction.destination < 31 ? state->x[d] : 0, 8)) {
                return false;
            }
            break;
        case compactStorePostIndex8:
            if (!up_rec_kernel_store_value(state, pc, state->x[left],
                                           instruction.destination < 31 ? (uint64_t)(uint8_t)state->x[d] : 0, 1)) {
                return false;
            }
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            break;
        case compactVectorDup32:
            up_rec_vector_dup(state, d, (int)instruction.immediate, 32, (uint64_t)(uint32_t)state->x[left]);
            break;
        case compactLoadVector: {
            uint64_t base = instruction.left == 31 ? state->sp : state->x[left];
            if (!up_rec_kernel_load_vector(state, pc, d,
                                           up_rec_add_offset(base, (int64_t)instruction.immediate),
                                           (int)instruction.accumulator)) {
                return false;
            }
            break;
        }
        case compactASRImm32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_shift_right_arithmetic(state->x[left], (int)instruction.shift, 32);
            break;
        case compactAndsLSR32:
            value = (uint64_t)((uint32_t)state->x[left] &
                               (uint32_t)up_rec_shift_right(state->x[right], (int)instruction.shift, 32));
            state->x[d] = value;
            up_rec_test_32(state, (uint32_t)value);
            break;
        case compactBicsLSR32:
            value = (uint64_t)((uint32_t)state->x[left] &
                               ~(uint32_t)up_rec_shift_right(state->x[right], (int)instruction.shift, 32));
            if (instruction.destination < 31) {
                state->x[d] = value;
            }
            up_rec_test_32(state, (uint32_t)value);
            break;
        case compactCCmnImm64:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            if (condition) {
                (void)up_rec_add_with_carry(state, state->x[left], (uint64_t)instruction.immediate, false, 64);
            } else {
                up_rec_set_nzcv(state, (int)instruction.accumulator);
            }
            break;
        case compactCSInc32:
            if (!up_rec_kernel_condition(state, pc, instruction.shift, &condition)) {
                return false;
            }
            if (condition) {
                state->x[d] = (uint64_t)(uint32_t)state->x[left];
            } else {
                value = instruction.right < 31 ? (uint64_t)(uint32_t)state->x[right] : 0;
                state->x[d] = (uint64_t)(uint32_t)(value + 1);
            }
            break;
        case compactTstImm64:
            up_rec_test_64(state, state->x[left] & (uint64_t)instruction.immediate);
            break;
        case compactEon32:
            state->x[d] = (uint64_t)(uint32_t)((uint32_t)state->x[left] ^ ~(uint32_t)state->x[right]);
            break;
        case compactVectorImmediate:
            up_rec_vector_clear(state, d);
            value = (uint64_t)instruction.immediate << instruction.shift;
            for (int lane = 0; lane < (int)instruction.right; lane++) {
                up_rec_vector_set_lane(state, d, lane, (int)instruction.left, value);
            }
            break;
        case compactVectorBinary:
            if (instruction.accumulator > 3) {
                snprintf(state->detail, sizeof(state->detail), "invalid vector binary encoding");
                return false;
            }
            up_rec_vector_binary(state, (int)instruction.accumulator, d, left, right,
                                 (int)instruction.immediate, (int)instruction.shift);
            break;
        case compactVectorMAC:
            up_rec_vector_multiply_accumulate(state, d, left, right,
                                              (int)instruction.immediate, (int)instruction.shift,
                                              instruction.accumulator != 0);
            break;
        case compactVectorUnsignedShiftLong:
            up_rec_vector_unsigned_shift_long(state, d, left,
                                              (int)(uint8_t)instruction.immediate,
                                              (int)(uint8_t)(instruction.immediate >> 8),
                                              (int)instruction.shift, instruction.accumulator != 0);
            break;
        case compactVectorMove64: {
            uint64_t lane_value = 0;
            up_rec_vector_lane(state, left, 0, 64, &lane_value);
            up_rec_vector_clear(state, d);
            up_rec_vector_set_lane(state, d, 0, 64, lane_value);
            break;
        }
        case compactStoreVector: {
            uint64_t base = instruction.left == 31 ? state->sp : state->x[left];
            if (!up_rec_kernel_store_vector(state, pc, d,
                                            up_rec_add_offset(base, (int64_t)(int16_t)instruction.immediate),
                                            (int)instruction.accumulator)) {
                return false;
            }
            break;
        }
        case compactVectorUnsignedMultiplyLong:
            up_rec_vector_unsigned_multiply_long(state, d, left, right,
                                                 (int)instruction.immediate, (int)instruction.shift,
                                                 instruction.accumulator != 0);
            break;
        case compactVectorEor3:
            up_rec_vector_eor3(state, d, left, right, (int)instruction.accumulator);
            break;
        case compactPairStoreVector: {
            uint64_t address = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            if (!up_rec_kernel_store_vector(state, pc, d, address, 16)) {
                return false;
            }
            if (!up_rec_kernel_store_vector(state, pc, right, address + 16, 16)) {
                return false;
            }
            break;
        }
        case compactVectorTable1: {
            const int tables[1] = {left};
            if (!up_rec_vector_table(state, pc, d, tables, 1, right)) {
                return false;
            }
            break;
        }
        case compactVectorTable4: {
            const int tables[4] = {left, left + 1, left + 2, left + 3};
            if (!up_rec_vector_table(state, pc, d, tables, 4, right)) {
                return false;
            }
            break;
        }
        case compactVectorExtractNarrow:
            up_rec_vector_extract_narrow(state, d, left,
                                         (int)instruction.immediate, (int)instruction.shift);
            break;
        case compactVectorShiftRightNarrow:
            up_rec_vector_shift_right_narrow(state, d, left, (int)instruction.immediate,
                                             (int)instruction.accumulator, (int)instruction.shift);
            break;
        case compactVectorUnzipEven:
            up_rec_vector_unzip_even(state, d, left, right,
                                     (int)instruction.immediate, (int)instruction.shift);
            break;
        case compactVectorNegateFloat64: {
            uint64_t lane_value = 0;
            up_rec_vector_lane(state, left, 0, 64, &lane_value);
            lane_value ^= UINT64_C(1) << 63;
            up_rec_vector_clear(state, d);
            up_rec_vector_set_lane(state, d, 0, 64, lane_value);
            break;
        }
        case compactVectorUnsignedShiftRight:
            up_rec_vector_unsigned_shift_right(state, d, left, (int)instruction.immediate,
                                               (int)instruction.accumulator, (int)instruction.shift);
            break;
        case compactVectorToW: {
            uint64_t lane_value = 0;
            up_rec_vector_lane(state, left, (int)instruction.immediate, 32, &lane_value);
            state->x[d] = (uint64_t)(uint32_t)lane_value;
            break;
        }
        case compactVectorUnsignedShift:
            up_rec_vector_unsigned_shift(state, d, left, right,
                                         (int)instruction.immediate, (int)instruction.shift);
            break;
        case compactVectorMove128:
            memcpy(state->vectors[d], state->vectors[left], sizeof(state->vectors[d]));
            break;
        case compactWToVectorLane:
            up_rec_vector_set_lane(state, d, (int)instruction.immediate, 32,
                                   (uint64_t)(uint32_t)state->x[left]);
            break;
        case compactAndsImm32: {
            uint32_t immediate = (uint32_t)instruction.immediate |
                                 (uint32_t)instruction.right << 16 |
                                 (uint32_t)instruction.accumulator << 24;
            value = (uint64_t)((uint32_t)state->x[left] & immediate);
            state->x[d] = value;
            up_rec_test_32(state, (uint32_t)value);
            break;
        }
        case compactASRReg32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_shift_right_arithmetic(state->x[left], (int)state->x[right], 32);
            break;
        case compactASRImm64:
            state->x[d] = up_rec_shift_right_arithmetic(state->x[left], (int)instruction.shift, 64);
            break;
        case compactBFI64:
            state->x[d] = up_rec_insert_bits(state->x[d], state->x[left],
                                             (int)instruction.shift, (int)instruction.immediate, 64);
            break;
        case compactBicLSR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] &
                                     ~(uint32_t)up_rec_shift_right(state->x[right], (int)instruction.shift, 32));
            break;
        case compactCMNLSL64:
            (void)up_rec_add_with_carry(state, state->x[left],
                                        up_rec_shift_left(state->x[right], (int)instruction.shift, 64), false, 64);
            break;
        case compactCmpUXTH32:
            up_rec_compare_32(state, (uint32_t)state->x[left], (uint32_t)(uint16_t)state->x[right]);
            break;
        case compactEon64:
            state->x[d] = state->x[left] ^ ~state->x[right];
            break;
        case compactXorASR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] ^
                                     (uint32_t)up_rec_shift_right_arithmetic(state->x[right], (int)instruction.shift, 32));
            break;
        case compactLoadPostIndex32:
        case compactLoadPostIndex64: {
            int width = (up_rec_opcode)instruction.op == compactLoadPostIndex32 ? 4 : 8;
            if (!up_rec_kernel_load(state, pc, state->x[left], width, &value)) {
                return false;
            }
            if (width == 4) {
                value = (uint64_t)(uint32_t)value;
            }
            state->x[d] = value;
            state->x[left] = up_rec_add_offset(state->x[left], (int64_t)(int16_t)instruction.immediate);
            break;
        }
        case compactLoadHalfUXTW32:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 64),
                                    2, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint16_t)value;
            break;
        case compactMovMaxIntMinusOne:
            state->x[d] = UINT64_C(0x7ffffffffffffffe);
            break;
        case compactOrLSR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] |
                                     (uint32_t)up_rec_shift_right(state->x[right], (int)instruction.shift, 32));
            break;
        case compactOrHigh32Imm64:
            state->x[d] = state->x[left] | UINT64_C(0xffffffff00000000);
            break;
        case compactRev32:
            state->x[d] = up_rec_reverse_bytes_32(state->x[left]);
            break;
        case compactSBFIZ32:
            state->x[d] = up_rec_shift_left(up_rec_sign_extend_bits(state->x[left], (int)instruction.immediate, 32),
                                            (int)instruction.shift, 32);
            break;
        case compactSBFX32:
            state->x[d] = up_rec_sign_extend_bits(up_rec_shift_right(state->x[left], (int)instruction.shift, 32),
                                                  (int)instruction.immediate, 32);
            break;
        case compactStoreSPHalf32:
            if (!up_rec_kernel_store_value(state, pc, up_rec_add_offset(state->sp, (int64_t)instruction.immediate),
                                           (uint64_t)(uint16_t)state->x[d], 2)) {
                return false;
            }
            break;
        case compactSubLSR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] -
                                     ((uint32_t)state->x[right] >> instruction.shift));
            break;
        case compactLogicalMask64: {
            int width = (int)instruction.shift;
            if (width < 2 || width > 64 || (width & (width - 1)) != 0 || instruction.immediate == 0 ||
                (int)instruction.immediate >= width || (int)instruction.right >= width ||
                (int)instruction.accumulator > 2) {
                snprintf(state->detail, sizeof(state->detail), "invalid logical-mask encoding");
                return false;
            }
            uint64_t mask = (UINT64_C(1) << instruction.immediate) - 1;
            for (int step = width; step < 64; step *= 2) {
                mask |= mask << step;
            }
            mask = up_rec_rotate_right(mask, (int)instruction.right, 64);
            switch (instruction.accumulator) {
            case 0:
                state->x[d] = state->x[left] & mask;
                break;
            case 1:
                state->x[d] = state->x[left] | mask;
                break;
            default:
                state->x[d] = state->x[left] ^ mask;
                break;
            }
            break;
        }
        case compactTestRegister64:
            up_rec_test_64(state, state->x[left] & state->x[right]);
            break;
        case compactSub64:
            state->x[d] = state->x[left] - state->x[right];
            break;
        case compactAdd64:
            state->x[d] = state->x[left] + state->x[right];
            break;
        case compactXor32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] ^ (uint32_t)state->x[right]);
            break;
        case compactStoreSXTW32:
            if (!up_rec_kernel_store_value(state, pc,
                                           state->x[left] + up_rec_shift_left(up_rec_sign_extend_32((uint32_t)state->x[right]), (int)instruction.shift, 64),
                                           instruction.destination < 31 ? (uint64_t)(uint32_t)state->x[d] : 0, 4)) {
                return false;
            }
            break;
        case compactAddImm32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] + (uint32_t)instruction.immediate);
            break;
        case compactCmp32:
            up_rec_compare_32(state, (uint32_t)state->x[left], (uint32_t)state->x[right]);
            break;
        case compactCCmp32LE:
            if (state->z || state->n != state->v) {
                up_rec_compare_32(state, (uint32_t)state->x[left], (uint32_t)state->x[right]);
            } else {
                up_rec_set_nzcv(state, (int)instruction.immediate);
            }
            break;
        case compactCSet32LT:
            if (!up_rec_kernel_condition(state, pc, up_rec_condition_lt, &condition)) {
                return false;
            }
            state->x[d] = up_rec_bool_value(condition);
            break;
        case compactMul32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] * (uint32_t)state->x[right]);
            break;
        case compactLoadSXTW64:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + up_rec_shift_left(up_rec_sign_extend_32((uint32_t)state->x[right]), (int)instruction.shift, 64),
                                    8, &value)) {
                return false;
            }
            state->x[d] = value;
            break;
        case compactMov64:
            state->x[d] = state->x[left];
            break;
        case compactMovImm64:
            state->x[d] = (uint64_t)instruction.immediate;
            break;
        case compactStoreSP32:
            if (!up_rec_kernel_store_value(state, pc, up_rec_add_offset(state->sp, (int64_t)instruction.immediate),
                                           instruction.left < 31 ? (uint64_t)(uint32_t)state->x[left] : 0, 4)) {
                return false;
            }
            break;
        case compactMovImm32:
            state->x[d] = (uint64_t)(uint32_t)instruction.immediate;
            break;
        case compactMovK32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_insert_bits((uint64_t)(uint32_t)state->x[d],
                                                                 (uint64_t)instruction.immediate,
                                                                 (int)instruction.shift, 16, 32);
            break;
        case compactUDiv32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_unsigned_divide((uint64_t)(uint32_t)state->x[left],
                                                                     (uint64_t)(uint32_t)state->x[right], 32);
            break;
        case compactMSub32:
            state->x[d] = (uint64_t)(uint32_t)((uint32_t)state->x[instruction.accumulator] -
                                               (uint32_t)state->x[left] * (uint32_t)state->x[right]);
            break;
        case compactLoadSP32:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->sp, (int64_t)instruction.immediate),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactUMull32:
            state->x[d] = (uint64_t)(uint32_t)state->x[left] * (uint64_t)(uint32_t)state->x[right];
            break;
        case compactLoadUXTW8:
            if (!up_rec_kernel_load(state, pc, state->x[left] + (uint64_t)(uint32_t)state->x[right], 1, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactLSRImm64:
            state->x[d] = up_rec_shift_right(state->x[left], (int)instruction.shift, 64);
            break;
        case compactMov32:
            state->x[d] = (uint64_t)(uint32_t)state->x[left];
            break;
        case compactOr32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] | (uint32_t)state->x[right]);
            break;
        case compactSub32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] - (uint32_t)state->x[right]);
            break;
        case compactAndLSL32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] &
                                     (uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactAddSPShiftImm64:
            state->x[d] = state->sp + up_rec_shift_left((uint64_t)instruction.immediate, (int)instruction.shift, 64);
            break;
        case compactLoadBaseImm32:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->x[left], (int64_t)instruction.immediate),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactExtract32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_extract_pair((uint64_t)(uint32_t)state->x[left],
                                                                  (uint64_t)(uint32_t)state->x[right],
                                                                  (int)instruction.shift, 32);
            break;
        case compactNot32:
            state->x[d] = (uint64_t)(uint32_t)~state->x[left];
            break;
        case compactLSRImm32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_shift_right((uint64_t)(uint32_t)state->x[left], (int)instruction.shift, 32);
            break;
        case compactLoadSP64:
            if (!up_rec_kernel_load(state, pc, up_rec_add_offset(state->sp, (int64_t)instruction.immediate),
                                    8, &value)) {
                return false;
            }
            state->x[d] = value;
            break;
        case compactMovImm32High:
            state->x[d] = (uint64_t)((uint32_t)instruction.immediate << 16);
            break;
        case compactAddImmShift32:
            state->x[d] = (uint64_t)(uint32_t)((uint32_t)state->x[left] +
                                               ((uint32_t)instruction.immediate << instruction.shift));
            break;
        case compactLSLImm32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[left], (int)instruction.shift, 32);
            break;
        case compactXorLSL32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] ^
                                     (uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactStoreBase32:
            if (!up_rec_kernel_store_value(state, pc, state->x[left],
                                           (uint64_t)(uint32_t)state->x[d], 4)) {
                return false;
            }
            break;
        case compactLoadUXTW32:
            if (!up_rec_kernel_load(state, pc,
                                    state->x[left] + up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 64),
                                    4, &value)) {
                return false;
            }
            state->x[d] = (uint64_t)(uint32_t)value;
            break;
        case compactMovNegOne32:
            state->x[d] = UINT64_C(0xffffffff);
            break;
        case compactMovK64:
            state->x[d] = up_rec_insert_bits(state->x[d], (uint64_t)instruction.immediate,
                                             (int)instruction.shift, 16, 64);
            break;
        case compactAddLSL32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] +
                                     (uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactXorLSR32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] ^
                                     (uint32_t)up_rec_shift_right((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactLSRReg32:
            state->x[d] = (uint64_t)(uint32_t)up_rec_shift_right((uint64_t)(uint32_t)state->x[left], (int)state->x[right], 32);
            break;
        case compactStoreUXTW8:
            if (!up_rec_kernel_store_value(state, pc, state->x[left] + (uint64_t)(uint32_t)state->x[right],
                                           instruction.destination < 31 ? (uint64_t)(uint8_t)state->x[d] : 0, 1)) {
                return false;
            }
            break;
        case compactUMulH64:
            state->x[d] = up_rec_multiply_high_64(state->x[left], state->x[right]);
            break;
        case compactMAdd32:
            state->x[d] = (uint64_t)(uint32_t)((uint32_t)state->x[left] * (uint32_t)state->x[right] +
                                               (uint32_t)state->x[instruction.accumulator]);
            break;
        case compactMAdd64:
            state->x[d] = state->x[left] * state->x[right] + state->x[instruction.accumulator];
            break;
        case compactAdds64:
            state->x[d] = up_rec_add_with_carry(state, state->x[left], state->x[right], false, 64);
            break;
        case compactADC32: {
            uint32_t left_value = instruction.left < 31 ? (uint32_t)state->x[left] : 0;
            uint32_t right_value = instruction.right < 31 ? (uint32_t)state->x[right] : 0;
            state->x[d] = (uint64_t)(left_value + right_value + (state->c ? 1u : 0u));
            break;
        }
        case compactCMN64:
            (void)up_rec_add_with_carry(state, state->x[left], state->x[right], false, 64);
            break;
        case compactCmpImm32:
            up_rec_compare_32(state, (uint32_t)state->x[left], (uint32_t)instruction.immediate);
            break;
        case compactCSet32HI:
            if (!up_rec_kernel_condition(state, pc, up_rec_condition_hi, &condition)) {
                return false;
            }
            state->x[d] = up_rec_bool_value(condition);
            break;
        case compactStoreBaseImm32:
            if (!up_rec_kernel_store_value(state, pc, up_rec_add_offset(state->x[left], (int64_t)instruction.immediate),
                                           instruction.destination < 31 ? (uint64_t)(uint32_t)state->x[d] : 0, 4)) {
                return false;
            }
            break;
        case compactMul64:
            state->x[d] = state->x[left] * state->x[right];
            break;
        case compactSubImmShift32:
            state->x[d] = (uint64_t)(uint32_t)((uint32_t)state->x[left] -
                                               ((uint32_t)instruction.immediate << instruction.shift));
            break;
        case compactXorImm32: {
            uint32_t immediate = (uint32_t)instruction.immediate |
                                 (uint32_t)instruction.right << 16 |
                                 (uint32_t)instruction.accumulator << 24;
            state->x[d] = (uint64_t)((uint32_t)state->x[left] ^ immediate);
            break;
        }
        case compactSubLSL32:
            state->x[d] = (uint64_t)((uint32_t)state->x[left] -
                                     (uint32_t)up_rec_shift_left((uint64_t)(uint32_t)state->x[right], (int)instruction.shift, 32));
            break;
        case compactMovImm32Wide: {
            uint32_t immediate = (uint32_t)instruction.immediate |
                                 (uint32_t)instruction.right << 16 |
                                 (uint32_t)instruction.accumulator << 24;
            state->x[d] = (uint64_t)immediate;
            break;
        }
        case compactAnd64:
            state->x[d] = state->x[left] & state->x[right];
            break;
        default:
            snprintf(state->detail, sizeof(state->detail),
                     "compact kernel %#llx has unknown opcode %d",
                     (unsigned long long)pc, (int)instruction.op);
            return false;
        }
        if (hook < kernel->hook_count && kernel->hooks[hook].after == pc) {
            state->detail[0] = '\0';
            bool hook_ok = false;
            switch (kernel->hooks[hook].action) {
            case up_rec_hook_digest: {
                int iterations = 0;
                hook_ok = up_rec_run_kernel_loop(state, "digest-natural", &iterations);
                break;
            }
            case up_rec_hook_optional:
                hook_ok = state->x[9] != state->profile->optional_start || up_rec_run_optional(state);
                break;
            case up_rec_hook_even: {
                int iterations = 0;
                hook_ok = up_rec_run_kernel_loop(state, "even", &iterations);
                break;
            }
            case up_rec_hook_odd: {
                int iterations = 0;
                hook_ok = up_rec_run_kernel_loop(state, "odd", &iterations);
                break;
            }
            case up_rec_hook_tail: {
                int iterations = 0;
                hook_ok = up_rec_run_kernel_loop(state, "tail", &iterations);
                break;
            }
            case up_rec_hook_writer: {
                int iterations = 0;
                hook_ok = up_rec_run_kernel_loop(state, "writer", &iterations);
                break;
            }
            default:
                snprintf(state->detail, sizeof(state->detail),
                         "unknown compact kernel hook %d", (int)kernel->hooks[hook].action);
                hook_ok = false;
                break;
            }
            if (!hook_ok) {
                char inner[sizeof(state->detail)];
                memcpy(inner, state->detail, sizeof(inner));
                inner[sizeof(inner) - 1] = '\0';
                snprintf(state->detail, sizeof(state->detail),
                         "compact kernel hook after %#llx: %s", (unsigned long long)pc, inner);
                return false;
            }
            hook++;
        }
        pc += 4;
    }
    return true;
}
