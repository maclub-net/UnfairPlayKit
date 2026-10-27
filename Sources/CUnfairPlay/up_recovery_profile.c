//
//  up_recovery_profile.c
//  CUnfairPlay
//
//  Loads the generated recovery assets: the compact CFG profile, the semantic
//  frame profile, and the kernel table emitted by the asset generator. Layouts
//  and validation rules match the Go reference so both implementations reject
//  the same malformed data.
//

#include "up_recovery.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "up_crypto.h"

#define UP_REC_PROFILE_MAGIC "FPCFG1\x00\x00"
#define UP_REC_FRAME_MAGIC "FPFRM1\x00\x00"
#define UP_REC_KERNEL_MAGIC "UPKR1\x00\x00\x00"

static uint16_t read_u16(const uint8_t *bytes) {
    return (uint16_t)(bytes[0] | (uint16_t)bytes[1] << 8);
}

static uint32_t read_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static uint64_t read_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (int index = 7; index >= 0; index--) {
        value = value << 8 | bytes[index];
    }
    return value;
}

// MARK: - gzip

bool up_rec_gunzip(up_context *ctx, const uint8_t *data, size_t length, size_t limit,
                   uint8_t **decoded, size_t *decoded_length) {
    *decoded = NULL;
    *decoded_length = 0;
    if (length == 0) {
        return up_fail(ctx, "empty compressed recovery asset");
    }
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        return up_fail(ctx, "cannot initialize gzip inflation");
    }
    size_t capacity = length * 8;
    if (capacity < 65536) {
        capacity = 65536;
    }
    if (limit != 0 && capacity > limit) {
        capacity = limit;
    }
    uint8_t *buffer = malloc(capacity);
    if (buffer == NULL) {
        inflateEnd(&stream);
        return up_fail(ctx, "out of memory inflating a recovery asset");
    }
    stream.next_in = (Bytef *)(uintptr_t)data;
    stream.avail_in = (uInt)length;
    size_t produced = 0;
    for (;;) {
        if (produced == capacity) {
            size_t grown_capacity = capacity * 2;
            if (limit != 0 && grown_capacity > limit) {
                grown_capacity = limit;
            }
            if (grown_capacity <= capacity) {
                free(buffer);
                inflateEnd(&stream);
                return up_fail(ctx, "recovery asset expands beyond its limit");
            }
            uint8_t *grown = realloc(buffer, grown_capacity);
            if (grown == NULL) {
                free(buffer);
                inflateEnd(&stream);
                return up_fail(ctx, "out of memory inflating a recovery asset");
            }
            buffer = grown;
            capacity = grown_capacity;
        }
        stream.next_out = buffer + produced;
        size_t available = capacity - produced;
        if (available > UINT32_MAX) {
            available = UINT32_MAX;
        }
        stream.avail_out = (uInt)available;
        int status = inflate(&stream, Z_NO_FLUSH);
        produced += available - stream.avail_out;
        if (status == Z_STREAM_END) {
            break;
        }
        if (status != Z_OK && status != Z_BUF_ERROR) {
            free(buffer);
            inflateEnd(&stream);
            return up_fail(ctx, "invalid gzip recovery asset: %s",
                           stream.msg == NULL ? "inflate failed" : stream.msg);
        }
        if (status == Z_BUF_ERROR && stream.avail_in == 0 && stream.avail_out != 0) {
            free(buffer);
            inflateEnd(&stream);
            return up_fail(ctx, "truncated gzip recovery asset");
        }
    }
    inflateEnd(&stream);
    *decoded = buffer;
    *decoded_length = produced;
    return true;
}

// MARK: - Blocks

static void release_blocks(up_rec_blocks *blocks) {
    if (blocks == NULL) {
        return;
    }
    for (size_t index = 0; index < blocks->count; index++) {
        free(blocks->blocks[index].instructions);
    }
    free(blocks->blocks);
    blocks->blocks = NULL;
    blocks->count = 0;
}

const up_rec_block *up_rec_blocks_find(const up_rec_blocks *blocks, uint64_t address) {
    if (blocks == NULL || blocks->count == 0) {
        return NULL;
    }
    size_t low = 0;
    size_t high = blocks->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (blocks->blocks[middle].start < address) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if (low < blocks->count && blocks->blocks[low].start == address) {
        return &blocks->blocks[low];
    }
    return NULL;
}

static bool verify_checksum(up_context *ctx, const uint8_t *payload, size_t length,
                            const uint8_t *checksum, const char *name) {
    uint8_t digest[32];
    up_sha256(payload, length, digest);
    if (memcmp(digest, checksum, 32) != 0) {
        return up_fail(ctx, "%s checksum mismatch", name);
    }
    return true;
}

typedef struct {
    up_rec_blocks **sections;
    size_t section_count;
} section_targets;

bool up_rec_load_compact_profile(up_context *ctx, const uint8_t *data, size_t length,
                                 up_rec_blocks *account_entry, up_rec_blocks *bootstrap,
                                 up_rec_blocks *selection, up_rec_blocks *sinf_entry,
                                 up_rec_blocks *supplemental, up_rec_blocks *extracted) {
    if (length < 32) {
        return up_fail(ctx, "compact profile is truncated");
    }
    size_t payload_length = length - 32;
    if (!verify_checksum(ctx, data, payload_length, data + payload_length, "compact profile")) {
        return false;
    }
    if (payload_length < 16 || memcmp(data, UP_REC_PROFILE_MAGIC, 8) != 0) {
        return up_fail(ctx, "invalid compact profile magic");
    }
    uint32_t version = read_u32(data + 8);
    if (version != 1) {
        return up_fail(ctx, "unsupported compact profile version %u", version);
    }
    uint32_t section_count = read_u32(data + 12);
    if (section_count == 0 || section_count > 255) {
        return up_fail(ctx, "invalid compact profile section count %u", section_count);
    }
    size_t offset = 16;
    bool seen[256] = {false};
    for (uint32_t section_index = 0; section_index < section_count; section_index++) {
        if (payload_length < offset + 16) {
            return up_fail(ctx, "compact profile is truncated");
        }
        uint8_t identifier = data[offset];
        for (int reserved = 0; reserved < 7; reserved++) {
            if (data[offset + 1 + (size_t)reserved] != 0) {
                return up_fail(ctx, "compact profile reserved bytes are nonzero");
            }
        }
        uint32_t block_count = read_u32(data + offset + 8);
        uint32_t reserved = read_u32(data + offset + 12);
        offset += 16;
        if (identifier == 0 || seen[identifier] || block_count == 0 || reserved != 0) {
            return up_fail(ctx, "invalid compact profile section header");
        }
        seen[identifier] = true;
        up_rec_blocks *target = NULL;
        switch (identifier) {
        case 1:
            target = account_entry;
            break;
        case 2:
            target = bootstrap;
            break;
        case 3:
            target = selection;
            break;
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
            target = &sinf_entry[identifier - 4];
            break;
        case 10:
            target = supplemental;
            break;
        case 11:
            target = extracted;
            break;
        default:
            return up_fail(ctx, "unknown compact profile section %u", identifier);
        }
        up_rec_block *blocks = calloc(block_count, sizeof(up_rec_block));
        if (blocks == NULL) {
            return up_fail(ctx, "out of memory loading the compact profile");
        }
        uint64_t previous = 0;
        for (uint32_t block_index = 0; block_index < block_count; block_index++) {
            if (payload_length < offset + 40) {
                free(blocks);
                return up_fail(ctx, "compact profile is truncated");
            }
            uint64_t address = read_u64(data + offset);
            if (address == 0 || (block_index != 0 && address <= previous)) {
                free(blocks);
                return up_fail(ctx, "compact profile block addresses are invalid");
            }
            previous = address;
            const uint8_t *control = data + offset + 8;
            if (control[0] > 8 || control[5] != 0 || control[6] != 0 || control[7] != 0) {
                free(blocks);
                return up_fail(ctx, "compact block %#llx has invalid control data",
                               (unsigned long long)address);
            }
            blocks[block_index].start = address;
            blocks[block_index].terminator = control[0];
            blocks[block_index].condition = control[1];
            blocks[block_index].reg = control[2];
            blocks[block_index].width = control[3];
            blocks[block_index].bit = control[4];
            blocks[block_index].target = read_u64(data + offset + 16);
            blocks[block_index].alternate = read_u64(data + offset + 24);
            uint32_t instruction_count = read_u32(data + offset + 32);
            uint32_t block_reserved = read_u32(data + offset + 36);
            offset += 40;
            if (block_reserved != 0) {
                free(blocks);
                return up_fail(ctx, "compact block %#llx has invalid header",
                               (unsigned long long)address);
            }
            size_t instruction_bytes = (size_t)instruction_count * 10;
            if (payload_length < offset + instruction_bytes) {
                free(blocks);
                return up_fail(ctx, "compact profile is truncated");
            }
            up_rec_instruction *instructions = calloc(instruction_count == 0 ? 1 : instruction_count,
                                                      sizeof(up_rec_instruction));
            if (instructions == NULL) {
                free(blocks);
                return up_fail(ctx, "out of memory loading the compact profile");
            }
            for (uint32_t instruction_index = 0; instruction_index < instruction_count; instruction_index++) {
                const uint8_t *record = data + offset + (size_t)instruction_index * 10;
                uint16_t opcode = read_u16(record);
                if (opcode >= 277 || record[7] != 0) {
                    free(instructions);
                    free(blocks);
                    return up_fail(ctx, "compact block %#llx has invalid instruction",
                                   (unsigned long long)address);
                }
                instructions[instruction_index].op = opcode;
                instructions[instruction_index].destination = record[2];
                instructions[instruction_index].left = record[3];
                instructions[instruction_index].right = record[4];
                instructions[instruction_index].accumulator = record[5];
                instructions[instruction_index].shift = record[6];
                instructions[instruction_index].immediate = read_u16(record + 8);
            }
            offset += instruction_bytes;
            blocks[block_index].instructions = instructions;
            blocks[block_index].instruction_count = instruction_count;
        }
        target->blocks = blocks;
        target->count = block_count;
    }
    if (offset != payload_length) {
        return up_fail(ctx, "compact profile has trailing data");
    }
    return true;
}

// MARK: - Kernels

bool up_rec_load_kernels(up_context *ctx, const uint8_t *data, size_t length, up_rec_profile *profile) {
    if (length < 16 || memcmp(data, UP_REC_KERNEL_MAGIC, 8) != 0) {
        return up_fail(ctx, "invalid recovery kernel table magic");
    }
    if (read_u32(data + 8) != 1) {
        return up_fail(ctx, "unsupported recovery kernel table version");
    }
    size_t offset = 12;
    uint64_t geometry[16];
    for (int index = 0; index < 16; index++) {
        if (length < offset + 8) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        geometry[index] = read_u64(data + offset);
        offset += 8;
    }
    profile->account_entry_start = geometry[0];
    profile->account_entry_stop = geometry[1];
    profile->bootstrap_start = geometry[2];
    profile->bootstrap_stop = geometry[3];
    profile->selection_start = geometry[4];
    profile->selection_stop = geometry[5];
    profile->sinf_entry_start = geometry[6];
    profile->sinf_entry_stop = geometry[7];
    profile->selection_frame_call = geometry[8];
    profile->source_address = geometry[9];
    profile->frame_address = geometry[10];
    profile->sinf_frame_offset = geometry[11];
    profile->outer_start = geometry[12];
    profile->outer_cycle = geometry[13];
    profile->cycle_final = geometry[14];
    profile->optional_start = geometry[15];
    if (length < offset + 8) {
        return up_fail(ctx, "truncated recovery kernel table");
    }
    profile->selection_stop_hits = (int)read_u32(data + offset);
    offset += 8;
    if (length < offset + 32 + 16 + 16 + 4096 + 4) {
        return up_fail(ctx, "truncated recovery kernel table");
    }
    memcpy(profile->binary_hash, data + offset, 32);
    offset += 32;
    memcpy(profile->current_sinf_mask, data + offset, 16);
    offset += 16;
    memcpy(profile->current_sinf_white, data + offset, 16);
    offset += 16;
    memcpy(profile->current_sinf_input, data + offset, 4096);
    offset += 4096;
    uint32_t token_count = read_u32(data + offset);
    offset += 4;
    if (token_count > 8) {
        return up_fail(ctx, "invalid recovery once-token count");
    }
    if (length < offset + (size_t)token_count * 8) {
        return up_fail(ctx, "truncated recovery kernel table");
    }
    profile->once_token_count = token_count;
    for (uint32_t index = 0; index < token_count; index++) {
        profile->once_tokens[index] = read_u64(data + offset + (size_t)index * 8);
    }
    offset += (size_t)token_count * 8;

    if (length < offset + 4) {
        return up_fail(ctx, "truncated recovery kernel table");
    }
    uint32_t kernel_count = read_u32(data + offset);
    offset += 4;
    if (kernel_count == 0 || kernel_count > 11) {
        return up_fail(ctx, "invalid recovery kernel count %u", kernel_count);
    }
    profile->kernel_count = kernel_count;
    for (uint32_t index = 0; index < kernel_count; index++) {
        if (length < offset + 1) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        uint8_t name_length = data[offset];
        offset += 1;
        if (length < offset + name_length + 8 + 4) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        up_rec_kernel *kernel = &profile->kernels[index];
        kernel->name = malloc((size_t)name_length + 1);
        if (kernel->name == NULL) {
            return up_fail(ctx, "out of memory loading the recovery kernel table");
        }
        memcpy(kernel->name, data + offset, name_length);
        kernel->name[name_length] = '\0';
        offset += name_length;
        kernel->start = read_u64(data + offset);
        offset += 8;
        uint32_t instruction_count = read_u32(data + offset);
        offset += 4;
        if (length < offset + (size_t)instruction_count * 10) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        kernel->instructions = calloc(instruction_count == 0 ? 1 : instruction_count,
                                      sizeof(up_rec_instruction));
        if (kernel->instructions == NULL) {
            return up_fail(ctx, "out of memory loading the recovery kernel table");
        }
        kernel->instruction_count = instruction_count;
        for (uint32_t instruction_index = 0; instruction_index < instruction_count; instruction_index++) {
            const uint8_t *record = data + offset + (size_t)instruction_index * 10;
            if (read_u16(record) >= 277) {
                return up_fail(ctx, "recovery kernel %s has an invalid opcode", kernel->name);
            }
            kernel->instructions[instruction_index].op = read_u16(record);
            kernel->instructions[instruction_index].destination = record[2];
            kernel->instructions[instruction_index].left = record[3];
            kernel->instructions[instruction_index].right = record[4];
            kernel->instructions[instruction_index].accumulator = record[5];
            kernel->instructions[instruction_index].shift = record[6];
            kernel->instructions[instruction_index].immediate = read_u16(record + 8);
        }
        offset += (size_t)instruction_count * 10;
        if (length < offset + 4) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        uint32_t segment_count = read_u32(data + offset);
        offset += 4;
        if (length < offset + (size_t)segment_count * 12) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        kernel->segments = calloc(segment_count == 0 ? 1 : segment_count, sizeof(up_rec_segment));
        if (kernel->segments == NULL) {
            return up_fail(ctx, "out of memory loading the recovery kernel table");
        }
        kernel->segment_count = segment_count;
        for (uint32_t segment_index = 0; segment_index < segment_count; segment_index++) {
            kernel->segments[segment_index].index = read_u32(data + offset);
            kernel->segments[segment_index].address = read_u64(data + offset + 4);
            offset += 12;
        }
        if (length < offset + 4) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        uint32_t hook_count = read_u32(data + offset);
        offset += 4;
        if (length < offset + (size_t)hook_count * 9) {
            return up_fail(ctx, "truncated recovery kernel table");
        }
        kernel->hooks = calloc(hook_count == 0 ? 1 : hook_count, sizeof(up_rec_hook));
        if (kernel->hooks == NULL) {
            return up_fail(ctx, "out of memory loading the recovery kernel table");
        }
        kernel->hook_count = hook_count;
        for (uint32_t hook_index = 0; hook_index < hook_count; hook_index++) {
            kernel->hooks[hook_index].after = read_u64(data + offset);
            kernel->hooks[hook_index].action = data[offset + 8];
            offset += 9;
        }
    }
    // Extra outer hooks appended by the generator.
    if (length < offset + 4) {
        return up_fail(ctx, "truncated recovery kernel table");
    }
    uint32_t extra_hook_count = read_u32(data + offset);
    offset += 4;
    if (length < offset + (size_t)extra_hook_count * 9) {
        return up_fail(ctx, "truncated recovery kernel table");
    }
    up_rec_kernel *outer = NULL;
    for (size_t index = 0; index < profile->kernel_count; index++) {
        if (strcmp(profile->kernels[index].name, "outer") == 0) {
            outer = &profile->kernels[index];
            break;
        }
    }
    if (extra_hook_count != 0 && outer != NULL) {
        up_rec_hook *hooks = calloc(extra_hook_count, sizeof(up_rec_hook));
        if (hooks == NULL) {
            return up_fail(ctx, "out of memory loading the recovery kernel table");
        }
        for (uint32_t index = 0; index < extra_hook_count; index++) {
            hooks[index].after = read_u64(data + offset + (size_t)index * 9);
            hooks[index].action = data[offset + (size_t)index * 9 + 8];
        }
        free(outer->hooks);
        outer->hooks = hooks;
        outer->hook_count = extra_hook_count;
    }
    offset += (size_t)extra_hook_count * 9;

    if (length < offset + 4) {
        return up_fail(ctx, "truncated recovery kernel table");
    }
    uint32_t verified_count = read_u32(data + offset);
    offset += 4;
    up_rec_block *verified = calloc(verified_count == 0 ? 1 : verified_count, sizeof(up_rec_block));
    if (verified == NULL) {
        return up_fail(ctx, "out of memory loading the recovery kernel table");
    }
    for (uint32_t block_index = 0; block_index < verified_count; block_index++) {
        if (length < offset + 40) {
            free(verified);
            return up_fail(ctx, "truncated recovery kernel table");
        }
        uint64_t address = read_u64(data + offset);
        const uint8_t *control = data + offset + 8;
        verified[block_index].start = address;
        verified[block_index].terminator = control[0];
        verified[block_index].condition = control[1];
        verified[block_index].reg = control[2];
        verified[block_index].width = control[3];
        verified[block_index].bit = control[4];
        verified[block_index].target = read_u64(data + offset + 16);
        verified[block_index].alternate = read_u64(data + offset + 24);
        uint32_t instruction_count = read_u32(data + offset + 32);
        offset += 40;
        if (length < offset + (size_t)instruction_count * 10) {
            free(verified);
            return up_fail(ctx, "truncated recovery kernel table");
        }
        verified[block_index].instructions = calloc(instruction_count == 0 ? 1 : instruction_count,
                                                    sizeof(up_rec_instruction));
        if (verified[block_index].instructions == NULL) {
            free(verified);
            return up_fail(ctx, "out of memory loading the recovery kernel table");
        }
        verified[block_index].instruction_count = instruction_count;
        for (uint32_t instruction_index = 0; instruction_index < instruction_count; instruction_index++) {
            const uint8_t *record = data + offset + (size_t)instruction_index * 10;
            verified[block_index].instructions[instruction_index].op = read_u16(record);
            verified[block_index].instructions[instruction_index].destination = record[2];
            verified[block_index].instructions[instruction_index].left = record[3];
            verified[block_index].instructions[instruction_index].right = record[4];
            verified[block_index].instructions[instruction_index].accumulator = record[5];
            verified[block_index].instructions[instruction_index].shift = record[6];
            verified[block_index].instructions[instruction_index].immediate = read_u16(record + 8);
        }
        offset += (size_t)instruction_count * 10;
    }
    if (offset != length) {
        free(verified);
        return up_fail(ctx, "recovery kernel table has trailing data");
    }
    profile->verified.blocks = verified;
    profile->verified.count = verified_count;
    return true;
}

const up_rec_kernel *up_rec_kernel_named(const up_rec_profile *profile, const char *name) {
    for (size_t index = 0; index < profile->kernel_count; index++) {
        if (strcmp(profile->kernels[index].name, name) == 0) {
            return &profile->kernels[index];
        }
    }
    return NULL;
}

void up_rec_release_profile(up_rec_profile *profile) {
    if (profile == NULL) {
        return;
    }
    release_blocks(&profile->account_entry);
    release_blocks(&profile->bootstrap);
    release_blocks(&profile->selection);
    release_blocks(&profile->supplemental);
    release_blocks(&profile->verified);
    release_blocks(&profile->extracted);
    for (size_t index = 0; index < 6; index++) {
        release_blocks(&profile->sinf_entry[index]);
    }
    for (size_t index = 0; index < profile->kernel_count; index++) {
        up_rec_kernel *kernel = &profile->kernels[index];
        free(kernel->name);
        free(kernel->instructions);
        free(kernel->segments);
        free(kernel->hooks);
    }
    memset(profile, 0, sizeof(*profile));
}

// MARK: - Semantic frame profile

static bool read_into(const uint8_t *data, size_t length, size_t *offset, void *output,
                      size_t count, const char *name) {
    if (length < *offset + count) {
        return false;
    }
    memcpy(output, data + *offset, count);
    *offset += count;
    (void)name;
    return true;
}

bool up_rec_frame_parse(up_context *ctx, const uint8_t *data, size_t length, up_rec_frame_profile *frame) {
    memset(frame, 0, sizeof(*frame));
    if (length < 32) {
        return up_fail(ctx, "semantic frame profile is truncated");
    }
    size_t payload_length = length - 32;
    if (!verify_checksum(ctx, data, payload_length, data + payload_length, "semantic frame profile")) {
        return false;
    }
    if (memcmp(data, UP_REC_FRAME_MAGIC, 8) != 0) {
        return up_fail(ctx, "invalid semantic frame profile magic");
    }
    if (read_u32(data + 8) != 2) {
        return up_fail(ctx, "unsupported semantic frame profile version");
    }
    size_t offset = 12;
    if (!read_into(data, payload_length, &offset, frame->input_constant, 16, "input constant") ||
        !read_into(data, payload_length, &offset, frame->input_columns, sizeof(frame->input_columns),
                   "input columns")) {
        return up_fail(ctx, "semantic frame profile is truncated");
    }
    if (payload_length < offset + 8) {
        return up_fail(ctx, "semantic frame profile is truncated");
    }
    uint8_t round_count = data[offset];
    for (int reserved = 1; reserved < 8; reserved++) {
        if (data[offset + (size_t)reserved] != 0) {
            return up_fail(ctx, "invalid semantic frame round header");
        }
    }
    offset += 8;
    if (round_count != 9) {
        return up_fail(ctx, "invalid semantic frame round count %u", round_count);
    }
    for (int round_index = 0; round_index < 9; round_index++) {
        up_rec_frame_round *round = &frame->rounds[round_index];
        if (!read_into(data, payload_length, &offset, round->baseline, 16, "round baseline")) {
            return up_fail(ctx, "semantic frame profile is truncated");
        }
        for (int position = 0; position < 16; position++) {
            if (!read_into(data, payload_length, &offset, round->targets[position], 4,
                           "round targets")) {
                return up_fail(ctx, "semantic frame profile is truncated");
            }
            bool seen[16] = {false};
            for (int slot = 0; slot < 4; slot++) {
                uint8_t target = round->targets[position][slot];
                if (target >= 16 || seen[target]) {
                    return up_fail(ctx, "invalid semantic frame target");
                }
                seen[target] = true;
            }
            if (!read_into(data, payload_length, &offset, round->tables[position],
                           sizeof(round->tables[position]), "round tables")) {
                return up_fail(ctx, "semantic frame profile is truncated");
            }
        }
    }
    if (!read_into(data, payload_length, &offset, frame->exit_inputs, 4, "exit inputs")) {
        return up_fail(ctx, "semantic frame profile is truncated");
    }
    for (int input = 0; input < 4; input++) {
        if (frame->exit_inputs[input] >= 16) {
            return up_fail(ctx, "invalid semantic frame exit input");
        }
    }
    if (!read_into(data, payload_length, &offset, frame->exit_baseline, 4, "exit baseline") ||
        !read_into(data, payload_length, &offset, frame->exit_contributions,
                   sizeof(frame->exit_contributions), "exit contributions")) {
        return up_fail(ctx, "semantic frame profile is truncated");
    }
    if (payload_length < offset + 8) {
        return up_fail(ctx, "semantic frame profile is truncated");
    }
    uint8_t final_count = data[offset];
    for (int reserved = 1; reserved < 8; reserved++) {
        if (data[offset + (size_t)reserved] != 0) {
            return up_fail(ctx, "invalid semantic frame final header");
        }
    }
    offset += 8;
    if (final_count != 16) {
        return up_fail(ctx, "invalid semantic frame final count %u", final_count);
    }
    for (int target = 0; target < 16; target++) {
        up_rec_frame_final *entry = &frame->final[target];
        if (payload_length < offset + 1) {
            return up_fail(ctx, "semantic frame profile is truncated");
        }
        uint8_t count = data[offset++];
        if (count != 1 && count != 3) {
            return up_fail(ctx, "invalid semantic frame final input count");
        }
        entry->input_count = count;
        if (!read_into(data, payload_length, &offset, entry->inputs, 3, "final inputs")) {
            return up_fail(ctx, "semantic frame profile is truncated");
        }
        for (int slot = 0; slot < count; slot++) {
            if (entry->inputs[slot] >= 16) {
                return up_fail(ctx, "invalid semantic frame final input");
            }
        }
        if (payload_length < offset + 4) {
            return up_fail(ctx, "semantic frame profile is truncated");
        }
        entry->baseline = data[offset];
        uint8_t stored_target = data[offset + 1];
        if (stored_target != (uint8_t)target) {
            return up_fail(ctx, "invalid semantic frame final target");
        }
        if (data[offset + 2] != 0 || data[offset + 3] != 0) {
            return up_fail(ctx, "invalid semantic frame final envelope");
        }
        offset += 4;
        if (count == 1) {
            if (!read_into(data, payload_length, &offset, entry->direct, 256, "final direct")) {
                return up_fail(ctx, "semantic frame profile is truncated");
            }
        } else {
            if (!read_into(data, payload_length, &offset, entry->encode, 256, "final encode") ||
                !read_into(data, payload_length, &offset, entry->contributions,
                           sizeof(entry->contributions), "final contributions")) {
                return up_fail(ctx, "semantic frame profile is truncated");
            }
        }
    }
    if (offset != payload_length) {
        return up_fail(ctx, "semantic frame profile has trailing data");
    }
    frame->loaded = true;
    return true;
}

void up_rec_release_frame_profile(up_rec_frame_profile *frame) {
    if (frame != NULL) {
        memset(frame, 0, sizeof(*frame));
    }
}
