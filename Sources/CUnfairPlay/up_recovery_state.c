//
//  up_recovery_state.c
//  CUnfairPlay
//
//  Captured-memory model and register state for the recovery interpreter.
//  Every observable behaviour here mirrors internal/recovery/oracle.go:
//  page lookup order, copy-on-write, destination-page holes, the digest
//  enumeration order and the error strings.
//

#include "up_recovery.h"

#include <stdlib.h>
#include <string.h>

#include "up_crypto.h"

#define UP_MODEL_MAGIC "FPGOOR1"

// MARK: - ARM helpers

uint64_t up_rec_shift_left(uint64_t value, int amount, int width) {
    if (width == 32) {
        return (uint64_t)((uint32_t)value << ((unsigned)amount & 31u));
    }
    return value << ((unsigned)amount & 63u);
}

uint64_t up_rec_shift_right(uint64_t value, int amount, int width) {
    if (width == 32) {
        return (uint64_t)((uint32_t)value >> ((unsigned)amount & 31u));
    }
    return value >> ((unsigned)amount & 63u);
}

uint64_t up_rec_shift_right_arithmetic(uint64_t value, int amount, int width) {
    if (width == 32) {
        return (uint64_t)(uint32_t)((int32_t)value >> ((unsigned)amount & 31u));
    }
    return (uint64_t)((int64_t)value >> ((unsigned)amount & 63u));
}

uint64_t up_rec_rotate_right(uint64_t value, int amount, int width) {
    if (width == 32) {
        uint32_t word = (uint32_t)value;
        unsigned rotation = (unsigned)amount & 31u;
        if (rotation == 0) {
            return word;
        }
        return (uint64_t)(uint32_t)((word >> rotation) | (word << (32u - rotation)));
    }
    unsigned rotation = (unsigned)amount & 63u;
    if (rotation == 0) {
        return value;
    }
    return (value >> rotation) | (value << (64u - rotation));
}

uint64_t up_rec_bit_mask(int bits, int width) {
    if (bits >= width) {
        return width == 32 ? (uint64_t)UINT32_MAX : UINT64_MAX;
    }
    return (UINT64_C(1) << (unsigned)bits) - 1;
}

uint64_t up_rec_insert_bits(uint64_t destination, uint64_t source, int lsb, int bits, int width) {
    uint64_t mask = up_rec_bit_mask(bits, width) << (unsigned)lsb;
    uint64_t value = (destination & ~mask) | ((source << (unsigned)lsb) & mask);
    if (width == 32) {
        return (uint64_t)(uint32_t)value;
    }
    return value;
}

uint64_t up_rec_extract_pair(uint64_t high, uint64_t low, int amount, int width) {
    if (width == 32) {
        uint64_t combined = (uint64_t)(uint32_t)high << 32 | (uint64_t)(uint32_t)low;
        return (uint64_t)(uint32_t)(combined >> (unsigned)amount);
    }
    if (amount == 0) {
        return low;
    }
    return high << (unsigned)(64 - amount) | low >> (unsigned)amount;
}

uint64_t up_rec_add_offset(uint64_t value, int64_t offset) {
    return value + (uint64_t)offset;
}

uint64_t up_rec_sign_extend_bits(uint64_t value, int bits, int width) {
    if (bits <= 0 || bits > width) {
        return value;
    }
    uint64_t mask = up_rec_bit_mask(bits, width);
    value &= mask;
    uint64_t sign = UINT64_C(1) << (unsigned)(bits - 1);
    if (value & sign) {
        value |= ~mask;
    }
    if (width == 32) {
        return (uint64_t)(uint32_t)value;
    }
    return value;
}

uint64_t up_rec_sign_extend_32(uint32_t value) {
    return (uint64_t)(int64_t)(int32_t)value;
}

uint64_t up_rec_unsigned_divide(uint64_t left, uint64_t right, int width) {
    if (width == 32) {
        uint32_t divisor = (uint32_t)right;
        if (divisor == 0) {
            return 0;
        }
        return (uint64_t)((uint32_t)left / divisor);
    }
    if (right == 0) {
        return 0;
    }
    return left / right;
}

uint64_t up_rec_multiply_high_64(uint64_t left, uint64_t right) {
    __uint128_t product = (__uint128_t)left * (__uint128_t)right;
    return (uint64_t)(product >> 64);
}

uint64_t up_rec_leading_zeros(uint64_t value, int width) {
    if (width == 32) {
        uint32_t word = (uint32_t)value;
        return word == 0 ? 32 : (uint64_t)__builtin_clz(word);
    }
    return value == 0 ? 64 : (uint64_t)__builtin_clzll(value);
}

uint64_t up_rec_reverse_bytes_32(uint64_t value) {
    uint32_t word = (uint32_t)value;
    word = ((word & UINT32_C(0x00ff00ff)) << 8) | ((word >> 8) & UINT32_C(0x00ff00ff));
    word = (word << 16) | (word >> 16);
    return (uint64_t)word;
}

uint64_t up_rec_reverse_bytes_64(uint64_t value) {
    return (uint64_t)__builtin_bswap64(value);
}

static uint16_t up_rec_read_u16(const uint8_t *bytes) {
    return (uint16_t)(bytes[0] | (uint16_t)bytes[1] << 8);
}

static uint32_t up_rec_read_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static uint64_t up_rec_read_u64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (int index = 7; index >= 0; index--) {
        value = value << 8 | bytes[index];
    }
    return value;
}

static void up_rec_write_u64(uint8_t *bytes, uint64_t value) {
    for (int index = 0; index < 8; index++) {
        bytes[index] = (uint8_t)(value >> (unsigned)(index * 8));
    }
}

// MARK: - Model

static size_t up_rec_model_page_index(const up_rec_model *model, uint64_t address) {
    size_t low = 0;
    size_t high = model->page_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (model->pages[middle].address < address) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return low;
}

static uint8_t *up_rec_model_page_at(const up_rec_model *model, uint64_t address) {
    size_t index = up_rec_model_page_index(model, address);
    if (index < model->page_count && model->pages[index].address == address) {
        return model->pages[index].page;
    }
    return NULL;
}

bool up_rec_load_model(up_context *ctx, const uint8_t *data, size_t length, up_rec_model *model) {
    memset(model, 0, sizeof(*model));
    if (length < 8 || memcmp(data, UP_MODEL_MAGIC, 8) != 0) {
        return up_fail(ctx, "invalid Go FairPlay oracle model magic");
    }
    size_t offset = 8;
    if (length < offset + 4 || up_rec_read_u32(data + offset) != 2) {
        return up_fail(ctx, "unsupported Go FairPlay oracle model version");
    }
    offset += 4;
    if (length < offset + 32 + 8 + 31 * 8 + 8 + 4) {
        return up_fail(ctx, "truncated Go FairPlay oracle model");
    }
    memcpy(model->binary_hash, data + offset, 32);
    offset += 32;
    model->block_address = up_rec_read_u64(data + offset);
    offset += 8;
    for (int index = 0; index < 31; index++) {
        model->registers[index] = up_rec_read_u64(data + offset);
        offset += 8;
    }
    model->registers[31] = 0;
    model->sp = up_rec_read_u64(data + offset);
    offset += 8;
    model->n = data[offset] != 0;
    model->z = data[offset + 1] != 0;
    model->c = data[offset + 2] != 0;
    model->v = data[offset + 3] != 0;
    offset += 4;

    uint32_t page_count = up_rec_read_u32(data + offset);
    offset += 4;
    if (page_count == 0 || page_count > UP_REC_MAX_PAGES) {
        return up_fail(ctx, "invalid Go FairPlay oracle page count");
    }
    up_rec_model_page *pages = calloc(page_count, sizeof(up_rec_model_page));
    if (pages == NULL) {
        return up_fail(ctx, "out of memory loading the recovery model");
    }
    for (uint32_t index = 0; index < page_count; index++) {
        if (length < offset + 8 + UP_REC_PAGE_SIZE) {
            free(pages);
            return up_fail(ctx, "truncated Go FairPlay oracle model");
        }
        uint64_t address = up_rec_read_u64(data + offset);
        offset += 8;
        if (address % UP_REC_PAGE_SIZE != 0) {
            free(pages);
            return up_fail(ctx, "invalid Go FairPlay oracle page address");
        }
        uint8_t *page = malloc(UP_REC_PAGE_SIZE);
        if (page == NULL) {
            free(pages);
            return up_fail(ctx, "out of memory loading the recovery model");
        }
        memcpy(page, data + offset, UP_REC_PAGE_SIZE);
        offset += UP_REC_PAGE_SIZE;
        // Insert in sorted order; the asset is sorted already, but validating
        // the order keeps lookups correct for hand-built fixtures.
        size_t position = index;
        while (position > 0 && pages[position - 1].address > address) {
            pages[position] = pages[position - 1];
            position--;
        }
        if (position > 0 && pages[position - 1].address == address) {
            free(page);
            free(pages);
            return up_fail(ctx, "duplicate Go FairPlay oracle page %#llx", (unsigned long long)address);
        }
        pages[position].address = address;
        pages[position].page = page;
    }
    model->pages = pages;
    model->page_count = page_count;

    if (length < offset + 4) {
        up_rec_release_model(model);
        return up_fail(ctx, "truncated Go FairPlay oracle model");
    }
    uint32_t domain_count = up_rec_read_u32(data + offset);
    offset += 4;
    if (domain_count > 64) {
        up_rec_release_model(model);
        return up_fail(ctx, "invalid Go FairPlay oracle domain count");
    }
    for (uint32_t index = 0; index < domain_count; index++) {
        if (length < offset + 16 + 256 * 8) {
            up_rec_release_model(model);
            return up_fail(ctx, "truncated Go FairPlay oracle model");
        }
        offset += 8;
        uint8_t reg = data[offset];
        if (reg >= 31) {
            up_rec_release_model(model);
            return up_fail(ctx, "invalid Go FairPlay oracle domain register");
        }
        offset += 8;
        uint64_t previous = 0;
        for (int value_index = 0; value_index < 256; value_index++) {
            uint64_t value = up_rec_read_u64(data + offset);
            offset += 8;
            if (value_index != 0 && value <= previous) {
                up_rec_release_model(model);
                return up_fail(ctx, "Go FairPlay oracle domain is not ordered");
            }
            previous = value;
        }
    }
    if (offset != length) {
        up_rec_release_model(model);
        return up_fail(ctx, "Go FairPlay oracle model has trailing data");
    }
    return true;
}

void up_rec_release_model(up_rec_model *model) {
    if (model == NULL) {
        return;
    }
    for (size_t index = 0; index < model->page_count; index++) {
        free(model->pages[index].page);
    }
    free(model->pages);
    model->pages = NULL;
    model->page_count = 0;
    model->length = 0;
}

// MARK: - Page collections

static size_t up_rec_writable_index(const up_rec_state *state, uint64_t address) {
    size_t low = 0;
    size_t high = state->writable_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (state->writable[middle].address < address) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return low;
}

static up_rec_writable *up_rec_writable_find(const up_rec_state *state, uint64_t address) {
    size_t index = up_rec_writable_index(state, address);
    if (index < state->writable_count && state->writable[index].address == address) {
        return &state->writable[index];
    }
    return NULL;
}

static size_t up_rec_mapped_index(const up_rec_state *state, uint64_t address) {
    size_t low = 0;
    size_t high = state->mapped_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (state->mapped[middle].address < address) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return low;
}

static up_rec_mapped *up_rec_mapped_find(const up_rec_state *state, uint64_t address) {
    size_t index = up_rec_mapped_index(state, address);
    if (index < state->mapped_count && state->mapped[index].address == address) {
        return &state->mapped[index];
    }
    return NULL;
}

static bool up_rec_is_destination_page(const up_rec_state *state, uint64_t address) {
    for (size_t index = 0; index < state->destination_count; index++) {
        if (state->destination[index] == address) {
            return true;
        }
    }
    return false;
}

static bool up_rec_ensure_writable(up_rec_state *state) {
    if (state->writable_count < state->writable_capacity) {
        return true;
    }
    size_t capacity = state->writable_capacity == 0 ? 16 : state->writable_capacity * 2;
    up_rec_writable *grown = realloc(state->writable, capacity * sizeof(up_rec_writable));
    if (grown == NULL) {
        return false;
    }
    state->writable = grown;
    state->writable_capacity = capacity;
    return true;
}

static bool up_rec_ensure_touched(up_rec_state *state) {
    if (state->touched_count < state->touched_capacity) {
        return true;
    }
    size_t capacity = state->touched_capacity == 0 ? 16 : state->touched_capacity * 2;
    uint64_t *grown = realloc(state->touched, capacity * sizeof(uint64_t));
    if (grown == NULL) {
        return false;
    }
    state->touched = grown;
    state->touched_capacity = capacity;
    return true;
}

static bool up_rec_ensure_mapped(up_rec_state *state) {
    if (state->mapped_count < state->mapped_capacity) {
        return true;
    }
    size_t capacity = state->mapped_capacity == 0 ? 16 : state->mapped_capacity * 2;
    up_rec_mapped *grown = realloc(state->mapped, capacity * sizeof(up_rec_mapped));
    if (grown == NULL) {
        return false;
    }
    state->mapped = grown;
    state->mapped_capacity = capacity;
    return true;
}

/// Mirrors `state.page`: base lookup through the model, then mapped pages, then
/// destination holes, copy-on-write for writes.
static uint8_t *up_rec_page(up_rec_state *state, uint64_t address, bool write) {
    uint64_t base = address & ~(UP_REC_PAGE_SIZE - 1);
    uint8_t *page = up_rec_model_page_at(state->model, base);
    if (page == NULL) {
        up_rec_mapped *mapped = up_rec_mapped_find(state, base);
        page = mapped == NULL ? NULL : mapped->page;
    }
    if (page == NULL && write && up_rec_is_destination_page(state, base) &&
        state->initialized_count < UP_REC_MAX_DESTINATION_PAGES) {
        if (!up_rec_ensure_mapped(state)) {
            snprintf(state->detail, sizeof(state->detail), "out of memory mapping %#llx",
                     (unsigned long long)base);
            return NULL;
        }
        uint8_t *mapped_page = calloc(1, UP_REC_PAGE_SIZE);
        uint8_t *initialized = calloc(1, UP_REC_PAGE_SIZE);
        if (mapped_page == NULL || initialized == NULL) {
            free(mapped_page);
            free(initialized);
            snprintf(state->detail, sizeof(state->detail), "out of memory mapping %#llx",
                     (unsigned long long)base);
            return NULL;
        }
        size_t index = up_rec_mapped_index(state, base);
        memmove(&state->mapped[index + 1], &state->mapped[index],
                (state->mapped_count - index) * sizeof(up_rec_mapped));
        state->mapped[index].address = base;
        state->mapped[index].page = mapped_page;
        state->mapped[index].initialized = initialized;
        state->mapped_count++;
        state->initialized_count++;
        page = mapped_page;
    }
    if (page == NULL) {
        snprintf(state->detail, sizeof(state->detail),
                 "oracle memory address %#llx is outside the model", (unsigned long long)address);
        return NULL;
    }
    if (!write) {
        up_rec_writable *writable = up_rec_writable_find(state, base);
        return writable == NULL ? page : writable->page;
    }
    up_rec_writable *writable = up_rec_writable_find(state, base);
    if (writable == NULL) {
        if (!up_rec_ensure_writable(state)) {
            snprintf(state->detail, sizeof(state->detail), "out of memory mapping %#llx",
                     (unsigned long long)base);
            return NULL;
        }
        uint8_t *copy = malloc(UP_REC_PAGE_SIZE);
        if (copy == NULL) {
            snprintf(state->detail, sizeof(state->detail), "out of memory mapping %#llx",
                     (unsigned long long)base);
            return NULL;
        }
        memcpy(copy, page, UP_REC_PAGE_SIZE);
        size_t index = up_rec_writable_index(state, base);
        memmove(&state->writable[index + 1], &state->writable[index],
                (state->writable_count - index) * sizeof(up_rec_writable));
        state->writable[index].address = base;
        state->writable[index].page = copy;
        state->writable[index].dirty = false;
        state->writable_count++;
        writable = &state->writable[index];
    }
    if (!writable->dirty) {
        if (!up_rec_ensure_touched(state)) {
            snprintf(state->detail, sizeof(state->detail), "out of memory tracking %#llx",
                     (unsigned long long)base);
            return NULL;
        }
        writable->dirty = true;
        state->touched[state->touched_count++] = base;
    }
    return writable->page;
}

static uint8_t *up_rec_initialized_page(up_rec_state *state, uint64_t address) {
    up_rec_mapped *mapped = up_rec_mapped_find(state, address & ~(UP_REC_PAGE_SIZE - 1));
    return mapped == NULL ? NULL : mapped->initialized;
}

bool up_rec_state_load(up_rec_state *state, uint64_t address, int size, uint64_t *value) {
    *value = 0;
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        snprintf(state->detail, sizeof(state->detail), "unsupported oracle load size %d", size);
        return false;
    }
    uint64_t offset_in_page = address & (UP_REC_PAGE_SIZE - 1);
    if (offset_in_page + (uint64_t)size <= UP_REC_PAGE_SIZE) {
        uint8_t *page = up_rec_page(state, address, false);
        if (page == NULL) {
            return false;
        }
        uint64_t offset = offset_in_page;
        uint8_t *initialized = up_rec_initialized_page(state, address);
        if (initialized != NULL) {
            for (uint64_t index = offset; index < offset + (uint64_t)size; index++) {
                if (!initialized[index]) {
                    snprintf(state->detail, sizeof(state->detail),
                             "read of uncaptured, unwritten memory %#llx", (unsigned long long)address);
                    return false;
                }
            }
        }
        switch (size) {
        case 1:
            *value = page[offset];
            return true;
        case 2:
            *value = up_rec_read_u16(page + offset);
            return true;
        case 4:
            *value = up_rec_read_u32(page + offset);
            return true;
        default:
            *value = up_rec_read_u64(page + offset);
            return true;
        }
    }
    uint8_t buffer[8] = {0};
    for (int index = 0; index < size; index++) {
        uint64_t byte = 0;
        if (!up_rec_state_load(state, address + (uint64_t)index, 1, &byte)) {
            return false;
        }
        buffer[index] = (uint8_t)byte;
    }
    *value = up_rec_read_u64(buffer);
    return true;
}

bool up_rec_state_store(up_rec_state *state, uint64_t address, const uint8_t *bytes, size_t length) {
    size_t consumed = 0;
    while (consumed < length) {
        uint8_t *page = up_rec_page(state, address, true);
        if (page == NULL) {
            return false;
        }
        uint64_t offset = address & (UP_REC_PAGE_SIZE - 1);
        size_t count = length - consumed;
        if (count > (size_t)(UP_REC_PAGE_SIZE - offset)) {
            count = (size_t)(UP_REC_PAGE_SIZE - offset);
        }
        memcpy(page + offset, bytes + consumed, count);
        uint8_t *initialized = up_rec_initialized_page(state, address);
        if (initialized != NULL) {
            memset(initialized + offset, 1, count);
        }
        address += (uint64_t)count;
        consumed += count;
    }
    return true;
}

bool up_rec_state_store_value(up_rec_state *state, uint64_t address, uint64_t value, int size) {
    uint8_t buffer[8] = {0};
    switch (size) {
    case 1:
        buffer[0] = (uint8_t)value;
        break;
    case 2:
        buffer[0] = (uint8_t)value;
        buffer[1] = (uint8_t)(value >> 8);
        break;
    case 4:
        for (int index = 0; index < 4; index++) {
            buffer[index] = (uint8_t)(value >> (unsigned)(index * 8));
        }
        break;
    case 8:
        up_rec_write_u64(buffer, value);
        break;
    default:
        snprintf(state->detail, sizeof(state->detail), "unsupported oracle store size %d", size);
        return false;
    }
    return up_rec_state_store(state, address, buffer, (size_t)size);
}

bool up_rec_state_map_zero(up_rec_state *state, uint64_t address, uint64_t size) {
    if (size == 0 || (address & (UP_REC_PAGE_SIZE - 1)) != 0) {
        snprintf(state->detail, sizeof(state->detail), "invalid zero mapping %#llx+%#llx",
                 (unsigned long long)address, (unsigned long long)size);
        return false;
    }
    uint64_t end = address + size;
    if (end < address) {
        snprintf(state->detail, sizeof(state->detail), "zero mapping overflows");
        return false;
    }
    for (uint64_t base = address; base < end; base += UP_REC_PAGE_SIZE) {
        if (up_rec_model_page_at(state->model, base) != NULL || up_rec_mapped_find(state, base) != NULL) {
            continue;
        }
        if (!up_rec_ensure_mapped(state)) {
            snprintf(state->detail, sizeof(state->detail), "out of memory mapping %#llx",
                     (unsigned long long)base);
            return false;
        }
        uint8_t *page = calloc(1, UP_REC_PAGE_SIZE);
        if (page == NULL) {
            snprintf(state->detail, sizeof(state->detail), "out of memory mapping %#llx",
                     (unsigned long long)base);
            return false;
        }
        size_t index = up_rec_mapped_index(state, base);
        memmove(&state->mapped[index + 1], &state->mapped[index],
                (state->mapped_count - index) * sizeof(up_rec_mapped));
        state->mapped[index].address = base;
        state->mapped[index].page = page;
        state->mapped[index].initialized = NULL;
        state->mapped_count++;
    }
    return true;
}

bool up_rec_state_read_cstring(up_rec_state *state, uint64_t address, size_t limit,
                               char *output, size_t output_size) {
    if (limit == 0) {
        snprintf(state->detail, sizeof(state->detail), "invalid C-string limit");
        return false;
    }
    size_t consumed = 0;
    while (consumed < limit) {
        uint64_t octet = 0;
        if (!up_rec_state_load(state, address + consumed, 1, &octet)) {
            return false;
        }
        if (octet == 0) {
            output[consumed < output_size ? consumed : output_size - 1] = '\0';
            return true;
        }
        if (consumed + 1 < output_size) {
            output[consumed] = (char)octet;
        }
        consumed++;
    }
    snprintf(state->detail, sizeof(state->detail), "unterminated C string at %#llx",
             (unsigned long long)address);
    return false;
}

bool up_rec_state_output_bytes(up_rec_state *state, uint64_t address, uint8_t *output, size_t length) {
    for (size_t index = 0; index < length; index++) {
        uint64_t value = 0;
        if (!up_rec_state_load(state, address + index, 1, &value)) {
            return false;
        }
        output[index] = (uint8_t)value;
    }
    return true;
}

bool up_rec_state_patch(up_rec_state *state, uint64_t base, const uint8_t *bytes, size_t length) {
    up_rec_model *model = state->model;
    size_t index = up_rec_model_page_index(model, base);
    if (index >= model->page_count || model->pages[index].address != base) {
        snprintf(state->detail, sizeof(state->detail), "oracle patch address %#llx is outside the model",
                 (unsigned long long)base);
        return false;
    }
    uint8_t *copy = malloc(UP_REC_PAGE_SIZE);
    if (copy == NULL) {
        snprintf(state->detail, sizeof(state->detail), "out of memory patching %#llx",
                 (unsigned long long)base);
        return false;
    }
    memcpy(copy, model->pages[index].page, UP_REC_PAGE_SIZE);
    uint64_t address = base;
    if (length > UP_REC_PAGE_SIZE) {
        length = UP_REC_PAGE_SIZE;
    }
    memcpy(copy, bytes, length);
    free(model->pages[index].page);
    model->pages[index].page = copy;
    (void)address;
    return true;
}

// MARK: - Vector helpers

void up_rec_vector_lane(const up_rec_state *state, int reg, int lane, int bits, uint64_t *value) {
    size_t offset = (size_t)(lane * bits / 8);
    switch (bits) {
    case 8:
        *value = state->vectors[reg][offset];
        break;
    case 16:
        *value = up_rec_read_u16(state->vectors[reg] + offset);
        break;
    case 32:
        *value = up_rec_read_u32(state->vectors[reg] + offset);
        break;
    default:
        *value = up_rec_read_u64(state->vectors[reg] + offset);
        break;
    }
}

void up_rec_vector_set_lane(up_rec_state *state, int reg, int lane, int bits, uint64_t value) {
    size_t offset = (size_t)(lane * bits / 8);
    switch (bits) {
    case 8:
        state->vectors[reg][offset] = (uint8_t)value;
        break;
    case 16:
        state->vectors[reg][offset] = (uint8_t)value;
        state->vectors[reg][offset + 1] = (uint8_t)(value >> 8);
        break;
    case 32:
        for (int index = 0; index < 4; index++) {
            state->vectors[reg][offset + (size_t)index] = (uint8_t)(value >> (unsigned)(index * 8));
        }
        break;
    default:
        up_rec_write_u64(state->vectors[reg] + offset, value);
        break;
    }
}

void up_rec_vector_clear(up_rec_state *state, int reg) {
    memset(state->vectors[reg], 0, 16);
}

// MARK: - State

static void up_rec_destination_pages(up_rec_state *state) {
    up_rec_model *model = state->model;
    if (!model->allow_destination_pages) {
        return;
    }
    const uint64_t low = UINT64_C(0x710000000000);
    const uint64_t high = UINT64_C(0x710000100000);
    for (size_t index = 0; index < model->page_count; index++) {
        uint64_t address = model->pages[index].address;
        if (address < low || address >= high) {
            continue;
        }
        if (address >= low + UP_REC_PAGE_SIZE && up_rec_model_page_at(model, address - UP_REC_PAGE_SIZE) == NULL) {
            uint64_t *grown = realloc(state->destination,
                                      (state->destination_count + 1) * sizeof(uint64_t));
            if (grown == NULL) {
                return;
            }
            state->destination = grown;
            state->destination[state->destination_count++] = address - UP_REC_PAGE_SIZE;
        }
        if (index > 0 && address - model->pages[index - 1].address <= 33 * UP_REC_PAGE_SIZE) {
            for (uint64_t page = model->pages[index - 1].address + UP_REC_PAGE_SIZE; page < address;
                 page += UP_REC_PAGE_SIZE) {
                bool known = false;
                for (size_t existing = 0; existing < state->destination_count; existing++) {
                    if (state->destination[existing] == page) {
                        known = true;
                        break;
                    }
                }
                if (known) {
                    continue;
                }
                uint64_t *grown = realloc(state->destination,
                                          (state->destination_count + 1) * sizeof(uint64_t));
                if (grown == NULL) {
                    return;
                }
                state->destination = grown;
                state->destination[state->destination_count++] = page;
            }
        }
    }
}

bool up_rec_state_create(up_rec_state *state, up_rec_model *model, up_rec_profile *profile,
                         up_rec_runtime *runtime) {
    memset(state, 0, sizeof(*state));
    state->ctx = NULL;
    state->model = model;
    state->profile = profile;
    state->runtime = runtime;
    up_rec_destination_pages(state);
    up_rec_state_reset(state);
    return true;
}

void up_rec_state_destroy(up_rec_state *state) {
    for (size_t index = 0; index < state->writable_count; index++) {
        free(state->writable[index].page);
    }
    free(state->writable);
    free(state->touched);
    for (size_t index = 0; index < state->mapped_count; index++) {
        free(state->mapped[index].page);
        free(state->mapped[index].initialized);
    }
    free(state->mapped);
    free(state->destination);
    if (state->trace != NULL) {
        up_sha256_release(state->trace);
    }
    memset(state, 0, sizeof(*state));
}

void up_rec_state_reset(up_rec_state *state) {
    for (size_t index = 0; index < state->touched_count; index++) {
        uint64_t address = state->touched[index];
        up_rec_writable *writable = up_rec_writable_find(state, address);
        uint8_t *page = up_rec_model_page_at(state->model, address);
        if (writable != NULL) {
            if (page != NULL) {
                memcpy(writable->page, page, UP_REC_PAGE_SIZE);
            }
            writable->dirty = false;
        }
    }
    for (size_t index = 0; index < state->mapped_count; index++) {
        memset(state->mapped[index].page, 0, UP_REC_PAGE_SIZE);
        free(state->mapped[index].initialized);
        state->mapped[index].initialized = NULL;
        up_rec_writable *writable = up_rec_writable_find(state, state->mapped[index].address);
        if (writable != NULL) {
            size_t position = up_rec_writable_index(state, state->mapped[index].address);
            free(state->writable[position].page);
            memmove(&state->writable[position], &state->writable[position + 1],
                    (state->writable_count - position - 1) * sizeof(up_rec_writable));
            state->writable_count--;
        }
    }
    for (size_t index = 0; index < state->mapped_count; index++) {
        free(state->mapped[index].page);
    }
    state->mapped_count = 0;
    state->initialized_count = 0;
    state->touched_count = 0;
    memcpy(state->x, state->model->registers, sizeof(state->x));
    memset(state->vectors, 0, sizeof(state->vectors));
    state->sp = state->model->sp;
    state->n = state->model->n;
    state->z = state->model->z;
    state->c = state->model->c;
    state->v = state->model->v;
}

bool up_rec_state_digest(up_rec_state *state, uint8_t output[32]) {
    up_sha256_ctx *hash = up_sha256_create();
    if (hash == NULL) {
        return up_fail(state->ctx, "out of memory hashing the recovery state");
    }
    uint8_t word[8];
    for (int index = 0; index < 31; index++) {
        up_rec_write_u64(word, state->x[index]);
        up_sha256_update(hash, word, 8);
    }
    up_rec_write_u64(word, state->sp);
    up_sha256_update(hash, word, 8);
    uint8_t flags[4] = {(uint8_t)state->n, (uint8_t)state->z, (uint8_t)state->c, (uint8_t)state->v};
    up_sha256_update(hash, flags, 4);

    // Merge the model pages with the mapped pages that are not in the model,
    // in ascending address order. This is the enumeration order the Go digest
    // uses.
    size_t cursor_model = 0;
    size_t cursor_mapped = 0;
    while (cursor_model < state->model->page_count || cursor_mapped < state->mapped_count) {
        while (cursor_mapped < state->mapped_count &&
               up_rec_model_page_at(state->model, state->mapped[cursor_mapped].address) != NULL) {
            cursor_mapped++;
        }
        uint64_t address = 0;
        uint8_t *page = NULL;
        if (cursor_model < state->model->page_count &&
            (cursor_mapped >= state->mapped_count ||
             state->model->pages[cursor_model].address < state->mapped[cursor_mapped].address)) {
            address = state->model->pages[cursor_model].address;
            page = state->model->pages[cursor_model].page;
            cursor_model++;
        } else if (cursor_mapped < state->mapped_count) {
            address = state->mapped[cursor_mapped].address;
            page = state->mapped[cursor_mapped].page;
            cursor_mapped++;
        } else {
            break;
        }
        up_rec_writable *writable = up_rec_writable_find(state, address);
        if (writable != NULL) {
            page = writable->page;
        }
        if (page == NULL) {
            continue;
        }
        up_rec_write_u64(word, address);
        up_sha256_update(hash, word, 8);
        up_sha256_update(hash, page, UP_REC_PAGE_SIZE);
    }
    up_sha256_final(hash, output);
    up_sha256_release(hash);
    return true;
}

void up_rec_state_trace(up_rec_state *state, uint64_t pc) {
    if (state->trace == NULL) {
        return;
    }
    uint8_t word[8];
    up_rec_write_u64(word, pc);
    up_sha256_update(state->trace, word, 8);
    for (int index = 0; index < 31; index++) {
        up_rec_write_u64(word, state->x[index]);
        up_sha256_update(state->trace, word, 8);
    }
    up_rec_write_u64(word, state->sp);
    up_sha256_update(state->trace, word, 8);
    uint8_t flags[4] = {(uint8_t)state->n, (uint8_t)state->z, (uint8_t)state->c, (uint8_t)state->v};
    up_sha256_update(state->trace, flags, 4);
    up_sha256_update(state->trace, &state->vectors[0][0], sizeof(state->vectors));
}

bool up_rec_state_trace_finish(up_rec_state *state, uint8_t output[32]) {
    if (state->trace == NULL) {
        memset(output, 0, 32);
        return true;
    }
    up_sha256_final(state->trace, output);
    up_sha256_release(state->trace);
    state->trace = NULL;
    return true;
}
