//
//  up_recovery_exec.c
//  CUnfairPlay
//
//  Block and control-flow execution for the native FairPlay recovery
//  interpreter. This is a direct port of the reference block driver, the four
//  generated CFG drivers, the bootstrap runtime externals, and the frame
//  dispatch that bridges the selection CFG back into the semantic model.
//

#include "up_recovery.h"
#include "up_crypto.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define UP_REC_EXTERNAL_MIN UINT64_C(0xf000000000000000)
#define UP_REC_PTHREAD_STUB UINT64_C(0x720000000000)
#define UP_REC_ERRNO_ADDRESS UINT64_C(0x7100FFF00000)
#define UP_REC_MAX_BOOTSTRAP_READ UINT64_C(0x10000000)
#define UP_REC_PATH_LIMIT 0x100000

// MARK: - Diagnostics

static void up_rec_detail(up_rec_state *state, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(state->detail, sizeof(state->detail), format, arguments);
    va_end(arguments);
}

/// Wraps the pending diagnostic in a prefix that names the driver and the
/// failing program counter. The message is copied first because the source and
/// destination overlap.
static bool up_rec_wrap(up_rec_state *state, const char *prefix, uint64_t pc) {
    char detail[sizeof(state->detail)];
    memcpy(detail, state->detail, sizeof(detail));
    snprintf(state->detail, sizeof(state->detail), "%s %#llx: %s", prefix,
             (unsigned long long)pc, detail);
    return false;
}

// MARK: - Block execution

bool up_rec_run_block(up_rec_state *state, const up_rec_block *block, uint64_t *next, bool *stopped) {
    *next = 0;
    *stopped = false;
    uint64_t terminal = block->start + (uint64_t)block->instruction_count * 4;
    up_rec_runtime *runtime = state->runtime;
    if (runtime != NULL && runtime->stop_pc >= block->start && runtime->stop_pc <= terminal &&
        (runtime->stop_pc - block->start) % 4 == 0) {
        size_t count = (size_t)((runtime->stop_pc - block->start) / 4);
        if (count != 0) {
            up_rec_kernel prefix;
            memset(&prefix, 0, sizeof(prefix));
            prefix.start = block->start;
            prefix.instructions = block->instructions;
            prefix.instruction_count = count;
            if (!up_rec_run_kernel(state, &prefix)) {
                return false;
            }
        }
        *next = runtime->stop_pc;
        *stopped = true;
        return true;
    }
    up_rec_kernel kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.start = block->start;
    kernel.instructions = block->instructions;
    kernel.instruction_count = block->instruction_count;
    if (!up_rec_run_kernel(state, &kernel)) {
        return false;
    }
    switch (block->terminator) {
    case 0:
        *next = block->target;
        return true;
    case 1: {
        int matches = up_rec_condition_matches(state, block->condition);
        if (matches < 0) {
            up_rec_detail(state, "unknown compact block condition %d", (int)block->condition);
            return false;
        }
        *next = matches != 0 ? block->target : block->alternate;
        return true;
    }
    case 2:
        *next = state->x[block->reg];
        return true;
    case 3:
        state->x[30] = terminal + 4;
        *next = state->x[block->reg];
        return true;
    case 4:
        state->x[30] = terminal + 4;
        *next = block->target;
        return true;
    case 5:
        *next = state->x[30];
        return true;
    case 6: {
        uint64_t value = state->x[block->reg];
        if (block->width == 32) {
            value = (uint64_t)(uint32_t)value;
        }
        if (block->condition != 0 && block->condition != 1) {
            up_rec_detail(state, "invalid compare-zero condition %d", (int)block->condition);
            return false;
        }
        bool zero = value == 0;
        bool take = (block->condition == 0 && zero) || (block->condition == 1 && !zero);
        *next = take ? block->target : block->alternate;
        return true;
    }
    case 7: {
        if (block->condition != 0 && block->condition != 1) {
            up_rec_detail(state, "invalid test-bit condition %d", (int)block->condition);
            return false;
        }
        bool set = (state->x[block->reg] & (UINT64_C(1) << block->bit)) != 0;
        bool take = (block->condition == 1 && set) || (block->condition == 0 && !set);
        *next = take ? block->target : block->alternate;
        return true;
    }
    case 8:
        *next = block->target;
        *stopped = true;
        return true;
    default:
        up_rec_detail(state, "unknown compact block terminator %d", (int)block->terminator);
        return false;
    }
}

// MARK: - Block lookup

static bool up_rec_block_lookup(up_rec_state *state, uint64_t pc,
                                const up_rec_blocks *primary, const up_rec_blocks *supplemental,
                                const up_rec_block **result) {
    *result = NULL;
    const up_rec_blocks *tables[4] = {primary, supplemental, &state->profile->verified,
                                      &state->profile->extracted};
    for (size_t index = 0; index < 4; index++) {
        const up_rec_blocks *table = tables[index];
        if (table == NULL || table->count == 0) {
            continue;
        }
        const up_rec_block *block = up_rec_blocks_find(table, pc);
        if (block != NULL) {
            if (table == &state->profile->extracted) {
                state->extracted_hits++;
            }
            *result = block;
            return true;
        }
    }
    return false;
}

static bool up_rec_sinf_entry_lookup(up_rec_state *state, uint64_t pc, const up_rec_block **result) {
    *result = NULL;
    for (size_t index = 0; index < 6; index++) {
        const up_rec_blocks *table = &state->profile->sinf_entry[index];
        if (table->count == 0) {
            continue;
        }
        const up_rec_block *block = up_rec_blocks_find(table, pc);
        if (block != NULL) {
            *result = block;
            return true;
        }
    }
    const up_rec_blocks *tables[2] = {&state->profile->supplemental, &state->profile->verified};
    for (size_t index = 0; index < 2; index++) {
        const up_rec_block *block = up_rec_blocks_find(tables[index], pc);
        if (block != NULL) {
            *result = block;
            return true;
        }
    }
    if (state->profile->extracted.count != 0) {
        const up_rec_block *block = up_rec_blocks_find(&state->profile->extracted, pc);
        if (block != NULL) {
            state->extracted_hits++;
            *result = block;
            return true;
        }
    }
    return false;
}

static bool up_rec_is_external(uint64_t pc) {
    return pc >= UP_REC_EXTERNAL_MIN || pc == UP_REC_PTHREAD_STUB;
}

// MARK: - CFG drivers

bool up_rec_run_account_entry_cfg(up_rec_state *state, int max_blocks) {
    uint64_t pc = state->profile->account_entry_start;
    int stop_hits = 0;
    for (int block_count = 0; block_count < max_blocks; block_count++) {
        if (pc == state->profile->account_entry_stop) {
            stop_hits++;
            if (stop_hits == 1) {
                return true;
            }
        }
        if (state->runtime != NULL && state->runtime->stop_pc != 0 && pc == state->runtime->stop_pc) {
            return true;
        }
        if (up_rec_is_external(pc)) {
            if (state->runtime == NULL) {
                up_rec_detail(state, "account-entry runtime is unavailable");
                return false;
            }
            uint64_t next = 0;
            if (!up_rec_runtime_handle(state, pc, &next)) {
                return false;
            }
            pc = next;
            continue;
        }
        const up_rec_block *block = NULL;
        if (!up_rec_block_lookup(state, pc, &state->profile->account_entry,
                                 &state->profile->supplemental, &block)) {
            up_rec_detail(state, "account-entry CFG reached unknown block %#llx",
                          (unsigned long long)pc);
            return false;
        }
        uint64_t next = 0;
        bool stopped = false;
        if (!up_rec_run_block(state, block, &next, &stopped)) {
            return up_rec_wrap(state, "compact account-entry CFG", pc);
        }
        if (stopped) {
            return true;
        }
        pc = next;
    }
    up_rec_detail(state, "account-entry CFG exceeded %d blocks; pc=%#llx", max_blocks,
                  (unsigned long long)pc);
    return false;
}

bool up_rec_run_bootstrap_cfg(up_rec_state *state, int max_blocks) {
    uint64_t pc = state->profile->bootstrap_start;
    for (int block_count = 0; block_count < max_blocks; block_count++) {
        if (pc == state->profile->bootstrap_stop) {
            return true;
        }
        if (state->runtime != NULL && state->runtime->stop_pc != 0 && pc == state->runtime->stop_pc) {
            return true;
        }
        if (up_rec_is_external(pc)) {
            if (state->runtime == NULL) {
                up_rec_detail(state, "bootstrap runtime is unavailable");
                return false;
            }
            uint64_t next = 0;
            if (!up_rec_runtime_handle(state, pc, &next)) {
                return false;
            }
            pc = next;
            continue;
        }
        const up_rec_block *block = NULL;
        if (!up_rec_block_lookup(state, pc, &state->profile->bootstrap,
                                 &state->profile->supplemental, &block)) {
            up_rec_detail(state, "bootstrap CFG reached unknown block %#llx",
                          (unsigned long long)pc);
            return false;
        }
        uint64_t next = 0;
        bool stopped = false;
        if (!up_rec_run_block(state, block, &next, &stopped)) {
            return up_rec_wrap(state, "compact bootstrap CFG", pc);
        }
        if (stopped) {
            return true;
        }
        pc = next;
    }
    up_rec_detail(state, "bootstrap CFG exceeded %d blocks; pc=%#llx", max_blocks,
                  (unsigned long long)pc);
    return false;
}

bool up_rec_run_selection_cfg(up_rec_state *state, int max_blocks) {
    uint64_t pc = state->profile->selection_start;
    int stop_hits = 0;
    int frame_calls = 0;
    for (int block_count = 0; block_count < max_blocks; block_count++) {
        if (pc == state->profile->selection_frame_call) {
            frame_calls++;
            if (frame_calls == 1) {
                // The first invocation materializes neighboring dispatcher
                // state; it falls through to the frame call itself.
            } else if (frame_calls == 2) {
                uint64_t next = 0;
                if (!up_rec_apply_frame(state, &next)) {
                    return false;
                }
                pc = next;
                continue;
            } else {
                up_rec_detail(state, "unexpected enrollment frame invocation %d", frame_calls);
                return false;
            }
        }
        if (pc == state->profile->selection_stop) {
            stop_hits++;
            if (stop_hits == state->profile->selection_stop_hits) {
                return true;
            }
        }
        if (state->runtime != NULL && state->runtime->stop_pc != 0 && pc == state->runtime->stop_pc) {
            return true;
        }
        if (up_rec_is_external(pc)) {
            if (state->runtime == NULL) {
                up_rec_detail(state, "selection runtime is unavailable");
                return false;
            }
            uint64_t next = 0;
            if (!up_rec_runtime_handle(state, pc, &next)) {
                return false;
            }
            pc = next;
            continue;
        }
        const up_rec_block *block = NULL;
        if (!up_rec_block_lookup(state, pc, &state->profile->selection,
                                 &state->profile->supplemental, &block)) {
            up_rec_detail(state, "selection CFG reached unknown block %#llx",
                          (unsigned long long)pc);
            return false;
        }
        uint64_t next = 0;
        bool stopped = false;
        if (!up_rec_run_block(state, block, &next, &stopped)) {
            return up_rec_wrap(state, "compact selection CFG", pc);
        }
        if (stopped) {
            return true;
        }
        pc = next;
    }
    up_rec_detail(state, "selection CFG exceeded %d blocks; pc=%#llx", max_blocks,
                  (unsigned long long)pc);
    return false;
}

bool up_rec_run_sinf_entry_cfg(up_rec_state *state, int max_blocks) {
    uint64_t pc = state->profile->sinf_entry_start;
    int stop_hits = 0;
    for (int block_count = 0; block_count < max_blocks; block_count++) {
        if (pc == state->profile->sinf_entry_stop) {
            stop_hits++;
            if (stop_hits == 1) {
                return true;
            }
        }
        if (state->runtime != NULL && state->runtime->stop_pc != 0 && pc == state->runtime->stop_pc) {
            return true;
        }
        if (up_rec_is_external(pc)) {
            if (state->runtime == NULL) {
                up_rec_detail(state, "sinf-entry runtime is unavailable");
                return false;
            }
            uint64_t next = 0;
            if (!up_rec_runtime_handle(state, pc, &next)) {
                return false;
            }
            pc = next;
            continue;
        }
        const up_rec_block *block = NULL;
        if (!up_rec_sinf_entry_lookup(state, pc, &block)) {
            up_rec_detail(state, "sinf-entry CFG reached unknown block %#llx",
                          (unsigned long long)pc);
            return false;
        }
        uint64_t next = 0;
        bool stopped = false;
        if (!up_rec_run_block(state, block, &next, &stopped)) {
            return up_rec_wrap(state, "compact SINF-entry CFG", pc);
        }
        if (stopped) {
            return true;
        }
        pc = next;
    }
    up_rec_detail(state, "sinf-entry CFG exceeded %d blocks; pc=%#llx", max_blocks,
                  (unsigned long long)pc);
    return false;
}

// MARK: - Named kernels

static bool up_rec_run_named_kernel(up_rec_state *state, const char *name) {
    const up_rec_kernel *kernel = up_rec_kernel_named(state->profile, name);
    if (kernel == NULL) {
        up_rec_detail(state, "recovery kernel \"%s\" is missing", name);
        return false;
    }
    return up_rec_run_kernel(state, kernel);
}

bool up_rec_run_optional(up_rec_state *state) {
    return up_rec_run_named_kernel(state, "optional");
}

static bool up_rec_cycle_boundary(up_rec_state *state, bool *exit) {
    if (!up_rec_run_named_kernel(state, "cycle")) {
        return false;
    }
    if (state->x[9] == state->profile->cycle_final) {
        if (!up_rec_run_named_kernel(state, "cycle-final")) {
            return false;
        }
    }
    if (state->x[9] == state->profile->outer_start) {
        *exit = false;
        return true;
    }
    *exit = state->x[8] != state->profile->outer_start;
    return true;
}

bool up_rec_run_kernel_iteration(up_rec_state *state, const char *kernel, bool *exit) {
    *exit = false;
    bool ok = false;
    if (strcmp(kernel, "account-cfg") == 0) {
        ok = up_rec_run_account_entry_cfg(state, 1000000);
        *exit = true;
    } else if (strcmp(kernel, "bootstrap") == 0) {
        ok = up_rec_run_named_kernel(state, "account-bootstrap");
        *exit = state->x[3] != state->profile->bootstrap_start;
    } else if (strcmp(kernel, "bootstrap-cfg") == 0) {
        ok = up_rec_run_bootstrap_cfg(state, 1000000);
        *exit = true;
    } else if (strcmp(kernel, "writer") == 0) {
        *exit = (uint32_t)state->x[1] + UINT32_C(0x9FCE627E) > UINT32_C(0xC7);
        ok = up_rec_run_named_kernel(state, "writer");
    } else if (strcmp(kernel, "tail") == 0) {
        *exit = (uint32_t)state->x[3] + UINT32_C(0x9FCE627E) >= UINT32_C(0x12C);
        ok = up_rec_run_named_kernel(state, "tail");
    } else if (strcmp(kernel, "even") == 0) {
        *exit = (uint32_t)state->x[12] + UINT32_C(2) > UINT32_C(0x63);
        ok = up_rec_run_named_kernel(state, "even");
    } else if (strcmp(kernel, "odd") == 0) {
        *exit = (uint32_t)state->x[1] + UINT32_C(0x9FCE627F) > UINT32_C(0x64);
        ok = up_rec_run_named_kernel(state, "odd");
    } else if (strcmp(kernel, "digest") == 0) {
        ok = up_rec_run_named_kernel(state, "digest");
    } else if (strcmp(kernel, "outer") == 0) {
        ok = up_rec_run_named_kernel(state, "outer");
        if (ok && state->x[12] == state->profile->outer_cycle) {
            ok = up_rec_cycle_boundary(state, exit);
        } else if (ok) {
            *exit = state->x[12] != state->profile->outer_start;
        }
    } else if (strcmp(kernel, "cycle") == 0) {
        ok = up_rec_cycle_boundary(state, exit);
    } else if (strcmp(kernel, "outer-primary") == 0) {
        ok = up_rec_run_named_kernel(state, "outer");
        *exit = state->x[12] != state->profile->outer_start;
    } else {
        up_rec_detail(state, "unknown raw source kernel \"%s\"", kernel);
        return false;
    }
    if (!ok) {
        return false;
    }
    if (strcmp(kernel, "digest") == 0) {
        *exit = state->z;
        if (!*exit) {
            return up_rec_run_named_kernel(state, "digest-prologue");
        }
    }
    return true;
}

bool up_rec_run_kernel_loop(up_rec_state *state, const char *kernel, int *iterations) {
    *iterations = 0;
    const char *step = kernel;
    if (strcmp(kernel, "digest-natural") == 0) {
        if (!up_rec_run_named_kernel(state, "digest-prologue")) {
            return false;
        }
        step = "digest";
    }
    int limit = 1024;
    if (strcmp(step, "bootstrap") == 0) {
        limit = 200000;
    }
    for (int count = 1; count <= limit; count++) {
        bool exit = false;
        if (!up_rec_run_kernel_iteration(state, step, &exit)) {
            *iterations = count - 1;
            return false;
        }
        if (exit) {
            *iterations = count;
            return true;
        }
    }
    *iterations = limit;
    up_rec_detail(state, "raw source writer loop did not reach its bounded exit");
    return false;
}

// MARK: - Frame dispatch

bool up_rec_apply_frame(up_rec_state *state, uint64_t *next) {
    const uint64_t input_address = UINT64_C(0x7000000fb524);
    const uint64_t output_address = UINT64_C(0x7000000fb724);
    uint8_t input[16];
    if (!up_rec_state_output_bytes(state, input_address, input, sizeof(input))) {
        return false;
    }
    uint8_t output[16];
    uint32_t exit_word = 0;
    if (!up_rec_frame_transform(state, input, output, &exit_word)) {
        return false;
    }
    if (!up_rec_state_store(state, output_address, output, sizeof(output))) {
        return false;
    }
    static const uint64_t registers[31] = {
        UINT64_C(0x21), UINT64_C(0x4b), UINT64_C(0x101074000), UINT64_C(0x7000000ffcc8),
        UINT64_C(0x7000000fb724), UINT64_C(0x101075b40), UINT64_C(0xa6), UINT64_C(0xa5cd4cf),
        UINT64_C(0x10030db7c), UINT64_C(0x5f79), UINT64_C(0x12), UINT64_C(0),
        UINT64_C(5), UINT64_C(0x100f4feb0), UINT64_C(0x5b), UINT64_C(0),
        UINT64_C(0x100f86660), UINT64_C(0x57c9), UINT64_C(0), UINT64_C(0xb1),
        UINT64_C(0x44), UINT64_C(0x53), UINT64_C(0x10105b6f0), UINT64_C(0x100d61250),
        UINT64_C(0x28), UINT64_C(0xb5), UINT64_C(0), UINT64_C(0x76),
        UINT64_C(0x73), UINT64_C(0x7000000ffdd0), UINT64_C(0xda)
    };
    memcpy(state->x, registers, sizeof(registers));
    state->x[26] = (uint64_t)exit_word;
    state->x[31] = 0;
    state->n = false;
    state->z = false;
    state->c = false;
    state->v = false;
    *next = UINT64_C(0x10030db7c);
    return true;
}

// MARK: - Runtime externals

typedef struct {
    char *suffix;
    uint8_t *data;
    size_t length;
} up_rec_mapping;

static bool up_rec_has_suffix(const char *path, const char *suffix) {
    size_t path_length = strlen(path);
    size_t suffix_length = strlen(suffix);
    if (suffix_length > path_length) {
        return false;
    }
    return memcmp(path + path_length - suffix_length, suffix, suffix_length) == 0;
}

static up_rec_open_file *up_rec_open_file_find(up_rec_runtime *runtime, uint64_t fd) {
    for (size_t index = 0; index < runtime->open_count; index++) {
        if (runtime->open_files[index].fd == fd) {
            return &runtime->open_files[index];
        }
    }
    return NULL;
}

static void up_rec_open_file_remove(up_rec_runtime *runtime, uint64_t fd) {
    for (size_t index = 0; index < runtime->open_count; index++) {
        if (runtime->open_files[index].fd == fd) {
            memmove(&runtime->open_files[index], &runtime->open_files[index + 1],
                    (runtime->open_count - index - 1) * sizeof(up_rec_open_file));
            runtime->open_count--;
            return;
        }
    }
}

static bool up_rec_open_file_add(up_rec_runtime *runtime, uint64_t fd, const uint8_t *data,
                                 size_t length) {
    if (runtime->open_count == runtime->open_capacity) {
        size_t capacity = runtime->open_capacity == 0 ? 8 : runtime->open_capacity * 2;
        up_rec_open_file *grown = realloc(runtime->open_files, capacity * sizeof(up_rec_open_file));
        if (grown == NULL) {
            return false;
        }
        runtime->open_files = grown;
        runtime->open_capacity = capacity;
    }
    runtime->open_files[runtime->open_count].fd = fd;
    runtime->open_files[runtime->open_count].data = data;
    runtime->open_files[runtime->open_count].length = length;
    runtime->open_files[runtime->open_count].offset = 0;
    runtime->open_count++;
    return true;
}

static bool up_rec_matching_file(const up_rec_runtime *runtime, const char *path,
                                 const uint8_t **data, size_t *length) {
    const char *best = NULL;
    const up_rec_file *match = NULL;
    for (size_t index = 0; index < runtime->file_count; index++) {
        const up_rec_file *file = &runtime->files[index];
        if (!up_rec_has_suffix(path, file->suffix)) {
            continue;
        }
        if (best == NULL || strlen(file->suffix) > strlen(best)) {
            best = file->suffix;
            match = file;
        }
    }
    if (match == NULL) {
        return false;
    }
    *data = match->data;
    *length = match->length;
    return true;
}

static bool up_rec_write_stat(up_rec_state *state, uint64_t address, size_t size) {
    uint8_t data[144];
    memset(data, 0, sizeof(data));
    data[4] = 0xA4;
    data[5] = 0x81;
    data[6] = 0x01;
    data[7] = 0x00;
    uint64_t value = (uint64_t)size;
    for (int index = 0; index < 8; index++) {
        data[96 + index] = (uint8_t)(value >> (unsigned)(index * 8));
    }
    return up_rec_state_store(state, address, data, sizeof(data));
}

static bool up_rec_set_errno(up_rec_state *state, uint32_t value) {
    return up_rec_state_store_value(state, UP_REC_ERRNO_ADDRESS, value, 4);
}

static bool up_rec_allocate(up_rec_state *state, uint64_t size, uint64_t *address) {
    up_rec_runtime *runtime = state->runtime;
    if (size > UINT64_C(0x10000000)) {
        up_rec_detail(state, "invalid bootstrap allocation size %#llx", (unsigned long long)size);
        return false;
    }
    *address = runtime->next_allocation;
    runtime->next_allocation += UINT64_C(0x100000);
    uint64_t rounded = (size == 0 ? 1 : size) + UP_REC_PAGE_SIZE - 1;
    rounded &= ~(UP_REC_PAGE_SIZE - 1);
    if (rounded < UINT64_C(0x100000)) {
        rounded = UINT64_C(0x100000);
    }
    return up_rec_state_map_zero(state, *address, rounded);
}

static up_rec_once_token *up_rec_token_find(up_rec_runtime *runtime, uint64_t token) {
    for (size_t index = 0; index < runtime->token_count; index++) {
        if (runtime->tokens[index].token == token) {
            return &runtime->tokens[index];
        }
    }
    return NULL;
}

static bool up_rec_token_add(up_rec_runtime *runtime, uint64_t token) {
    if (runtime->token_count == runtime->token_capacity) {
        size_t capacity = runtime->token_capacity == 0 ? 8 : runtime->token_capacity * 2;
        up_rec_once_token *grown = realloc(runtime->tokens, capacity * sizeof(up_rec_once_token));
        if (grown == NULL) {
            return false;
        }
        runtime->tokens = grown;
        runtime->token_capacity = capacity;
    }
    runtime->tokens[runtime->token_count].token = token;
    runtime->tokens[runtime->token_count].taken = true;
    runtime->token_count++;
    return true;
}

static uint32_t up_rec_iterator_take(up_rec_runtime *runtime, uint32_t iterator) {
    for (size_t index = 0; index < runtime->iterator_count; index++) {
        if (runtime->iterators[index].pc == (uint64_t)iterator) {
            uint32_t service = (uint32_t)runtime->iterators[index].service;
            memmove(&runtime->iterators[index], &runtime->iterators[index + 1],
                    (runtime->iterator_count - index - 1) * sizeof(up_rec_iterator));
            runtime->iterator_count--;
            return service;
        }
    }
    return 0;
}

static bool up_rec_iterator_add(up_rec_runtime *runtime, uint32_t iterator, uint32_t service) {
    if (runtime->iterator_count == runtime->iterator_capacity) {
        size_t capacity = runtime->iterator_capacity == 0 ? 8 : runtime->iterator_capacity * 2;
        up_rec_iterator *grown = realloc(runtime->iterators, capacity * sizeof(up_rec_iterator));
        if (grown == NULL) {
            return false;
        }
        runtime->iterators = grown;
        runtime->iterator_capacity = capacity;
    }
    runtime->iterators[runtime->iterator_count].pc = iterator;
    runtime->iterators[runtime->iterator_count].service = service;
    runtime->iterator_count++;
    return true;
}

static up_rec_cf_value *up_rec_value_find(up_rec_runtime *runtime, uint64_t address) {
    for (size_t index = 0; index < runtime->value_count; index++) {
        if (runtime->values[index].address == address) {
            return &runtime->values[index];
        }
    }
    return NULL;
}

static void up_rec_value_remove(up_rec_runtime *runtime, uint64_t address) {
    for (size_t index = 0; index < runtime->value_count; index++) {
        if (runtime->values[index].address == address) {
            memmove(&runtime->values[index], &runtime->values[index + 1],
                    (runtime->value_count - index - 1) * sizeof(up_rec_cf_value));
            runtime->value_count--;
            return;
        }
    }
}

static up_rec_cf_value *up_rec_value_add(up_rec_runtime *runtime, uint64_t address) {
    if (runtime->value_count == runtime->value_capacity) {
        size_t capacity = runtime->value_capacity == 0 ? 8 : runtime->value_capacity * 2;
        up_rec_cf_value *grown = realloc(runtime->values, capacity * sizeof(up_rec_cf_value));
        if (grown == NULL) {
            return NULL;
        }
        runtime->values = grown;
        runtime->value_capacity = capacity;
    }
    up_rec_cf_value *value = &runtime->values[runtime->value_count++];
    memset(value, 0, sizeof(*value));
    value->address = address;
    return value;
}

bool up_rec_runtime_handle(up_rec_state *state, uint64_t pc, uint64_t *next) {
    up_rec_runtime *runtime = state->runtime;
    uint64_t return_address = state->x[30];
    *next = return_address;
    switch (pc) {
    case UINT64_C(0xF100000000006000): // free
    case UINT64_C(0xF1000000000E4000): // chkstk_darwin
        return true;
    case UINT64_C(0xF100000000007000): { // malloc
        uint64_t address = 0;
        if (!up_rec_allocate(state, state->x[0], &address)) {
            return false;
        }
        state->x[0] = address;
        return true;
    }
    case UINT64_C(0xF10000000001F000): { // open
        char *path = malloc(UP_REC_PATH_LIMIT + 1);
        if (path == NULL) {
            up_rec_detail(state, "out of memory reading a runtime path");
            return false;
        }
        bool ok = up_rec_state_read_cstring(state, state->x[0], UP_REC_PATH_LIMIT, path,
                                            UP_REC_PATH_LIMIT + 1);
        const uint8_t *data = NULL;
        size_t length = 0;
        bool matched = ok && up_rec_matching_file(runtime, path, &data, &length);
        free(path);
        if (!ok) {
            return false;
        }
        if (!matched) {
            if (!up_rec_set_errno(state, 2)) {
                return false;
            }
            state->x[0] = UINT64_C(0xFFFFFFFF);
            return true;
        }
        uint64_t fd = runtime->next_fd++;
        if (!up_rec_open_file_add(runtime, fd, data, length)) {
            up_rec_detail(state, "out of memory tracking an opened file");
            return false;
        }
        state->x[0] = fd;
        return true;
    }
    case UINT64_C(0xF10000000004D000): { // fstat
        up_rec_open_file *entry = up_rec_open_file_find(runtime, state->x[0]);
        if (entry == NULL) {
            if (!up_rec_set_errno(state, 9)) {
                return false;
            }
            state->x[0] = UINT64_C(0xFFFFFFFF);
            return true;
        }
        if (!up_rec_write_stat(state, state->x[1], entry->length)) {
            return false;
        }
        state->x[0] = 0;
        return true;
    }
    case UINT64_C(0xF100000000023000): { // mmap
        up_rec_open_file *entry = up_rec_open_file_find(runtime, state->x[4]);
        if (entry == NULL) {
            state->x[0] = UINT64_MAX;
            return true;
        }
        uint64_t length = state->x[1];
        uint64_t accessible = (length + UINT64_C(0x3FFF)) & ~UINT64_C(0x3FFF);
        uint64_t address = 0;
        if (!up_rec_allocate(state, length, &address)) {
            return false;
        }
        uint64_t start = state->x[5] < entry->length ? state->x[5] : entry->length;
        uint64_t limit = start + accessible;
        if (limit < start) {
            limit = UINT64_MAX;
        }
        uint64_t end = limit < entry->length ? limit : entry->length;
        if (!up_rec_state_store(state, address, entry->data + start, (size_t)(end - start))) {
            return false;
        }
        state->x[0] = address;
        return true;
    }
    case UINT64_C(0xF100000000050000): // munmap
        state->x[0] = 0;
        return true;
    case UINT64_C(0xF10000000001A000): // close
        up_rec_open_file_remove(runtime, state->x[0]);
        state->x[0] = 0;
        return true;
    case UINT64_C(0xF10000000006E000): { // lstat
        char *path = malloc(UP_REC_PATH_LIMIT + 1);
        if (path == NULL) {
            up_rec_detail(state, "out of memory reading a runtime path");
            return false;
        }
        bool ok = up_rec_state_read_cstring(state, state->x[0], UP_REC_PATH_LIMIT, path,
                                            UP_REC_PATH_LIMIT + 1);
        const uint8_t *data = NULL;
        size_t length = 0;
        bool matched = ok && up_rec_matching_file(runtime, path, &data, &length);
        free(path);
        if (!ok) {
            return false;
        }
        if (!matched) {
            if (!up_rec_set_errno(state, 2)) {
                return false;
            }
            state->x[0] = UINT64_C(0xFFFFFFFF);
            return true;
        }
        if (!up_rec_write_stat(state, state->x[1], length)) {
            return false;
        }
        state->x[0] = 0;
        return true;
    }
    case UINT64_C(0xF100000000008000): { // read
        up_rec_open_file *entry = up_rec_open_file_find(runtime, state->x[0]);
        if (entry == NULL) {
            if (!up_rec_set_errno(state, 9)) {
                return false;
            }
            state->x[0] = UINT64_C(0xFFFFFFFF);
            return true;
        }
        uint64_t count = state->x[2] < UP_REC_MAX_BOOTSTRAP_READ ? state->x[2]
                                                                 : UP_REC_MAX_BOOTSTRAP_READ;
        uint64_t start = entry->offset < entry->length ? entry->offset : entry->length;
        uint64_t limit = start + count;
        if (limit < start) {
            limit = UINT64_MAX;
        }
        uint64_t end = limit < entry->length ? limit : entry->length;
        if (!up_rec_state_store(state, state->x[1], entry->data + start, (size_t)(end - start))) {
            return false;
        }
        entry->offset = end;
        state->x[0] = end - start;
        return true;
    }
    case UINT64_C(0xF10000000001B000): // __error
        state->x[0] = UP_REC_ERRNO_ADDRESS;
        return true;
    case UINT64_C(0xF100000000003000): // gettimeofday
        if (state->x[0] != 0) {
            if (!up_rec_state_store_value(state, state->x[0], UINT64_C(1700000000), 8)) {
                return false;
            }
            if (!up_rec_state_store_value(state, state->x[0] + 8, 0, 8)) {
                return false;
            }
        }
        state->x[0] = 0;
        return true;
    case UINT64_C(0xF10000000002F000): // IOMainPort
        if (state->x[1] != 0) {
            if (!up_rec_state_store_value(state, state->x[1], 1, 4)) {
                return false;
            }
        }
        state->x[0] = 0;
        return true;
    case UINT64_C(0xF1000000000A1000): // IOBSDNameMatching
        state->x[0] = UINT64_C(0x710200000000);
        return true;
    case UINT64_C(0xF100000000043000): { // IOServiceGetMatchingServices
        uint32_t iterator = runtime->next_iterator++;
        uint32_t service = runtime->next_service++;
        if (!up_rec_iterator_add(runtime, iterator, service)) {
            up_rec_detail(state, "out of memory tracking an IO iterator");
            return false;
        }
        if (!up_rec_state_store_value(state, state->x[2], iterator, 4)) {
            return false;
        }
        state->x[0] = 0;
        return true;
    }
    case UINT64_C(0xF10000000002C000): { // IOIteratorNext
        uint32_t iterator = (uint32_t)state->x[0];
        state->x[0] = up_rec_iterator_take(runtime, iterator);
        return true;
    }
    case UINT64_C(0xF10000000004E000): { // IORegistryEntryCreateCFProperty
        uint64_t key_pointer = 0;
        if (!up_rec_state_load(state, state->x[1] + 16, 8, &key_pointer)) {
            return false;
        }
        uint64_t key_length = 0;
        if (!up_rec_state_load(state, state->x[1] + 24, 8, &key_length) ||
            key_length > UINT64_C(0x1000)) {
            up_rec_detail(state, "invalid IOKit property key");
            return false;
        }
        uint8_t key[0x1001];
        if (!up_rec_state_output_bytes(state, key_pointer, key, (size_t)key_length)) {
            return false;
        }
        key[key_length] = '\0';
        uint64_t value_address = 0;
        if (!up_rec_allocate(state, 1, &value_address)) {
            return false;
        }
        if (key_length == 9 && memcmp(key, "IOBuiltin", 9) == 0) {
            up_rec_cf_value *value = up_rec_value_add(runtime, value_address);
            if (value == NULL) {
                up_rec_detail(state, "out of memory modeling an IOKit property");
                return false;
            }
            value->is_boolean = true;
            value->flag = true;
        } else if (key_length == 12 && memcmp(key, "IOMACAddress", 12) == 0) {
            if (!runtime->has_mac) {
                up_rec_detail(state, "bootstrap CFG requires --raw-source-mac");
                return false;
            }
            up_rec_cf_value *value = up_rec_value_add(runtime, value_address);
            if (value == NULL) {
                up_rec_detail(state, "out of memory modeling an IOKit property");
                return false;
            }
            memcpy(value->data, runtime->mac, 6);
            value->length = 6;
        } else {
            up_rec_detail(state, "unsupported IOKit property \"%s\"", (const char *)key);
            return false;
        }
        state->x[0] = value_address;
        return true;
    }
    case UINT64_C(0xF10000000000C000): { // CFBooleanGetValue
        up_rec_cf_value *value = up_rec_value_find(runtime, state->x[0]);
        if (value == NULL || !value->is_boolean) {
            up_rec_detail(state, "invalid modeled CFBoolean");
            return false;
        }
        state->x[0] = value->flag ? 1 : 0;
        return true;
    }
    case UINT64_C(0xF100000000019000): // CFRelease
        up_rec_value_remove(runtime, state->x[0]);
        return true;
    case UINT64_C(0xF1000000000A2000): { // IORegistryEntryGetParentEntry
        uint32_t parent = runtime->next_service++;
        if (!up_rec_state_store_value(state, state->x[2], parent, 4)) {
            return false;
        }
        state->x[0] = 0;
        return true;
    }
    case UINT64_C(0xF10000000007C000): { // CFDataGetBytes
        up_rec_cf_value *value = up_rec_value_find(runtime, state->x[0]);
        if (value == NULL || value->is_boolean) {
            up_rec_detail(state, "invalid modeled CFData");
            return false;
        }
        uint64_t start = state->x[1] < value->length ? state->x[1] : value->length;
        uint64_t limit = start + state->x[2];
        if (limit < start) {
            limit = UINT64_MAX;
        }
        uint64_t end = limit < value->length ? limit : value->length;
        if (!up_rec_state_store(state, state->x[3], value->data + start, (size_t)(end - start))) {
            return false;
        }
        return true;
    }
    case UINT64_C(0xF100000000034000): // IOObjectRelease
        state->x[0] = 0;
        return true;
    case UINT64_C(0xF100000000025000): { // pthread_once
        up_rec_once_token *token = up_rec_token_find(runtime, state->x[0]);
        if (token != NULL && token->taken) {
            // Model the private reference runner's tiny stub, including the
            // otherwise-dead stack spill so checkpoints stay byte-exact.
            uint64_t stack = state->sp - 16;
            if (!up_rec_state_store_value(state, stack, state->x[29], 8)) {
                return false;
            }
            if (!up_rec_state_store_value(state, stack + 8, state->x[30], 8)) {
                return false;
            }
            state->x[1] = UP_REC_PTHREAD_STUB;
            state->x[0] = 0;
            return true;
        }
        if (!up_rec_token_add(runtime, state->x[0])) {
            up_rec_detail(state, "out of memory tracking a pthread_once token");
            return false;
        }
        return true;
    }
    case UINT64_C(0xF10000000002500C): // initialized pthread_once callback
    case UINT64_C(0x720000000000):     // initialized pthread_once callback
        return true;
    case UINT64_C(0xF10000000000E000): // pthread_rwlock_unlock
    case UINT64_C(0xF100000000040000): // pthread_rwlock_rdlock
    case UINT64_C(0xF10000000005C000): // pthread_rwlock_init
    case UINT64_C(0xF100000000065000): // pthread_rwlock_wrlock
        state->x[0] = 0;
        return true;
    default:
        up_rec_detail(state, "unsupported bootstrap external %#llx", (unsigned long long)pc);
        return false;
    }
}

// MARK: - Runtime configuration

static bool up_rec_read_private_file(up_context *ctx, const char *path, uint8_t **data,
                                     size_t *length) {
    struct stat info;
    if (lstat(path, &info) != 0) {
        return up_fail(ctx, "read recovery input %s", path);
    }
    if (!S_ISREG(info.st_mode) || (info.st_mode & 077) != 0) {
        return up_fail(ctx, "recovery input must be a mode-0600 regular file: %s", path);
    }
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return up_fail(ctx, "read recovery input %s", path);
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return up_fail(ctx, "read recovery input %s", path);
    }
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return up_fail(ctx, "read recovery input %s", path);
    }
    uint8_t *bytes = malloc((size_t)size == 0 ? 1 : (size_t)size);
    if (bytes == NULL) {
        fclose(file);
        return up_fail(ctx, "out of memory reading %s", path);
    }
    size_t read = fread(bytes, 1, (size_t)size, file);
    fclose(file);
    if (read != (size_t)size) {
        free(bytes);
        return up_fail(ctx, "read recovery input %s", path);
    }
    *data = bytes;
    *length = (size_t)size;
    return true;
}

static int up_rec_hex_digit(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

bool up_rec_runtime_configure(up_context *ctx, up_rec_state *state, const char *kernel,
                              const char *const *mappings, size_t mapping_count,
                              const char *hardware_path, const char *executable_path,
                              uint64_t stop_pc) {
    bool runtime_kernel = strcmp(kernel, "account-cfg") == 0 ||
                          strcmp(kernel, "enrollment-full") == 0 ||
                          strcmp(kernel, "enrollment-frame") == 0 ||
                          strcmp(kernel, "enrollment-sinf") == 0 ||
                          strcmp(kernel, "bootstrap-cfg") == 0 ||
                          strcmp(kernel, "bootstrap-full") == 0;
    if (!runtime_kernel) {
        if (mapping_count != 0 || (hardware_path != NULL && hardware_path[0] != '\0') ||
            (executable_path != NULL && executable_path[0] != '\0') || stop_pc != 0) {
            return up_fail(ctx, "raw source runtime inputs require an account or bootstrap CFG kernel");
        }
        return true;
    }
    up_rec_profile *profile = state->profile;
    if (memcmp(state->model->binary_hash, profile->binary_hash, 32) != 0) {
        return up_fail(ctx, "raw source model does not match generated fairplayd build");
    }
    up_rec_runtime *runtime = calloc(1, sizeof(up_rec_runtime));
    if (runtime == NULL) {
        return up_fail(ctx, "out of memory configuring the recovery runtime");
    }
    runtime->next_fd = 100;
    runtime->next_allocation = UINT64_C(0x710100000000);
    runtime->next_iterator = 0x100;
    runtime->next_service = 0x200;
    runtime->stop_pc = stop_pc;
    for (size_t index = 0; index < profile->once_token_count; index++) {
        if (!up_rec_token_add(runtime, profile->once_tokens[index])) {
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "out of memory configuring the recovery runtime");
        }
    }
    uint64_t maximum = 0;
    for (size_t index = 0; index < state->model->page_count; index++) {
        uint64_t address = state->model->pages[index].address;
        if (address >= UINT64_C(0x700010000000) && address < UINT64_C(0x700020000000) &&
            address > maximum) {
            maximum = address;
        }
    }
    if (maximum != 0) {
        runtime->next_allocation = (maximum + UINT64_C(0x100000)) & ~UINT64_C(0xFFFFF);
    }
    bool account_kernel = strcmp(kernel, "account-cfg") == 0 ||
                          strcmp(kernel, "enrollment-full") == 0 ||
                          strcmp(kernel, "enrollment-frame") == 0 ||
                          strcmp(kernel, "enrollment-sinf") == 0;
    if (account_kernel) {
        if (executable_path == NULL || executable_path[0] == '\0' ||
            strlen(executable_path) >= UP_REC_PAGE_SIZE) {
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "account-entry parser requires a bounded installed executable path");
        }
        size_t length = strlen(executable_path) + 1;
        uint8_t *patched = malloc(length);
        if (patched == NULL) {
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "out of memory preparing the installed executable path");
        }
        memcpy(patched, executable_path, length);
        bool patched_ok = up_rec_state_patch(state, UINT64_C(0x700000200000), patched, length);
        free(patched);
        if (!patched_ok) {
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "%s", state->detail);
        }
    } else if (executable_path != NULL && executable_path[0] != '\0') {
        up_rec_runtime_release(runtime);
        return up_fail(ctx, "installed executable path is only valid with an account CFG kernel");
    }
    if (!up_rec_state_map_zero(state, UP_REC_ERRNO_ADDRESS, UP_REC_PAGE_SIZE)) {
        up_rec_runtime_release(runtime);
        return up_fail(ctx, "%s", state->detail);
    }
    for (size_t index = 0; index < mapping_count; index++) {
        const char *specification = mappings[index];
        const char *separator = strchr(specification, '=');
        if (separator == NULL || separator == specification || separator[1] == '\0') {
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "invalid raw source file mapping \"%s\"", specification);
        }
        size_t suffix_length = (size_t)(separator - specification);
        char *suffix = malloc(suffix_length + 1);
        if (suffix == NULL) {
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "out of memory reading raw source file mappings");
        }
        memcpy(suffix, specification, suffix_length);
        suffix[suffix_length] = '\0';
        for (size_t existing = 0; existing < runtime->file_count; existing++) {
            if (strcmp(runtime->files[existing].suffix, suffix) == 0) {
                up_fail(ctx, "duplicate raw source file mapping \"%s\"", suffix);
                free(suffix);
                up_rec_runtime_release(runtime);
                return false;
            }
        }
        uint8_t *data = NULL;
        size_t length = 0;
        if (!up_rec_read_private_file(ctx, separator + 1, &data, &length)) {
            free(suffix);
            up_rec_runtime_release(runtime);
            return false;
        }
        up_rec_file *grown = realloc(runtime->files,
                                     (runtime->file_count + 1) * sizeof(up_rec_file));
        if (grown == NULL) {
            free(data);
            free(suffix);
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "out of memory reading raw source file mappings");
        }
        runtime->files = grown;
        runtime->files[runtime->file_count].suffix = suffix;
        runtime->files[runtime->file_count].data = data;
        runtime->files[runtime->file_count].length = length;
        runtime->file_count++;
    }
    if (hardware_path != NULL && hardware_path[0] != '\0') {
        uint8_t *data = NULL;
        size_t length = 0;
        if (!up_rec_read_private_file(ctx, hardware_path, &data, &length)) {
            up_rec_runtime_release(runtime);
            return false;
        }
        bool valid = true;
        if (length != 6) {
            char digits[64];
            size_t digits_length = 0;
            for (size_t index = 0; index < length && digits_length < sizeof(digits); index++) {
                char value = (char)data[index];
                if (value == ':' || value == '-' || value == ' ' || value == '\t' ||
                    value == '\n' || value == '\r') {
                    continue;
                }
                digits[digits_length++] = value;
            }
            if (digits_length != 12) {
                valid = false;
            } else {
                for (size_t index = 0; index < 6 && valid; index++) {
                    int high = up_rec_hex_digit(digits[index * 2]);
                    int low = up_rec_hex_digit(digits[index * 2 + 1]);
                    if (high < 0 || low < 0) {
                        valid = false;
                    } else {
                        runtime->mac[index] = (uint8_t)(high << 4 | low);
                    }
                }
            }
        } else {
            memcpy(runtime->mac, data, 6);
        }
        free(data);
        if (!valid) {
            up_rec_runtime_release(runtime);
            return up_fail(ctx, "raw source hardware address must contain six bytes");
        }
        runtime->has_mac = true;
    }
    state->runtime = runtime;
    return true;
}

void up_rec_runtime_release(up_rec_runtime *runtime) {
    if (runtime == NULL) {
        return;
    }
    for (size_t index = 0; index < runtime->file_count; index++) {
        free(runtime->files[index].suffix);
        free(runtime->files[index].data);
    }
    free(runtime->files);
    free(runtime->open_files);
    free(runtime->tokens);
    free(runtime->iterators);
    free(runtime->values);
    free(runtime);
}

// MARK: - Reference pages

static uint32_t up_rec_macho_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static uint64_t up_rec_macho_u64(const uint8_t *bytes) {
    return (uint64_t)up_rec_macho_u32(bytes) | (uint64_t)up_rec_macho_u32(bytes + 4) << 32;
}

static bool up_rec_reference_text(const uint8_t *blob, size_t length, uint64_t *address,
                                  const uint8_t **payload, size_t *payload_length) {
    if (length < 32) {
        return false;
    }
    uint32_t magic = up_rec_macho_u32(blob);
    if (magic != UINT32_C(0xFEEDFACF)) {
        return false;
    }
    uint32_t cpu_type = up_rec_macho_u32(blob + 4);
    if (cpu_type != UINT32_C(0x0100000C)) {
        return false;
    }
    uint32_t command_count = up_rec_macho_u32(blob + 16);
    uint32_t command_bytes = up_rec_macho_u32(blob + 20);
    if (command_bytes > length - 32) {
        return false;
    }
    size_t offset = 32;
    for (uint32_t index = 0; index < command_count; index++) {
        if (offset + 8 > length) {
            return false;
        }
        uint32_t command = up_rec_macho_u32(blob + offset);
        uint32_t size = up_rec_macho_u32(blob + offset + 4);
        if (size < 8 || size > length - offset) {
            return false;
        }
        if (command == UINT32_C(0x19) && size >= 72) {
            const uint8_t *segment = blob + offset;
            if (memcmp(segment + 8, "__TEXT", 7) == 0) {
                uint64_t vm_address = up_rec_macho_u64(segment + 24);
                uint64_t file_offset = up_rec_macho_u64(segment + 40);
                uint64_t file_size = up_rec_macho_u64(segment + 48);
                if (file_size == 0 || file_size > UINT64_C(32) * 1024 * 1024 ||
                    vm_address % UP_REC_PAGE_SIZE != 0 || file_offset > length ||
                    file_size > length - file_offset) {
                    return false;
                }
                *address = vm_address;
                *payload = blob + file_offset;
                *payload_length = (size_t)file_size;
                return true;
            }
        }
        offset += size;
    }
    return false;
}

bool up_rec_runtime_add_reference_pages(up_context *ctx, up_rec_model *model,
                                        up_rec_profile *profile, const char *path) {
    if (path == NULL || path[0] == '\0') {
        return true;
    }
    uint8_t *data = NULL;
    size_t length = 0;
    if (!up_rec_read_private_file(ctx, path, &data, &length)) {
        return false;
    }
    up_sha256_ctx *hash = up_sha256_create();
    if (hash == NULL) {
        free(data);
        return up_fail(ctx, "out of memory hashing the reference binary");
    }
    uint8_t digest[32];
    up_sha256_update(hash, data, length);
    up_sha256_final(hash, digest);
    up_sha256_release(hash);
    if (memcmp(digest, profile->binary_hash, 32) != 0) {
        free(data);
        return up_fail(ctx, "reference binary SHA256 mismatch");
    }
    uint64_t text_address = 0;
    const uint8_t *text = NULL;
    size_t text_length = 0;
    bool parsed = up_rec_reference_text(data, length, &text_address, &text, &text_length);
    if (!parsed) {
        free(data);
        return up_fail(ctx, "invalid reference text segment");
    }
    for (size_t offset = 0; offset < text_length; offset += UP_REC_PAGE_SIZE) {
        uint64_t address = text_address + offset;
        bool present = false;
        for (size_t index = 0; index < model->page_count; index++) {
            if (model->pages[index].address == address) {
                present = true;
                break;
            }
        }
        if (present) {
            continue;
        }
        uint8_t *page = calloc(1, UP_REC_PAGE_SIZE);
        if (page == NULL) {
            free(data);
            return up_fail(ctx, "out of memory adding reference pages");
        }
        size_t count = text_length - offset;
        if (count > UP_REC_PAGE_SIZE) {
            count = UP_REC_PAGE_SIZE;
        }
        memcpy(page, text + offset, count);
        size_t position = 0;
        while (position < model->page_count && model->pages[position].address < address) {
            position++;
        }
        up_rec_model_page *grown = realloc(model->pages,
                                           (model->page_count + 1) * sizeof(up_rec_model_page));
        if (grown == NULL) {
            free(page);
            free(data);
            return up_fail(ctx, "out of memory adding reference pages");
        }
        model->pages = grown;
        memmove(&model->pages[position + 1], &model->pages[position],
                (model->page_count - position) * sizeof(up_rec_model_page));
        model->pages[position].address = address;
        model->pages[position].page = page;
        model->page_count++;
    }
    free(data);
    model->allow_destination_pages = true;
    return true;
}
