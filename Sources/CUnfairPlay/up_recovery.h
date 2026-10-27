//
//  up_recovery.h
//  CUnfairPlay
//
//  Internal types for the native FairPlay recovery interpreter. The interpreter
//  consumes the same generated profile data as the Go reference
//  implementation: a captured model, a compact CFG profile, a compact semantic
//  frame profile, an exact-build extracted block profile, and a kernel table.
//
//  Nothing here is public API. The two entry points are declared at the end of
//  include/unfairplay.h so the Swift layer can drive one recovery run.
//

#ifndef UP_RECOVERY_H
#define UP_RECOVERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "up_internal.h"

#define UP_REC_PAGE_SIZE UINT64_C(0x1000)
#define UP_REC_MAX_PAGES 8192
#define UP_REC_MAX_DESTINATION_PAGES 32

/// One compact instruction. 10 bytes on disk; the struct is padded in memory.
typedef struct {
    uint16_t op;
    uint8_t destination;
    uint8_t left;
    uint8_t right;
    uint8_t accumulator;
    uint8_t shift;
    uint16_t immediate;
} up_rec_instruction;

typedef struct {
    uint32_t index;
    uint64_t address;
} up_rec_segment;

typedef struct {
    uint64_t after;
    uint8_t action;
} up_rec_hook;

typedef struct {
    char *name;
    uint64_t start;
    up_rec_instruction *instructions;
    size_t instruction_count;
    up_rec_segment *segments;
    size_t segment_count;
    up_rec_hook *hooks;
    size_t hook_count;
} up_rec_kernel;

typedef struct {
    uint64_t start;
    uint64_t target;
    uint64_t alternate;
    uint8_t terminator;
    uint8_t condition;
    uint8_t reg;
    uint8_t width;
    uint8_t bit;
    up_rec_instruction *instructions;
    size_t instruction_count;
} up_rec_block;

/// Sorted-by-start block table.
typedef struct {
    up_rec_block *blocks;
    size_t count;
} up_rec_blocks;

typedef struct {
    uint64_t account_entry_start, account_entry_stop;
    uint64_t bootstrap_start, bootstrap_stop;
    uint64_t selection_start, selection_stop;
    uint64_t sinf_entry_start, sinf_entry_stop;
    uint64_t selection_frame_call;
    int selection_stop_hits;
    uint64_t source_address, frame_address, sinf_frame_offset;
    uint64_t outer_start, outer_cycle, cycle_final, optional_start;
    uint8_t binary_hash[32];
    uint8_t current_sinf_mask[16];
    uint8_t current_sinf_white[16];
    uint8_t current_sinf_input[4096];
    uint64_t once_tokens[8];
    size_t once_token_count;

    // Block tables, all sorted by start. Empty tables have count 0.
    up_rec_blocks account_entry;
    up_rec_blocks bootstrap;
    up_rec_blocks selection;
    up_rec_blocks supplemental;
    up_rec_blocks verified;
    up_rec_blocks extracted;      // section 11, loaded on demand
    up_rec_blocks sinf_entry[6];

    up_rec_kernel kernels[11];
    size_t kernel_count;
} up_rec_profile;

/// Semantic frame model (profile version 2).
typedef struct {
    uint8_t baseline[16];
    uint8_t targets[16][4];
    uint8_t tables[16][256][4];
} up_rec_frame_round;

typedef struct {
    uint8_t input_count;
    uint8_t inputs[3];
    uint8_t baseline;
    uint8_t direct[256];
    uint8_t encode[256];
    uint8_t contributions[3][256];
} up_rec_frame_final;

typedef struct {
    bool loaded;
    uint8_t input_constant[16];
    uint8_t input_columns[128][16];
    up_rec_frame_round rounds[9];
    uint8_t exit_inputs[4];
    uint8_t exit_baseline[4];
    uint8_t exit_contributions[4][4][256];
    up_rec_frame_final final[16];
} up_rec_frame_profile;

typedef struct {
    uint64_t address;
    uint8_t *page;
} up_rec_model_page;

typedef struct {
    uint8_t *page;            // decompressed model bytes, owned
    size_t length;
    uint64_t block_address;
    uint64_t registers[32];
    uint64_t sp;
    bool n, z, c, v;
    uint8_t binary_hash[32];
    bool allow_destination_pages;
    up_rec_model_page *pages;
    size_t page_count;
} up_rec_model;

typedef struct {
    uint64_t address;
    uint8_t *page;
    uint8_t *initialized;     // only for destination pages
} up_rec_mapped;

typedef struct {
    uint64_t address;
    uint8_t *page;
    bool dirty;
} up_rec_writable;

typedef struct {
    uint64_t pc;
    uint64_t service;
} up_rec_iterator;

typedef struct {
    uint64_t address;
    bool is_boolean;
    bool flag;
    uint8_t data[6];
    size_t length;
} up_rec_cf_value;

typedef struct {
    char *suffix;
    uint8_t *data;
    size_t length;
} up_rec_file;

typedef struct {
    uint64_t fd;
    const uint8_t *data;
    size_t length;
    size_t offset;
} up_rec_open_file;

typedef struct {
    uint64_t token;
    bool taken;
} up_rec_once_token;

typedef struct {
    up_rec_file *files;
    size_t file_count;
    up_rec_open_file *open_files;
    size_t open_count, open_capacity;
    uint64_t next_fd;
    uint64_t next_allocation;
    uint8_t mac[6];
    bool has_mac;
    up_rec_once_token *tokens;
    size_t token_count, token_capacity;
    uint32_t next_iterator;
    uint32_t next_service;
    up_rec_iterator *iterators;
    size_t iterator_count, iterator_capacity;
    up_rec_cf_value *values;
    size_t value_count, value_capacity;
    uint64_t stop_pc;
} up_rec_runtime;

typedef struct {
    up_context *ctx;
    up_rec_model *model;
    up_rec_profile *profile;
    const up_rec_frame_profile *frame;
    up_rec_runtime *runtime;

    // Registers 0-30. Index 31 exists only so encodings that name the zero
    // register as a discard target cannot index out of bounds; it is never
    // read as input and is excluded from digests.
    uint64_t x[32];
    uint8_t vectors[32][16];
    uint64_t sp;
    bool n, z, c, v;

    up_rec_writable *writable;
    size_t writable_count, writable_capacity;
    uint64_t *touched;
    size_t touched_count, touched_capacity;
    up_rec_mapped *mapped;
    size_t mapped_count, mapped_capacity;
    size_t initialized_count;
    uint64_t *destination;
    size_t destination_count;

    int extracted_hits;

    /// Most recent memory error without the caller's prefix. Engine errors
    /// wrap this the way the Go reference wraps `page` failures.
    char detail[192];

    // Rolling trace over executed blocks. Used to compare the native port with
    // the Go reference byte for byte; it never affects execution.
    struct up_sha256_ctx *trace;
} up_rec_state;

// MARK: - Helpers shared by every translation unit

uint64_t up_rec_shift_left(uint64_t value, int amount, int width);
uint64_t up_rec_shift_right(uint64_t value, int amount, int width);
uint64_t up_rec_shift_right_arithmetic(uint64_t value, int amount, int width);
uint64_t up_rec_rotate_right(uint64_t value, int amount, int width);
uint64_t up_rec_bit_mask(int bits, int width);
uint64_t up_rec_insert_bits(uint64_t destination, uint64_t source, int lsb, int bits, int width);
uint64_t up_rec_extract_pair(uint64_t high, uint64_t low, int amount, int width);
uint64_t up_rec_add_offset(uint64_t value, int64_t offset);
uint64_t up_rec_sign_extend_bits(uint64_t value, int bits, int width);
uint64_t up_rec_sign_extend_32(uint32_t value);
uint64_t up_rec_unsigned_divide(uint64_t left, uint64_t right, int width);
uint64_t up_rec_multiply_high_64(uint64_t left, uint64_t right);
uint64_t up_rec_leading_zeros(uint64_t value, int width);
uint64_t up_rec_reverse_bytes_32(uint64_t value);
uint64_t up_rec_reverse_bytes_64(uint64_t value);

// MARK: - Profile asset loading

/// Parses the kernel table produced by the asset generator.
bool up_rec_load_kernels(up_context *ctx, const uint8_t *data, size_t length, up_rec_profile *profile);
/// Parses one `FPCFG1` compact profile and stores its sections.
bool up_rec_load_compact_profile(up_context *ctx, const uint8_t *data, size_t length,
                                 up_rec_blocks *account_entry, up_rec_blocks *bootstrap,
                                 up_rec_blocks *selection, up_rec_blocks *sinf_entry,
                                 up_rec_blocks *supplemental, up_rec_blocks *extracted);
bool up_rec_load_model(up_context *ctx, const uint8_t *data, size_t length, up_rec_model *model);
void up_rec_release_profile(up_rec_profile *profile);
void up_rec_release_model(up_rec_model *model);
void up_rec_release_frame_profile(up_rec_frame_profile *frame);

/// gzip decompression helper. The caller owns the result.
bool up_rec_gunzip(up_context *ctx, const uint8_t *data, size_t length, size_t limit,
                   uint8_t **decoded, size_t *decoded_length);

const up_rec_kernel *up_rec_kernel_named(const up_rec_profile *profile, const char *name);
const up_rec_block *up_rec_blocks_find(const up_rec_blocks *blocks, uint64_t address);

// MARK: - State and memory

bool up_rec_state_create(up_rec_state *state, up_rec_model *model, up_rec_profile *profile,
                         up_rec_runtime *runtime);
void up_rec_state_destroy(up_rec_state *state);
void up_rec_state_reset(up_rec_state *state);
bool up_rec_state_load(up_rec_state *state, uint64_t address, int size, uint64_t *value);
bool up_rec_state_store(up_rec_state *state, uint64_t address, const uint8_t *bytes, size_t length);
bool up_rec_state_store_value(up_rec_state *state, uint64_t address, uint64_t value, int size);
bool up_rec_state_map_zero(up_rec_state *state, uint64_t address, uint64_t size);
bool up_rec_state_read_cstring(up_rec_state *state, uint64_t address, size_t limit,
                               char *output, size_t output_size);
bool up_rec_state_output_bytes(up_rec_state *state, uint64_t address, uint8_t *output, size_t length);
bool up_rec_state_digest(up_rec_state *state, uint8_t output[32]);
bool up_rec_state_patch(up_rec_state *state, uint64_t base, const uint8_t *bytes, size_t length);
void up_rec_state_trace(up_rec_state *state, uint64_t pc);
bool up_rec_state_trace_finish(up_rec_state *state, uint8_t output[32]);

void up_rec_vector_lane(const up_rec_state *state, int reg, int lane, int bits, uint64_t *value);
void up_rec_vector_set_lane(up_rec_state *state, int reg, int lane, int bits, uint64_t value);
void up_rec_vector_clear(up_rec_state *state, int reg);

// MARK: - Interpretation

bool up_rec_run_kernel(up_rec_state *state, const up_rec_kernel *kernel);
bool up_rec_run_block(up_rec_state *state, const up_rec_block *block, uint64_t *next, bool *stopped);
int up_rec_condition_matches(up_rec_state *state, uint8_t condition);

// MARK: - CFG drivers

bool up_rec_run_account_entry_cfg(up_rec_state *state, int max_blocks);
bool up_rec_run_bootstrap_cfg(up_rec_state *state, int max_blocks);
bool up_rec_run_selection_cfg(up_rec_state *state, int max_blocks);
bool up_rec_run_sinf_entry_cfg(up_rec_state *state, int max_blocks);
bool up_rec_run_kernel_iteration(up_rec_state *state, const char *kernel, bool *exit);
bool up_rec_run_kernel_loop(up_rec_state *state, const char *kernel, int *iterations);
bool up_rec_run_optional(up_rec_state *state);
bool up_rec_apply_frame(up_rec_state *state, uint64_t *next);

// MARK: - Runtime externals

bool up_rec_runtime_handle(up_rec_state *state, uint64_t pc, uint64_t *next);
bool up_rec_runtime_configure(up_context *ctx, up_rec_state *state, const char *kernel,
                              const char *const *mappings, size_t mapping_count,
                              const char *hardware_path, const char *executable_path,
                              uint64_t stop_pc);
void up_rec_runtime_release(up_rec_runtime *runtime);
bool up_rec_runtime_add_reference_pages(up_context *ctx, up_rec_model *model,
                                        up_rec_profile *profile, const char *path);

// MARK: - Frame profile

bool up_rec_frame_parse(up_context *ctx, const uint8_t *data, size_t length, up_rec_frame_profile *frame);
bool up_rec_frame_transform(up_rec_state *state, const uint8_t input[16], uint8_t output[16],
                            uint32_t *exit_word);

#endif /* UP_RECOVERY_H */
