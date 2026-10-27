//
//  up_macho.h
//  CUnfairPlay
//
//  Mach-O inspection ported from internal/fairplay/macho.go. Only the parts
//  the decryptor and doctor need are implemented: slice geometry, the encrypted
//  range, instruction sections, and the embedded CodeDirectory audit.
//

#ifndef UP_MACHO_H
#define UP_MACHO_H

#include "up_internal.h"

#define UP_PAGE_BYTES 4096

typedef struct {
    uint64_t offset;
    uint64_t size;
    char segment[17];
    char section[17];
    uint32_t flags;
} up_macho_range;

typedef struct {
    uint32_t cpu_type;
    uint32_t cpu_subtype;
    uint32_t crypt_offset;
    uint32_t crypt_size;
    uint32_t crypt_id;
    int crypt_id_offset;
    uint32_t signature_offset;
    uint32_t signature_size;
    up_macho_range *ranges;
    size_t range_count;
} up_macho_layout;

typedef struct {
    uint64_t offset;
    uint64_t size;
    up_macho_layout layout;
} up_macho_slice;

void up_macho_layout_free(up_macho_layout *layout);
bool up_macho_layout_equal(const up_macho_layout *left, const up_macho_layout *right);

/// Human-readable architecture name for a CPU type/subtype pair.
void up_macho_architecture(uint32_t cpu_type, uint32_t cpu_subtype, char output[32]);

int up_parse_macho_slices(up_context *ctx,
                          const uint8_t *blob,
                          size_t blob_length,
                          uint64_t total_size,
                          up_macho_slice **slices,
                          size_t *count);

void up_macho_slices_free(up_macho_slice *slices, size_t count);

typedef struct {
    uint8_t hash_type;
    int hash_size;
    int page_size;
    int first_slot;
    int slot_count;
    int matched_slots;
} up_code_directory_audit;

int up_audit_code_directories(up_context *ctx,
                              const uint8_t *executable,
                              size_t length,
                              const up_macho_layout *layout,
                              up_code_directory_audit **audits,
                              size_t *count);

bool up_is_arm64_instruction_set(uint32_t cpu_type);

#endif /* UP_MACHO_H */
