//
//  up_supf.h
//  CUnfairPlay
//
//  SUPF page-key tables, ported from internal/fairplay/supf.go.
//

#ifndef UP_SUPF_H
#define UP_SUPF_H

#include "up_internal.h"

typedef struct {
    uint32_t cpu_type;
    uint32_t cpu_subtype;
    /// `record_count` records of 32 bytes: wrapped key (16) then IV (16).
    uint8_t *records;
    size_t record_count;
} up_supf_architecture;

typedef struct {
    up_supf_architecture *architectures;
    size_t count;
} up_supf_table;

int up_supf_parse(up_context *ctx, const uint8_t *blob, size_t length, up_supf_table *out);
void up_supf_free(up_supf_table *table);

/// Returns a pointer to the first record, or fails with the Go message.
int up_supf_records(const up_supf_table *table,
                    uint32_t cpu_type,
                    uint32_t cpu_subtype,
                    const uint8_t **records,
                    size_t *count);

#endif /* UP_SUPF_H */
