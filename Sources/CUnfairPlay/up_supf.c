//
//  up_supf.c
//  CUnfairPlay
//
//  Port of internal/fairplay/supf.go. Variants 3 and 5 are accepted; every
//  geometry check is kept in the same order as the Go source.
//

#include "up_supf.h"

static uint32_t up_supf_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

void up_supf_free(up_supf_table *table) {
    if (table == NULL) {
        return;
    }
    for (size_t index = 0; index < table->count; index++) {
        free(table->architectures[index].records);
    }
    free(table->architectures);
    table->architectures = NULL;
    table->count = 0;
}

int up_supf_parse(up_context *ctx, const uint8_t *blob, size_t length, up_supf_table *out) {
    memset(out, 0, sizeof(*out));
    if (length < 12) {
        return up_fail(ctx, "SUPF is truncated");
    }
    uint8_t variant = blob[0];
    if (variant != 3 && variant != 5) {
        return up_fail(ctx, "unsupported SUPF variant %d", (int)variant);
    }
    uint64_t outer_end = 8 + (uint64_t)up_supf_be32(blob + 4);
    if (outer_end > length) {
        return up_fail(ctx, "SUPF outer payload exceeds file");
    }
    uint32_t count = up_supf_be32(blob + 8);
    if (count == 0 || count > 32) {
        return up_fail(ctx, "SUPF architecture count is invalid");
    }
    size_t cursor = 12;
    up_supf_architecture *architectures = calloc(count, sizeof(up_supf_architecture));
    if (architectures == NULL) {
        return up_fail(ctx, "out of memory");
    }
    size_t architecture_count = 0;
    int status = 1;
    for (uint32_t index = 0; index < count; index++) {
        if ((uint64_t)cursor + 4 > outer_end) {
            status = up_fail(ctx, "SUPF architecture length is truncated");
            break;
        }
        uint64_t entry_length = up_supf_be32(blob + cursor);
        uint64_t start = (uint64_t)cursor + 4;
        uint64_t end = start + entry_length;
        if (start + 8 > end || end > outer_end) {
            status = up_fail(ctx, "SUPF architecture has invalid geometry");
            break;
        }
        up_supf_architecture architecture;
        memset(&architecture, 0, sizeof(architecture));
        architecture.cpu_type = up_supf_be32(blob + start);
        architecture.cpu_subtype = up_supf_be32(blob + start + 4);
        uint64_t payload = start + 8;
        if (variant == 3) {
            payload += 20;
        }
        if (payload + 4 > end) {
            status = up_fail(ctx, "SUPF page count is truncated");
            break;
        }
        uint32_t pages = up_supf_be32(blob + payload);
        uint64_t keys = payload + 4;
        if (keys + (uint64_t)pages * 32 != end) {
            status = up_fail(ctx, "SUPF page-key table has inconsistent length");
            break;
        }
        if (pages > 0) {
            architecture.records = malloc((size_t)pages * 32);
            if (architecture.records == NULL) {
                status = up_fail(ctx, "out of memory");
                break;
            }
            memcpy(architecture.records, blob + keys, (size_t)pages * 32);
        }
        architecture.record_count = pages;
        architectures[architecture_count++] = architecture;
        cursor = (size_t)end;
    }
    if (status && cursor != outer_end) {
        status = up_fail(ctx, "SUPF records do not fill outer payload");
    }
    if (!status) {
        for (size_t index = 0; index < architecture_count; index++) {
            free(architectures[index].records);
        }
        free(architectures);
        return 0;
    }
    out->architectures = architectures;
    out->count = architecture_count;
    return 1;
}

int up_supf_records(const up_supf_table *table,
                    uint32_t cpu_type,
                    uint32_t cpu_subtype,
                    const uint8_t **records,
                    size_t *count) {
    for (size_t index = 0; index < table->count; index++) {
        const up_supf_architecture *architecture = &table->architectures[index];
        if (architecture->cpu_type == cpu_type && architecture->cpu_subtype == cpu_subtype) {
            *records = architecture->records;
            *count = architecture->record_count;
            return 1;
        }
    }
    *records = NULL;
    *count = 0;
    return 0;
}
