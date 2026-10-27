//
//  up_model.c
//  CUnfairPlay
//
//  Enrollment model parsing and SINF atom layout, ported line by line from
//  internal/fairplay/model.go and sinf.go.
//

#include "up_model.h"

static uint32_t up_read_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static uint32_t up_read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

bool up_selector_equal(up_selector left, up_selector right) {
    return left.user == right.user && left.key == right.key;
}

void up_selector_identifier(up_selector selector, char output[18]) {
    snprintf(output, 18, "%08x:%08x", (unsigned)selector.user, (unsigned)selector.key);
}

// MARK: - Model

static bool up_magic_matches(const uint8_t *pack, const char *magic) {
    return memcmp(pack, magic, 8) == 0;
}

static bool up_validate_permutations(up_context *ctx, const char *kind, const uint8_t *tables,
                                     size_t length) {
    if (length == 0 || length % 256 != 0) {
        return up_fail(ctx, "current SINF %s tables have invalid size", kind), false;
    }
    for (size_t position = 0; position < length / 256; position++) {
        bool seen[256] = {false};
        for (size_t index = 0; index < 256; index++) {
            uint8_t value = tables[position * 256 + index];
            if (seen[value]) {
                return up_fail(ctx, "current SINF %s table %zu is not a permutation", kind, position),
                       false;
            }
            seen[value] = true;
        }
    }
    return true;
}

int up_model_parse(up_context *ctx, const uint8_t *pack, size_t length, up_model *out) {
    memset(out, 0, sizeof(*out));
    if (length < 16 || up_read_le32(pack + 12) != (uint32_t)length) {
        return up_fail(ctx, "invalid current SINF model envelope");
    }
    size_t payload_offset = 0;
    if (length == UP_MODEL_V1_BYTES &&
        (up_magic_matches(pack, "FPS26A4\0") || up_magic_matches(pack, "FPSENR1\0")) &&
        up_read_le32(pack + 8) == 1) {
        out->version = 1;
        memcpy(out->fairplayd_hash, pack + 16, 32);
        payload_offset = 48;
    } else if (length == UP_MODEL_V2_BYTES && up_magic_matches(pack, "FPSENR2\0") &&
               up_read_le32(pack + 8) == 2) {
        out->version = 2;
        memcpy(out->fairplayd_hash, pack + 16, 32);
        out->selector.user = up_read_le32(pack + 48);
        out->selector.key = up_read_le32(pack + 52);
        out->has_selector = true;
        payload_offset = 56;
    } else if (length == UP_MODEL_V3_BYTES && up_magic_matches(pack, "FPSENR3\0") &&
               up_read_le32(pack + 8) == 3) {
        out->version = 3;
        memcpy(out->fairplayd_hash, pack + 16, 32);
        out->selector.user = up_read_le32(pack + 48);
        out->selector.key = up_read_le32(pack + 52);
        out->has_selector = true;
        out->source_offset = (int32_t)up_read_le32(pack + 56);
        out->source_bytes = up_read_le32(pack + 60);
        out->final_xor = pack[64];
        if (pack[65] != 0 || pack[66] != 0 || pack[67] != 0 || out->source_offset < 0 ||
            out->source_bytes != UP_SINF_V3_SOURCE_BYTES) {
            return up_fail(ctx, "invalid current SINF version 3 geometry");
        }
        payload_offset = 68;
    } else {
        return up_fail(ctx, "invalid current SINF model envelope");
    }
    memcpy(out->key, pack + payload_offset, 16);
    if (out->version < 3) {
        memcpy(out->whitening, pack + payload_offset + 16, 16);
        memcpy(out->input_decode, pack + payload_offset + 32, sizeof(out->input_decode));
    } else {
        size_t cursor = payload_offset + 16;
        memcpy(out->output_encode, pack + cursor, sizeof(out->output_encode));
        cursor += sizeof(out->output_encode);
        memcpy(out->output_mask, pack + cursor, sizeof(out->output_mask));
        cursor += sizeof(out->output_mask);
        memcpy(out->post_decode, pack + cursor, sizeof(out->post_decode));
    }
    if (out->version < 3) {
        if (!up_validate_permutations(ctx, "input", out->input_decode, sizeof(out->input_decode))) {
            return 0;
        }
    } else {
        if (!up_validate_permutations(ctx, "output", out->output_encode, sizeof(out->output_encode))) {
            return 0;
        }
        if (!up_validate_permutations(ctx, "post-codec", out->post_decode, sizeof(out->post_decode))) {
            return 0;
        }
    }
    return 1;
}

// MARK: - SINF

void up_atoms_free(up_atoms *atoms) {
    if (atoms == NULL) {
        return;
    }
    free(atoms->items);
    atoms->items = NULL;
    atoms->count = 0;
}

static bool up_atoms_reserve(up_atoms *atoms, size_t extra) {
    size_t needed = atoms->count + extra;
    if (needed <= atoms->count) {
        return false;
    }
    up_atom *grown = realloc(atoms->items, needed * sizeof(up_atom));
    if (grown == NULL) {
        return false;
    }
    atoms->items = grown;
    return true;
}

/// Walks `[start, end)` and records each child atom. Returns 0 on a malformed list.
static int up_parse_atom_list(up_context *ctx,
                              const uint8_t *blob,
                              size_t start,
                              size_t end,
                              up_atoms *out) {
    up_atoms result = {NULL, 0};
    for (size_t cursor = start; cursor < end;) {
        if (end - cursor < 8) {
            up_atoms_free(&result);
            return up_fail(ctx, "SINF atom list has a truncated header");
        }
        uint32_t size = up_read_be32(blob + cursor);
        if (size < 8 || (size_t)size > end - cursor) {
            up_atoms_free(&result);
            return up_fail(ctx, "SINF atom has invalid bounds");
        }
        if (!up_atoms_reserve(&result, 1)) {
            up_atoms_free(&result);
            return up_fail(ctx, "out of memory");
        }
        up_atom *atom = &result.items[result.count++];
        memcpy(atom->type, blob + cursor + 4, 4);
        atom->type[4] = '\0';
        atom->start = cursor + 8;
        atom->end = cursor + size;
        cursor += size;
    }
    *out = result;
    return 1;
}

/// Returns the single atom of `type`, or fails.
int up_unique_atom(up_context *ctx, const up_atoms *atoms, const char *type, up_atom *out) {
    const up_atom *found = NULL;
    int count = 0;
    for (size_t index = 0; index < atoms->count; index++) {
        if (strcmp(atoms->items[index].type, type) == 0) {
            found = &atoms->items[index];
            count++;
        }
    }
    if (count != 1) {
        return up_fail(ctx, "SINF requires one \"%s\" atom, found %d", type, count);
    }
    *out = *found;
    return 1;
}

int up_sinf_fields(up_context *ctx, const uint8_t *blob, size_t length, up_atoms *out) {
    memset(out, 0, sizeof(*out));
    up_atoms roots = {NULL, 0};
    if (!up_parse_atom_list(ctx, blob, 0, length, &roots)) {
        return 0;
    }
    if (roots.count != 1 || strcmp(roots.items[0].type, "sinf") != 0 ||
        roots.items[0].start != 8 || roots.items[0].end != length) {
        up_atoms_free(&roots);
        return up_fail(ctx, "SINF must contain one complete root atom");
    }
    size_t root_start = roots.items[0].start;
    size_t root_end = roots.items[0].end;
    up_atoms_free(&roots);

    up_atoms children = {NULL, 0};
    if (!up_parse_atom_list(ctx, blob, root_start, root_end, &children)) {
        return 0;
    }
    up_atom schi;
    if (!up_unique_atom(ctx, &children, "schi", &schi)) {
        up_atoms_free(&children);
        return 0;
    }
    up_atoms_free(&children);
    return up_parse_atom_list(ctx, blob, schi.start, schi.end, out);
}

int up_sinf_selector(up_context *ctx,
                     const uint8_t *blob,
                     size_t length,
                     const up_atoms *fields,
                     up_selector *out) {
    (void)length;
    up_atom user;
    if (!up_unique_atom(ctx, fields, "user", &user)) {
        return 0;
    }
    up_atom key;
    if (!up_unique_atom(ctx, fields, "key ", &key)) {
        return 0;
    }
    if (user.end - user.start != 4 || key.end - key.start != 4) {
        return up_fail(ctx, "SINF user/key atom has invalid geometry");
    }
    out->user = up_read_be32(blob + user.start);
    out->key = up_read_be32(blob + key.start);
    return 1;
}

int up_sinf_read_selector(up_context *ctx, const uint8_t *blob, size_t length, up_selector *out) {
    up_atoms fields = {NULL, 0};
    if (!up_sinf_fields(ctx, blob, length, &fields)) {
        return 0;
    }
    int result = up_sinf_selector(ctx, blob, length, &fields, out);
    up_atoms_free(&fields);
    return result;
}

int up_sinf_private_payload(up_context *ctx,
                            const uint8_t *blob,
                            size_t length,
                            const up_atoms *fields,
                            const uint8_t **payload,
                            size_t *payload_length) {
    up_atom priv;
    if (!up_unique_atom(ctx, fields, "priv", &priv)) {
        return 0;
    }
    if (priv.end < priv.start || priv.end > length) {
        return up_fail(ctx, "SINF priv atom has invalid bounds");
    }
    *payload = blob + priv.start;
    *payload_length = priv.end - priv.start;
    return 1;
}
