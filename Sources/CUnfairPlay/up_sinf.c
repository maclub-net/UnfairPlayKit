//
//  up_sinf.c
//  CUnfairPlay
//
//  Bit-exact port of the current-SINF private-key decoders. Both the legacy
//  (v1/v2) whitebox path and the v3 transformation path must reject anything
//  unexpected: the caller relies on failure to fail closed.
//

#include "up_sinf.h"

#include "up_crypto.h"

static const char *const up_profile_mismatch = "SINF does not match the selected FairPlay model";

static int up_mismatch(up_context *ctx, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    va_list copy;
    va_copy(copy, arguments);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    char *detail = needed >= 0 ? malloc((size_t)needed + 1) : NULL;
    if (detail != NULL) {
        vsnprintf(detail, (size_t)needed + 1, format, arguments);
    }
    va_end(arguments);
    int status;
    if (detail != NULL) {
        status = up_fail(ctx, "%s: %s", up_profile_mismatch, detail);
        free(detail);
    } else {
        status = up_fail(ctx, "%s", up_profile_mismatch);
    }
    return status;
}

static uint32_t up_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

/// Port of `parseClearAtom`. `truncated` distinguishes the Go error text.
static int up_parse_clear_atom(const uint8_t *blob,
                               size_t length,
                               size_t offset,
                               size_t limit,
                               bool *truncated,
                               up_atom *out) {
    *truncated = false;
    if (limit > length || limit < offset || limit - offset < 8) {
        *truncated = true;
        return 0;
    }
    uint32_t size = up_be32(blob + offset);
    if (size < 8 || (size_t)size > limit - offset) {
        return 0;
    }
    memcpy(out->type, blob + offset + 4, 4);
    out->type[4] = '\0';
    out->start = offset;
    out->end = offset + size;
    return 1;
}

void up_logical_from_inner_key(const uint8_t inner_key[16], uint8_t logical[16]) {
    for (int word = 0; word < 4; word++) {
        const uint8_t *bytes = inner_key + word * 4;
        uint32_t decoded = up_be32(bytes);
        decoded += (uint32_t)(13 + word) * 0xa6b13d89u;
        logical[word * 4] = (uint8_t)decoded;
        logical[word * 4 + 1] = (uint8_t)(decoded >> 8);
        logical[word * 4 + 2] = (uint8_t)(decoded >> 16);
        logical[word * 4 + 3] = (uint8_t)(decoded >> 24);
    }
}

static int up_current_sinf_private_key_legacy(up_context *ctx,
                                              const up_model *model,
                                              const uint8_t *source,
                                              size_t source_length,
                                              uint8_t inner_key[16],
                                              bool *profile_mismatch) {
    if (source_length < 48) {
        *profile_mismatch = true;
        return up_mismatch(ctx, "priv source is too short");
    }
    size_t body_bytes = source_length - 16;
    size_t trailer_bytes = body_bytes % 16;
    size_t ciphertext_bytes = body_bytes - trailer_bytes;
    if (ciphertext_bytes < 32 || (trailer_bytes != 0 && trailer_bytes != 8)) {
        *profile_mismatch = true;
        return up_mismatch(ctx, "priv block geometry is invalid");
    }
    size_t encoded_bytes = 16 + ciphertext_bytes;
    for (size_t index = encoded_bytes; index < source_length; index++) {
        if (source[index] != 0) {
            *profile_mismatch = true;
            return up_mismatch(ctx, "priv trailer is not zero");
        }
    }

    size_t plaintext_length = ciphertext_bytes + trailer_bytes;
    uint8_t *encoded = malloc(encoded_bytes);
    uint8_t *plaintext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (encoded == NULL || plaintext == NULL) {
        free(encoded);
        free(plaintext);
        return up_fail(ctx, "out of memory");
    }
    for (size_t index = 0; index < encoded_bytes; index++) {
        size_t position = index % 16;
        uint8_t external = (uint8_t)(source[index] ^ model->whitening[position]);
        encoded[index] = model->input_decode[position * 256 + external];
    }
    bool decrypted =
        up_aes_cbc(false, model->key, encoded, encoded + 16, ciphertext_bytes, plaintext);
    if (!decrypted) {
        memset(encoded, 0, encoded_bytes);
        memset(plaintext, 0, plaintext_length);
        free(encoded);
        free(plaintext);
        *profile_mismatch = false;
        return up_fail(ctx, "decode selected current SINF model: invalid AES-CBC geometry");
    }
    if (trailer_bytes != 0) {
        memcpy(plaintext + ciphertext_bytes, source + encoded_bytes, trailer_bytes);
    }
    memset(encoded, 0, encoded_bytes);
    free(encoded);

    static const struct {
        const char *type;
        size_t sizes[2];
        size_t count;
    } expected[] = {
        {"key ", {24, 0}, 1},
        {"iviv", {24, 0}, 1},
        {"tmpr", {24, 0}, 1},
        {"righ", {88, 96}, 2},
        {"name", {264, 0}, 1},
    };
    size_t cursor = 0;
    int status = 1;
    for (size_t index = 0; index < sizeof(expected) / sizeof(expected[0]); index++) {
        up_atom atom;
        bool truncated = false;
        if (!up_parse_clear_atom(plaintext, plaintext_length, cursor, plaintext_length, &truncated,
                                 &atom)) {
            *profile_mismatch = true;
            status = up_mismatch(ctx, "plaintext atom %zu: %s", index,
                                 truncated ? "atom is truncated" : "atom has invalid bounds");
            break;
        }
        bool valid_size = false;
        for (size_t size_index = 0; size_index < expected[index].count; size_index++) {
            valid_size = valid_size || atom.end - cursor == expected[index].sizes[size_index];
        }
        if (strcmp(atom.type, expected[index].type) != 0 || !valid_size) {
            *profile_mismatch = true;
            status = up_mismatch(ctx, "plaintext has invalid %s atom", expected[index].type);
            break;
        }
        if (index == 0) {
            memcpy(inner_key, plaintext + cursor + 8, 16);
        }
        cursor = atom.end;
    }
    if (status == 1 && cursor != plaintext_length) {
        *profile_mismatch = true;
        status = up_mismatch(ctx, "plaintext has trailing data");
    }
    memset(plaintext, 0, plaintext_length);
    free(plaintext);
    return status;
}

static int up_validate_current_sinf_v3_plaintext(up_context *ctx, const uint8_t *plaintext,
                                                 size_t length) {
    if (length != UP_SINF_V3_SOURCE_BYTES) {
        return up_mismatch(ctx, "version 3 plaintext has invalid size");
    }
    static const uint8_t itun[4] = {'i', 't', 'u', 'n'};
    static const uint8_t vers[4] = {'v', 'e', 'r', 's'};
    if (memcmp(plaintext, itun, 4) != 0 || up_be32(plaintext + 4) != 12 ||
        memcmp(plaintext + 8, vers, 4) != 0 || up_be32(plaintext + 12) != 1) {
        return up_mismatch(ctx, "version 3 plaintext has invalid header");
    }
    static const struct {
        size_t offset;
        uint32_t size;
        const char *type;
    } expected[] = {
        {16, 24, "key "},
        {40, 24, "iviv"},
        {64, 24, "tmpr"},
        {88, 88, "righ"},
        {176, 264, "name"},
    };
    for (size_t index = 0; index < sizeof(expected) / sizeof(expected[0]); index++) {
        const uint8_t *field = plaintext + expected[index].offset;
        if (up_be32(field) != expected[index].size ||
            memcmp(field + 4, expected[index].type, 4) != 0) {
            return up_mismatch(ctx, "version 3 plaintext has invalid %s field",
                               expected[index].type);
        }
    }
    // The native 432-byte work buffer deliberately carries only the first 256
    // bytes of the final 264-byte name record.
    if (176 + up_be32(plaintext + 176) != length + 8) {
        return up_mismatch(ctx, "version 3 plaintext has invalid name geometry");
    }
    return 1;
}

static int up_current_sinf_private_key_v3(up_context *ctx,
                                          const up_model *model,
                                          const uint8_t *sinf,
                                          size_t sinf_length,
                                          const up_atoms *fields,
                                          uint8_t inner_key[16],
                                          bool *profile_mismatch) {
    up_atom private_atom;
    if (!up_unique_atom(ctx, fields, "priv", &private_atom)) {
        return 0;
    }
    size_t start = (size_t)model->source_offset;
    size_t end = start + (size_t)model->source_bytes;
    if (start < private_atom.start || start > private_atom.end || end < start ||
        end > sinf_length) {
        *profile_mismatch = true;
        return up_mismatch(ctx, "version 3 source has invalid bounds");
    }
    if (model->source_bytes != UP_SINF_V3_SOURCE_BYTES) {
        *profile_mismatch = true;
        return up_mismatch(ctx, "version 3 source has invalid geometry");
    }
    const uint8_t *source = sinf + start;

    uint8_t internal[UP_SINF_V3_SOURCE_BYTES];
    uint8_t plaintext[UP_SINF_V3_SOURCE_BYTES];
    for (size_t offset = 0; offset < UP_SINF_V3_SOURCE_BYTES; offset += 16) {
        if (!up_aes_decrypt_block(model->key, source + offset, internal + offset)) {
            memset(internal, 0, sizeof(internal));
            *profile_mismatch = false;
            return up_fail(ctx, "decode current SINF version 3 model: invalid AES block");
        }
    }
    for (size_t index = 0; index < UP_SINF_V3_SOURCE_BYTES; index++) {
        size_t position = index % 16;
        uint8_t substituted = model->output_encode[position * 256 + internal[index]];
        uint8_t external = (uint8_t)(substituted ^ model->output_mask[index]);
        plaintext[index] =
            (uint8_t)(model->post_decode[position * 256 + external] ^ model->final_xor);
    }
    memset(internal, 0, sizeof(internal));

    int status = 1;
    if (!up_validate_current_sinf_v3_plaintext(ctx, plaintext, sizeof(plaintext))) {
        *profile_mismatch = true;
        status = 0;
    } else {
        memcpy(inner_key, plaintext + 24, 16);
    }
    memset(plaintext, 0, sizeof(plaintext));
    return status;
}

int up_current_sinf_private_key(up_context *ctx,
                                const up_model *model,
                                const uint8_t *sinf,
                                size_t sinf_length,
                                const up_atoms *fields,
                                uint8_t inner_key[16],
                                bool *profile_mismatch) {
    memset(inner_key, 0, 16);
    *profile_mismatch = false;
    if (model->version == 3) {
        return up_current_sinf_private_key_v3(ctx, model, sinf, sinf_length, fields, inner_key,
                                              profile_mismatch);
    }
    const uint8_t *payload = NULL;
    size_t payload_length = 0;
    if (!up_sinf_private_payload(ctx, sinf, sinf_length, fields, &payload, &payload_length)) {
        return 0;
    }
    return up_current_sinf_private_key_legacy(ctx, model, payload, payload_length, inner_key,
                                              profile_mismatch);
}

int up_resolve_logical_key(up_context *ctx,
                           const uint8_t *sinf,
                           size_t sinf_length,
                           const up_model *model,
                           uint8_t logical[16],
                           up_selector *selector,
                           bool *profile_mismatch) {
    up_atoms fields = {NULL, 0};
    if (!up_sinf_fields(ctx, sinf, sinf_length, &fields)) {
        return 0;
    }
    up_selector parsed_selector;
    if (!up_sinf_selector(ctx, sinf, sinf_length, &fields, &parsed_selector)) {
        up_atoms_free(&fields);
        return 0;
    }
    if (model->has_selector && !up_selector_equal(model->selector, parsed_selector)) {
        char supported[18], requested[18];
        up_selector_identifier(model->selector, supported);
        up_selector_identifier(parsed_selector, requested);
        up_atoms_free(&fields);
        *profile_mismatch = false;
        return up_fail(ctx, "enrollment model is bound to selector %s, but IPA has %s", supported,
                       requested);
    }
    uint8_t inner_key[16];
    int status = up_current_sinf_private_key(ctx, model, sinf, sinf_length, &fields, inner_key,
                                             profile_mismatch);
    up_atoms_free(&fields);
    if (!status) {
        return 0;
    }
    up_logical_from_inner_key(inner_key, logical);
    memset(inner_key, 0, sizeof(inner_key));
    if (selector != NULL) {
        *selector = parsed_selector;
    }
    return 1;
}
