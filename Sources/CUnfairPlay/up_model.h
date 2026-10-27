//
//  up_model.h
//  CUnfairPlay
//
//  Enrollment model (`.bin`) layout and the model registry rules ported from
//  internal/fairplay/model.go, model_files.go, and sinf.go.
//

#ifndef UP_MODEL_H
#define UP_MODEL_H

#include "up_internal.h"

#define UP_MAX_MODELS 256
#define UP_MODEL_V1_BYTES (8 + 4 + 4 + 32 + 16 + 16 + 16 * 256)
#define UP_MODEL_V2_BYTES (8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16 * 256)
#define UP_SINF_V3_SOURCE_BYTES (27 * 16)
#define UP_MODEL_V3_BYTES \
    (8 + 4 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 16 + 16 * 256 + UP_SINF_V3_SOURCE_BYTES + 16 * 256)

/// SINF user/key selector.
typedef struct {
    uint32_t user;
    uint32_t key;
} up_selector;

bool up_selector_equal(up_selector left, up_selector right);

/// `%08x:%08x`
void up_selector_identifier(up_selector selector, char output[18]);

/// Parsed enrollment model. Every table is stored verbatim; the model holds
/// no key material beyond what the file itself carries.
typedef struct {
    uint32_t version;
    uint8_t fairplayd_hash[32];
    bool has_selector;
    up_selector selector;
    uint8_t key[16];
    // Version 1 and 2.
    uint8_t whitening[16];
    uint8_t input_decode[16 * 256];
    // Version 3.
    int32_t source_offset;
    uint32_t source_bytes;
    uint8_t final_xor;
    uint8_t output_encode[16 * 256];
    uint8_t output_mask[UP_SINF_V3_SOURCE_BYTES];
    uint8_t post_decode[16 * 256];
} up_model;

/// Parses a model pack. The caller keeps ownership of `pack`.
int up_model_parse(up_context *ctx, const uint8_t *pack, size_t length, up_model *out);

/// Parses a SINF byte range into its `schi` child atoms. The atom list is
/// heap allocated and must be released with up_atoms_free().
typedef struct {
    char type[5];
    size_t start;
    size_t end;
} up_atom;

typedef struct {
    up_atom *items;
    size_t count;
} up_atoms;

void up_atoms_free(up_atoms *atoms);

int up_sinf_fields(up_context *ctx, const uint8_t *blob, size_t length, up_atoms *out);
/// Returns the single atom of `type`, or fails with the same message the Go
/// version produces.
int up_unique_atom(up_context *ctx, const up_atoms *atoms, const char *type, up_atom *out);
int up_sinf_selector(up_context *ctx,
                     const uint8_t *blob,
                     size_t length,
                     const up_atoms *fields,
                     up_selector *out);
/// Reads only the selector carried by the SINF.
int up_sinf_read_selector(up_context *ctx, const uint8_t *blob, size_t length, up_selector *out);
int up_sinf_private_payload(up_context *ctx,
                            const uint8_t *blob,
                            size_t length,
                            const up_atoms *fields,
                            const uint8_t **payload,
                            size_t *payload_length);

/// A model pack read from disk together with its path, used for reporting.
typedef struct {
    uint8_t *bytes;
    size_t length;
    char *path;
} up_model_pack;

typedef struct {
    up_model_pack *packs;
    size_t count;
} up_model_registry;

void up_model_pack_free(up_model_pack *pack);
void up_model_registry_free(up_model_registry *registry);

int up_read_model_file(up_context *ctx, const char *path, up_model_pack *out);
int up_read_model_registry(up_context *ctx, const char *path, up_model_registry *out);

#endif /* UP_MODEL_H */
