//
//  up_recovery_api.c
//  CUnfairPlay
//
//  Public entry point for one native recovery run. The Swift layer supplies
//  the generated assets and the runtime inputs; this file loads them, walks
//  the enrollment CFGs, and returns the `FPSENR2` enrollment model that the
//  decryptor consumes.
//

#include "unfairplay.h"
#include "up_recovery.h"
#include "up_crypto.h"

#include <stdlib.h>
#include <string.h>

#define UP_RECOVERY_MODEL_BYTES 4184
#define UP_RECOVERY_SELECTION_BLOCKS 2000000
#define UP_RECOVERY_MODEL_LIMIT (UINT64_C(64) * 1024 * 1024)
#define UP_RECOVERY_PROFILE_LIMIT (UINT64_C(128) * 1024 * 1024)
#define UP_RECOVERY_EXTRACTED_LIMIT (UINT64_C(128) * 1024 * 1024)
#define UP_RECOVERY_FRAME_LIMIT (UINT64_C(16) * 1024 * 1024)

static bool up_recovery_decompress(up_context *ctx, const uint8_t *data, size_t length,
                                   uint64_t limit, uint8_t **decoded, size_t *decoded_length) {
    if (data == NULL || length == 0) {
        return up_fail(ctx, "recovery asset is empty");
    }
    return up_rec_gunzip(ctx, data, length, limit, decoded, decoded_length);
}

static uint32_t up_recovery_be32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 |
           (uint32_t)bytes[3];
}

static void up_recovery_put_u32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

// MARK: - SINF selector

static bool up_recovery_atom(const uint8_t *blob, size_t start, size_t limit, const char *name,
                             size_t *atom_start, size_t *atom_end) {
    for (size_t cursor = start; cursor < limit;) {
        if (limit - cursor < 8) {
            return false;
        }
        uint32_t size = up_recovery_be32(blob + cursor);
        if (size < 8 || size > limit - cursor) {
            return false;
        }
        if (memcmp(blob + cursor + 4, name, 4) == 0) {
            *atom_start = cursor + 8;
            *atom_end = cursor + size;
            return true;
        }
        cursor += size;
    }
    return false;
}

static bool up_recovery_sinf_selector(up_context *ctx, const uint8_t *blob, size_t length,
                                      uint32_t *user, uint32_t *key_id) {
    size_t root_start = 0;
    size_t root_end = 0;
    if (!up_recovery_atom(blob, 0, length, "sinf", &root_start, &root_end) ||
        root_start != 8 || root_end != length) {
        return up_fail(ctx, "SINF root is invalid");
    }
    size_t schi_start = 0;
    size_t schi_end = 0;
    if (!up_recovery_atom(blob, root_start, root_end, "schi", &schi_start, &schi_end)) {
        return up_fail(ctx, "SINF has no \"schi\" atom");
    }
    const char *names[2] = {"user", "key "};
    size_t positions[2] = {0, 0};
    for (int index = 0; index < 2; index++) {
        size_t start = 0;
        size_t end = 0;
        if (!up_recovery_atom(blob, schi_start, schi_end, names[index], &start, &end) ||
            end - start != 4) {
            return up_fail(ctx, "SINF selector atom \"%s\" is invalid", names[index]);
        }
        positions[index] = start;
    }
    *user = up_recovery_be32(blob + positions[0]);
    *key_id = up_recovery_be32(blob + positions[1]);
    return true;
}

static bool up_recovery_ends_with(const char *value, const char *suffix) {
    size_t value_length = strlen(value);
    size_t suffix_length = strlen(suffix);
    if (suffix_length > value_length) {
        return false;
    }
    return memcmp(value + value_length - suffix_length, suffix, suffix_length) == 0;
}

// MARK: - Public API

void up_recovery_result_free(up_recovery_result *result) {
    if (result == NULL) {
        return;
    }
    free(result->model);
    result->model = NULL;
    result->model_length = 0;
    result->state_sha256[0] = '\0';
    result->iterations = 0;
    result->extracted_block_hits = 0;
}

int up_recovery_run(up_context *ctx, const up_recovery_assets *assets,
                    const up_recovery_options *options, up_recovery_result *result) {
    if (ctx == NULL || assets == NULL || options == NULL || result == NULL) {
        return 0;
    }
    memset(result, 0, sizeof(*result));
    if (options->executable_path == NULL || options->executable_path[0] == '\0') {
        return up_fail(ctx, "recovery requires an installed executable path");
    }
    if (options->hardware_path == NULL || options->hardware_path[0] == '\0') {
        return up_fail(ctx, "recovery requires a hardware address input");
    }
    int selection_blocks = options->selection_max_blocks;
    if (selection_blocks <= 0) {
        selection_blocks = UP_RECOVERY_SELECTION_BLOCKS;
    }

    uint8_t *model_bytes = NULL;
    size_t model_bytes_length = 0;
    uint8_t *compact_bytes = NULL;
    size_t compact_length = 0;
    uint8_t *frame_bytes = NULL;
    size_t frame_length = 0;
    uint8_t *extracted_bytes = NULL;
    size_t extracted_length = 0;

    up_rec_model model;
    memset(&model, 0, sizeof(model));
    up_rec_profile profile;
    memset(&profile, 0, sizeof(profile));
    up_rec_frame_profile frame;
    memset(&frame, 0, sizeof(frame));
    up_rec_state state;
    memset(&state, 0, sizeof(state));
    up_rec_blocks main_extracted;
    memset(&main_extracted, 0, sizeof(main_extracted));
    bool state_created = false;
    bool simulated = false;

    if (!up_recovery_decompress(ctx, assets->model_gz, assets->model_gz_length,
                                UP_RECOVERY_MODEL_LIMIT, &model_bytes, &model_bytes_length) ||
        !up_recovery_decompress(ctx, assets->compact_cfg_gz, assets->compact_cfg_gz_length,
                                UP_RECOVERY_PROFILE_LIMIT, &compact_bytes, &compact_length) ||
        !up_recovery_decompress(ctx, assets->frame_gz, assets->frame_gz_length,
                                UP_RECOVERY_FRAME_LIMIT, &frame_bytes, &frame_length)) {
        goto cleanup;
    }
    // The extracted block table only participates when a reference binary of
    // the exact recovered build is supplied, matching the Go reference.
    if (options->reference_path != NULL && options->reference_path[0] != '\0') {
        if (!up_recovery_decompress(ctx, assets->safe_extracted_gz,
                                    assets->safe_extracted_gz_length,
                                    UP_RECOVERY_EXTRACTED_LIMIT, &extracted_bytes,
                                    &extracted_length)) {
            goto cleanup;
        }
    }
    if (!up_rec_load_model(ctx, model_bytes, model_bytes_length, &model)) {
        goto cleanup;
    }
    if (!up_rec_load_compact_profile(ctx, compact_bytes, compact_length, &profile.account_entry,
                                     &profile.bootstrap, &profile.selection, profile.sinf_entry,
                                     &profile.supplemental, &main_extracted)) {
        goto cleanup;
    }
    if (main_extracted.count != 0) {
        up_fail(ctx, "compact profile must not embed extracted blocks");
        goto cleanup;
    }
    if (extracted_bytes != NULL) {
        up_rec_blocks unused_account;
        up_rec_blocks unused_bootstrap;
        up_rec_blocks unused_selection;
        up_rec_blocks unused_sinf[6];
        up_rec_blocks unused_supplemental;
        memset(&unused_account, 0, sizeof(unused_account));
        memset(&unused_bootstrap, 0, sizeof(unused_bootstrap));
        memset(&unused_selection, 0, sizeof(unused_selection));
        memset(unused_sinf, 0, sizeof(unused_sinf));
        memset(&unused_supplemental, 0, sizeof(unused_supplemental));
        up_rec_blocks safe;
        memset(&safe, 0, sizeof(safe));
        if (!up_rec_load_compact_profile(ctx, extracted_bytes, extracted_length, &unused_account,
                                         &unused_bootstrap, &unused_selection, unused_sinf,
                                         &unused_supplemental, &safe)) {
            goto cleanup;
        }
        if (unused_account.count != 0 || unused_bootstrap.count != 0 ||
            unused_selection.count != 0 || unused_supplemental.count != 0) {
            free(unused_account.blocks);
            free(unused_bootstrap.blocks);
            free(unused_selection.blocks);
            free(unused_supplemental.blocks);
            up_fail(ctx, "extracted block profile contains unexpected sections");
            goto cleanup;
        }
        for (size_t index = 0; index < 6; index++) {
            free(unused_sinf[index].blocks);
        }
        profile.extracted = safe;
    }
    if (!up_rec_load_kernels(ctx, assets->kernels, assets->kernels_length, &profile)) {
        goto cleanup;
    }
    if (memcmp(model.binary_hash, profile.binary_hash, 32) != 0) {
        up_fail(ctx, "recovery profile does not match the captured model");
        goto cleanup;
    }
    if (!up_rec_frame_parse(ctx, frame_bytes, frame_length, &frame)) {
        goto cleanup;
    }
    if (!up_rec_runtime_add_reference_pages(ctx, &model, &profile, options->reference_path)) {
        goto cleanup;
    }
    if (!up_rec_state_create(&state, &model, &profile, NULL)) {
        goto cleanup;
    }
    state_created = true;
    state.ctx = ctx;
    state.frame = &frame;
    if (!up_rec_runtime_configure(ctx, &state, "enrollment-sinf", options->file_mappings,
                                  options->file_mapping_count, options->hardware_path,
                                  options->executable_path, 0)) {
        goto cleanup;
    }
    int iterations = 0;
    uint8_t digest[32];
    bool ok = up_rec_run_account_entry_cfg(&state, 1000000);
    if (ok) {
        ok = up_rec_run_bootstrap_cfg(&state, 1000000);
    }
    if (ok) {
        ok = up_rec_run_kernel_loop(&state, "outer", &iterations);
    }
    if (ok) {
        ok = up_rec_run_selection_cfg(&state, selection_blocks);
    }
    if (ok) {
        ok = up_rec_run_sinf_entry_cfg(&state, 2000000);
    }
    if (ok) {
        ok = up_rec_state_digest(&state, digest);
    }
    if (!ok) {
        up_fail(ctx, "%s", state.detail);
        goto cleanup;
    }
    result->iterations = iterations;
    result->extracted_block_hits = state.extracted_hits;
    for (int index = 0; index < 32; index++) {
        snprintf(result->state_sha256 + index * 2, 3, "%02x", digest[index]);
    }

    uint8_t material[16];
    if (state.x[29] < profile.sinf_frame_offset ||
        !up_rec_state_output_bytes(&state, state.x[29] - profile.sinf_frame_offset, material,
                                   sizeof(material))) {
        up_fail(ctx, "current-SINF frame pointer is invalid");
        goto cleanup;
    }
    const uint8_t *sinf = NULL;
    size_t sinf_length = 0;
    for (size_t index = 0; index < state.runtime->file_count; index++) {
        const up_rec_file *file = &state.runtime->files[index];
        if (!up_recovery_ends_with(file->suffix, ".sinf")) {
            continue;
        }
        if (sinf != NULL) {
            up_fail(ctx, "enrollment model requires exactly one installed SINF");
            goto cleanup;
        }
        sinf = file->data;
        sinf_length = file->length;
    }
    if (sinf == NULL) {
        up_fail(ctx, "enrollment model requires one installed SINF mapping");
        goto cleanup;
    }
    uint32_t user = 0;
    uint32_t key_id = 0;
    if (!up_recovery_sinf_selector(ctx, sinf, sinf_length, &user, &key_id)) {
        goto cleanup;
    }

    uint8_t *pack = malloc(UP_RECOVERY_MODEL_BYTES);
    if (pack == NULL) {
        up_fail(ctx, "out of memory generating the enrollment model");
        goto cleanup;
    }
    size_t offset = 0;
    memcpy(pack, "FPSENR2\0", 8);
    offset += 8;
    up_recovery_put_u32(pack + offset, 2);
    offset += 4;
    up_recovery_put_u32(pack + offset, UP_RECOVERY_MODEL_BYTES);
    offset += 4;
    memcpy(pack + offset, profile.binary_hash, 32);
    offset += 32;
    up_recovery_put_u32(pack + offset, user);
    offset += 4;
    up_recovery_put_u32(pack + offset, key_id);
    offset += 4;
    for (size_t index = 0; index < sizeof(material); index++) {
        pack[offset + index] = material[index] ^ profile.current_sinf_mask[index];
    }
    offset += sizeof(material);
    memcpy(pack + offset, profile.current_sinf_white, sizeof(profile.current_sinf_white));
    offset += sizeof(profile.current_sinf_white);
    memcpy(pack + offset, profile.current_sinf_input, sizeof(profile.current_sinf_input));
    offset += sizeof(profile.current_sinf_input);
    if (offset != UP_RECOVERY_MODEL_BYTES) {
        free(pack);
        up_fail(ctx, "generated enrollment model has invalid size %zu", offset);
        goto cleanup;
    }
    result->model = pack;
    result->model_length = UP_RECOVERY_MODEL_BYTES;
    simulated = true;

cleanup:
    if (state_created) {
        up_rec_runtime_release(state.runtime);
        up_rec_state_destroy(&state);
    }
    free(main_extracted.blocks);
    up_rec_release_frame_profile(&frame);
    up_rec_release_profile(&profile);
    up_rec_release_model(&model);
    free(model_bytes);
    free(compact_bytes);
    free(frame_bytes);
    free(extracted_bytes);
    return simulated ? 1 : 0;
}
