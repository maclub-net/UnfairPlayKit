//
//  up_license.c
//  CUnfairPlay
//
//  Port of provider.go and ipa_licenses.go.
//

#include "up_license.h"

#include <errno.h>
#include <sys/stat.h>

#include "up_crypto.h"
#include "up_model.h"
#include "up_sinf.h"

static void up_digest_hex(const uint8_t *bytes, size_t length, char output[65]) {
    uint8_t digest[32];
    up_sha256(bytes, length, digest);
    up_hex_encode(digest, sizeof(digest), output);
}

/// Copies the current context error so a new message can wrap it.
static char *up_take_error(up_context *ctx) {
    const char *current = up_last_error(ctx);
    if (current == NULL) {
        current = "unknown error";
    }
    char *copy = malloc(strlen(current) + 1);
    if (copy != NULL) {
        memcpy(copy, current, strlen(current) + 1);
    }
    return copy;
}

int up_resolve_with_model(up_context *ctx,
                          const uint8_t *sinf,
                          size_t sinf_length,
                          const uint8_t *pack,
                          size_t pack_length,
                          up_key_material *out,
                          bool *profile_mismatch) {
    memset(out, 0, sizeof(*out));
    if (profile_mismatch != NULL) {
        *profile_mismatch = false;
    }
    up_model model;
    if (!up_model_parse(ctx, pack, pack_length, &model)) {
        return 0;
    }
    up_atoms fields = {NULL, 0};
    if (!up_sinf_fields(ctx, sinf, sinf_length, &fields)) {
        return 0;
    }
    up_selector selector;
    if (!up_sinf_selector(ctx, sinf, sinf_length, &fields, &selector)) {
        up_atoms_free(&fields);
        return 0;
    }
    const uint8_t *private_payload = NULL;
    size_t private_length = 0;
    if (!up_sinf_private_payload(ctx, sinf, sinf_length, &fields, &private_payload,
                                 &private_length)) {
        up_atoms_free(&fields);
        return 0;
    }
    char sinf_sha256[65];
    char private_sha256[65];
    up_digest_hex(sinf, sinf_length, sinf_sha256);
    up_digest_hex(private_payload, private_length, private_sha256);
    char selector_id[18];
    up_selector_identifier(selector, selector_id);
    char profile[256];
    snprintf(profile, sizeof(profile), "%s (sinf_sha256=%s priv_bytes=%zu priv_sha256=%s)",
             selector_id, sinf_sha256, private_length, private_sha256);
    if (model.has_selector && !up_selector_equal(model.selector, selector)) {
        char supported[18];
        up_selector_identifier(model.selector, supported);
        up_atoms_free(&fields);
        return up_fail(ctx, "enrollment model is bound to selector %s, but IPA has %s", supported,
                       profile);
    }
    uint8_t inner_key[16];
    bool mismatch = false;
    int status = up_current_sinf_private_key(ctx, &model, sinf, sinf_length, &fields, inner_key,
                                             &mismatch);
    if (!status) {
        char *detail = up_take_error(ctx);
        up_atoms_free(&fields);
        int result = 0;
        if (mismatch) {
            result = up_fail(ctx,
                             "enrollment model cannot decode SINF %s; recover a model from the "
                             "account that acquired this IPA: %s",
                             profile, detail == NULL ? "unknown error" : detail);
        } else {
            result = up_fail(ctx, "decode SINF %s with enrollment model: %s", profile,
                             detail == NULL ? "unknown error" : detail);
        }
        free(detail);
        if (profile_mismatch != NULL) {
            *profile_mismatch = mismatch;
        }
        return result;
    }
    up_atoms_free(&fields);
    up_logical_from_inner_key(inner_key, out->logical);
    memset(inner_key, 0, sizeof(inner_key));
    out->model_version = model.version;
    snprintf(out->provider_kind, sizeof(out->provider_kind), "%s",
             model.version == 3 ? "current-sinf-whitebox-direct-v3"
                                : "current-sinf-whitebox-direct-v1");
    up_digest_hex(pack, pack_length, out->model_sha256);
    snprintf(out->model_name, sizeof(out->model_name), "external-current-sinf-%.16s",
             out->model_sha256);
    up_hex_encode(model.fairplayd_hash, sizeof(model.fairplayd_hash),
                  out->evaluator_source_sha256);
    snprintf(out->request_selector, sizeof(out->request_selector), "%s", selector_id);
    up_app_mask_from_logical_key(out->logical, out->mask);
    up_page_deriver_init(&out->deriver, out->mask);
    return 1;
}

int up_resolve_with_registry(up_context *ctx,
                             const uint8_t *sinf,
                             size_t sinf_length,
                             const up_model_registry *registry,
                             up_key_material *out,
                             size_t *selected_index) {
    memset(out, 0, sizeof(*out));
    up_selector selector;
    if (!up_sinf_read_selector(ctx, sinf, sinf_length, &selector)) {
        return 0;
    }
    char selector_id[18];
    up_selector_identifier(selector, selector_id);
    bool matched_selector = false;
    size_t decoded_count = 0;
    up_key_material selected;
    memset(&selected, 0, sizeof(selected));
    size_t chosen = SIZE_MAX;
    for (size_t index = 0; index < registry->count; index++) {
        up_model model;
        if (!up_model_parse(ctx, registry->packs[index].bytes, registry->packs[index].length,
                            &model)) {
            char *detail = up_take_error(ctx);
            int result = up_fail(ctx, "parse FairPlay model %zu: %s", index,
                                 detail == NULL ? "unknown error" : detail);
            free(detail);
            return result;
        }
        if (!model.has_selector) {
            return up_fail(ctx, "FairPlay model %zu is version 1 and cannot be used in a registry",
                           index);
        }
        if (!up_selector_equal(model.selector, selector)) {
            continue;
        }
        matched_selector = true;
        bool mismatch = false;
        up_key_material candidate;
        if (!up_resolve_with_model(ctx, sinf, sinf_length, registry->packs[index].bytes,
                                   registry->packs[index].length, &candidate, &mismatch)) {
            if (mismatch) {
                continue;
            }
            char *detail = up_take_error(ctx);
            int result = up_fail(ctx, "FairPlay model %zu: %s", index,
                                 detail == NULL ? "unknown error" : detail);
            free(detail);
            return result;
        }
        decoded_count++;
        if (decoded_count > 1) {
            return up_fail(
                ctx, "FairPlay model registry has multiple models that decode SINF for selector %s",
                selector_id);
        }
        selected = candidate;
        chosen = index;
    }
    if (decoded_count == 1) {
        *out = selected;
        if (selected_index != NULL) {
            *selected_index = chosen;
        }
        return 1;
    }
    if (matched_selector) {
        return up_fail(ctx,
                       "FairPlay model registry has no model that decodes SINF for selector %s",
                       selector_id);
    }
    return up_fail(ctx, "FairPlay model registry has no model for selector %s", selector_id);
}

void up_license_set_free(up_license_set *set) {
    if (set == NULL) {
        return;
    }
    for (size_t index = 0; index < set->count; index++) {
        free(set->items[index].member);
    }
    free(set->items);
    set->items = NULL;
    set->count = 0;
}

static int up_license_append(up_context *ctx, up_license_set *set, const char *member,
                             const uint8_t *sinf, size_t sinf_length,
                             const up_key_material *material) {
    up_license *grown = realloc(set->items, (set->count + 1) * sizeof(up_license));
    if (grown == NULL) {
        return up_fail(ctx, "out of memory");
    }
    set->items = grown;
    up_license *license = &set->items[set->count];
    memset(license, 0, sizeof(*license));
    license->member = malloc(strlen(member) + 1);
    if (license->member == NULL) {
        return up_fail(ctx, "out of memory");
    }
    memcpy(license->member, member, strlen(member) + 1);
    up_digest_hex(sinf, sinf_length, license->request_sinf_sha256);
    license->material = *material;
    set->count++;
    return 1;
}

int up_resolve_ipa_licenses(up_context *ctx,
                            up_ipa_inventory *inventory,
                            const char *model_path,
                            up_license_set *out) {
    memset(out, 0, sizeof(*out));
    if (model_path == NULL || model_path[0] == '\0') {
        return up_fail(ctx, "no saved enrollment models; pass --model FILE or --model DIRECTORY");
    }
    struct stat info;
    if (stat(model_path, &info) != 0) {
        int error = errno;
        return up_fail(ctx, "inspect FairPlay enrollment model: %s", strerror(error));
    }
    bool registry_mode = S_ISDIR(info.st_mode);
    up_model_registry registry;
    memset(&registry, 0, sizeof(registry));
    if (registry_mode) {
        if (!up_read_model_registry(ctx, model_path, &registry)) {
            return 0;
        }
    } else {
        up_model_pack pack;
        if (!up_read_model_file(ctx, model_path, &pack)) {
            return 0;
        }
        registry.packs = malloc(sizeof(up_model_pack));
        if (registry.packs == NULL) {
            up_model_pack_free(&pack);
            return up_fail(ctx, "out of memory");
        }
        registry.packs[0] = pack;
        registry.count = 1;
    }

    int status = 1;
    for (size_t image_index = 0; image_index < inventory->image_count && status; image_index++) {
        const char *sinf_member = inventory->images[image_index].sinf_member;
        bool already = false;
        for (size_t index = 0; index < out->count; index++) {
            if (strcmp(out->items[index].member, sinf_member) == 0) {
                already = true;
                break;
            }
        }
        if (already) {
            continue;
        }
        const up_zip_entry *entry = up_ipa_entry(ctx, inventory, sinf_member);
        if (entry == NULL) {
            status = 0;
            break;
        }
        uint8_t *sinf = NULL;
        size_t sinf_length = 0;
        if (!up_zip_read(ctx, &inventory->archive, entry, &sinf, &sinf_length)) {
            status = 0;
            break;
        }
        up_key_material material;
        bool resolved = registry_mode
                            ? up_resolve_with_registry(ctx, sinf, sinf_length, &registry, &material,
                                                       NULL)
                            : up_resolve_with_model(ctx, sinf, sinf_length, registry.packs[0].bytes,
                                                    registry.packs[0].length, &material, NULL);
        if (!resolved) {
            char *detail = up_take_error(ctx);
            status = up_fail(ctx, "SINF \"%s\": %s", sinf_member,
                             detail == NULL ? "unknown error" : detail);
            free(detail);
            free(sinf);
            break;
        }
        status = up_license_append(ctx, out, sinf_member, sinf, sinf_length, &material);
        free(sinf);
    }
    up_model_registry_free(&registry);
    if (!status) {
        up_license_set_free(out);
        return 0;
    }
    return 1;
}
