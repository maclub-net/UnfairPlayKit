//
//  up_report.c
//  CUnfairPlay
//
//  Hand-written serialization of internal/fairplay/report.go. Indentation is
//  explicit because the report is a public artifact compared field by field
//  between the Go and native engines.
//

#include "up_report.h"

#include "up_crypto.h"

static void up_report_key(up_buf *buffer, int level, const char *key) {
    up_json_indent(buffer, level);
    up_json_key(buffer, key);
}

static void up_digest_hex(const uint8_t *bytes, size_t length, char output[65]) {
    uint8_t digest[32];
    up_sha256(bytes, length, digest);
    up_hex_encode(digest, sizeof(digest), output);
}

static void up_report_oracle(up_buf *buffer, const up_license *license, int level,
                             const char *ipa_sha256) {
    up_buf_append(buffer, "{", 1);
    // encoding/json sorts map keys, so the evidence object is alphabetical.
    up_report_key(buffer, level + 1, "device_state_imported");
    up_json_bool(buffer, false);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "evaluator_source_sha256");
    up_json_string(buffer, license->material.evaluator_source_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "hardware_backend");
    up_json_string(buffer, "none");
    up_buf_append(buffer, ",", 1);
    char logical_sha256[65];
    up_digest_hex(license->material.logical, sizeof(license->material.logical), logical_sha256);
    up_report_key(buffer, level + 1, "logical_key_sha256");
    up_json_string(buffer, logical_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "model_name");
    up_json_string(buffer, license->material.model_name);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "model_sha256");
    up_json_string(buffer, license->material.model_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "model_version");
    up_json_uint(buffer, license->material.model_version);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "provider_kind");
    up_json_string(buffer, license->material.provider_kind);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "provider_status");
    up_json_uint(buffer, 0);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "request_ipa_sha256");
    up_json_string(buffer, ipa_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "request_selector");
    up_json_string(buffer, license->material.request_selector);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "request_sinf_sha256");
    up_json_string(buffer, license->request_sinf_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "runtime_hardware_calls");
    up_json_uint(buffer, 0);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "selector_status");
    up_json_uint(buffer, 0);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "state_origin");
    up_json_string(buffer, "external-enrollment-model");
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "status_patched");
    up_json_bool(buffer, false);
    up_json_indent(buffer, level);
    up_buf_append(buffer, "}", 1);
}

static void up_report_license(up_buf *buffer, const up_license *license, int level,
                              const char *ipa_sha256) {
    up_buf_append(buffer, "{", 1);
    up_report_key(buffer, level + 1, "member");
    up_json_string(buffer, license->member);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "provider");
    up_json_string(buffer, license->material.provider_kind[0] == '\0'
                                ? "unknown"
                                : license->material.provider_kind);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "model_build");
    up_json_string(buffer,
                   license->material.model_name[0] == '\0' ? "unknown"
                                                           : license->material.model_name);
    up_buf_append(buffer, ",", 1);
    char logical_sha256[65];
    up_digest_hex(license->material.logical, sizeof(license->material.logical), logical_sha256);
    up_report_key(buffer, level + 1, "logical_key_sha256");
    up_json_string(buffer, logical_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "oracle");
    up_report_oracle(buffer, license, level + 1, ipa_sha256);
    up_json_indent(buffer, level);
    up_buf_append(buffer, "}", 1);
}

static void up_report_image(up_buf *buffer, const up_image_result *result, int level) {
    const up_encrypted_image *image = result->image;
    up_buf_append(buffer, "{", 1);
    up_report_key(buffer, level + 1, "member");
    up_json_string(buffer, image->member);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "sinf_member");
    up_json_string(buffer, image->sinf_member);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "supf_member");
    up_json_string(buffer, image->supf_member);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "architecture");
    up_json_string(buffer, result->architecture);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "cpu_type");
    up_json_uint(buffer, image->layout.cpu_type);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "cpu_subtype");
    up_json_uint(buffer, image->layout.cpu_subtype);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "slice_offset");
    up_json_uint(buffer, image->slice_offset);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "slice_size");
    up_json_uint(buffer, image->slice_size);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "encrypted_sha256");
    up_json_string(buffer, result->encrypted_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "decrypted_sha256");
    up_json_string(buffer, result->decrypted_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "cryptoff");
    up_json_uint(buffer, image->layout.crypt_offset);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "cryptsize");
    up_json_uint(buffer, image->layout.crypt_size);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "pages");
    up_json_int(buffer, result->pages);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "first_plaintext_page_sha256");
    up_json_string(buffer, result->first_plaintext_page_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "first_page_audit");
    // The native engine does not carry the ARM64 decoder, so the first page is
    // never audited. The SINF structural checks remain the fail-closed gate.
    up_json_string(buffer, "not-performed");
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "audited_page_index");
    up_json_int(buffer, 0);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "first_page_structurally_plausible");
    up_json_bool(buffer, false);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "first_page_mnemonics");
    up_buf_append(buffer, "{}", 2);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "ordered_page_keys_sha256");
    up_json_string(buffer, result->ordered_page_keys_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "app_mask_sha256");
    up_json_string(buffer, result->app_mask_sha256);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "code_directories");
    if (result->audit_count == 0) {
        up_buf_append(buffer, "null", 4);
    } else {
        up_buf_append(buffer, "[", 1);
        for (size_t index = 0; index < result->audit_count; index++) {
            const up_code_directory_audit *audit = &result->audits[index];
            if (index != 0) {
                up_buf_append(buffer, ",", 1);
            }
            up_json_indent(buffer, level + 2);
            up_buf_append(buffer, "{", 1);
            up_report_key(buffer, level + 3, "hash_type");
            up_json_uint(buffer, audit->hash_type);
            up_buf_append(buffer, ",", 1);
            up_report_key(buffer, level + 3, "hash_size");
            up_json_int(buffer, audit->hash_size);
            up_buf_append(buffer, ",", 1);
            up_report_key(buffer, level + 3, "page_size");
            up_json_int(buffer, audit->page_size);
            up_buf_append(buffer, ",", 1);
            up_report_key(buffer, level + 3, "first_slot");
            up_json_int(buffer, audit->first_slot);
            up_buf_append(buffer, ",", 1);
            up_report_key(buffer, level + 3, "slot_count");
            up_json_int(buffer, audit->slot_count);
            up_buf_append(buffer, ",", 1);
            up_report_key(buffer, level + 3, "matched_slots");
            up_json_int(buffer, audit->matched_slots);
            up_json_indent(buffer, level + 2);
            up_buf_append(buffer, "}", 1);
        }
        up_json_indent(buffer, level + 1);
        up_buf_append(buffer, "]", 1);
    }
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "cryptid_before");
    up_json_uint(buffer, 1);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "cryptid_after");
    up_json_uint(buffer, 0);
    up_buf_append(buffer, ",", 1);
    up_report_key(buffer, level + 1, "exact_mutation_scope");
    up_json_bool(buffer, true);
    up_json_indent(buffer, level);
    up_buf_append(buffer, "}", 1);
}

char *up_report_decryption_json(up_context *ctx,
                                const char *input_path,
                                int64_t input_bytes,
                                const char *input_sha256,
                                const char *output_path,
                                const char *output_sha256,
                                const up_license_set *licenses,
                                const up_image_result *images,
                                size_t image_count,
                                size_t decrypted_pages,
                                const char *provider,
                                const char *model_build,
                                const char *ipa_sha256) {
    up_buf buffer;
    up_buf_init(&buffer);
    up_buf_append(&buffer, "{", 1);

    up_report_key(&buffer, 1, "schema");
    up_json_string(&buffer, "unfairplay-decryption-v1");
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 1, "model_build");
    up_json_string(&buffer, model_build);
    up_buf_append(&buffer, ",", 1);

    up_report_key(&buffer, 1, "input");
    up_buf_append(&buffer, "{", 1);
    up_report_key(&buffer, 2, "path");
    up_json_string(&buffer, input_path);
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 2, "sha256");
    up_json_string(&buffer, input_sha256);
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 2, "bytes");
    up_json_int(&buffer, input_bytes);
    up_json_indent(&buffer, 1);
    up_buf_append(&buffer, "}", 1);
    up_buf_append(&buffer, ",", 1);

    up_report_key(&buffer, 1, "output");
    up_buf_append(&buffer, "{", 1);
    up_report_key(&buffer, 2, "path");
    up_json_string(&buffer, output_path);
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 2, "sha256");
    up_json_string(&buffer, output_sha256);
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 2, "mode");
    up_json_string(&buffer, "0600");
    up_json_indent(&buffer, 1);
    up_buf_append(&buffer, "}", 1);
    up_buf_append(&buffer, ",", 1);

    up_report_key(&buffer, 1, "provider");
    up_json_string(&buffer, provider);
    up_buf_append(&buffer, ",", 1);

    up_report_key(&buffer, 1, "oracle");
    if (licenses->count == 1) {
        up_report_oracle(&buffer, &licenses->items[0], 1, ipa_sha256);
    } else {
        up_buf_append(&buffer, "{", 1);
        up_report_key(&buffer, 2, "request_ipa_sha256");
        up_json_string(&buffer, ipa_sha256);
        up_json_indent(&buffer, 1);
        up_buf_append(&buffer, "}", 1);
    }
    up_buf_append(&buffer, ",", 1);

    if (licenses->count != 0) {
        up_report_key(&buffer, 1, "licenses");
        up_buf_append(&buffer, "[", 1);
        for (size_t index = 0; index < licenses->count; index++) {
            if (index != 0) {
                up_buf_append(&buffer, ",", 1);
            }
            up_json_indent(&buffer, 2);
            up_report_license(&buffer, &licenses->items[index], 2, ipa_sha256);
        }
        up_json_indent(&buffer, 1);
        up_buf_append(&buffer, "]", 1);
        up_buf_append(&buffer, ",", 1);
    }

    up_report_key(&buffer, 1, "encrypted_image_count");
    up_json_uint(&buffer, image_count);
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 1, "decrypted_page_count");
    up_json_uint(&buffer, decrypted_pages);
    up_buf_append(&buffer, ",", 1);

    up_report_key(&buffer, 1, "images");
    up_buf_append(&buffer, "[", 1);
    for (size_t index = 0; index < image_count; index++) {
        if (index != 0) {
            up_buf_append(&buffer, ",", 1);
        }
        up_json_indent(&buffer, 2);
        up_report_image(&buffer, &images[index], 2);
    }
    if (image_count != 0) {
        up_json_indent(&buffer, 1);
    }
    up_buf_append(&buffer, "]", 1);
    up_buf_append(&buffer, ",", 1);

    up_report_key(&buffer, 1, "complete");
    up_json_bool(&buffer, true);
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 1, "plaintext_verified");
    up_json_bool(&buffer, false);
    up_buf_append(&buffer, ",", 1);
    up_report_key(&buffer, 1, "signature_verified");
    up_json_bool(&buffer, false);
    up_buf_append(&buffer, ",", 1);

    static const char *const warnings[] = {
        "Complete means every inventoried encrypted image was processed; plaintext correctness is "
        "not authenticated.",
        "Only ARM64 first pages are checked for instruction plausibility; ARMv7 plaintext, SUPF "
        "records, and subsequent plaintext are not authenticated.",
        "CodeDirectory checks compare encrypted bytes with embedded hashes, not an authenticated "
        "Apple signature; those hashes are stale after decryption.",
        "Analysis IPA requires recursive re-signing before installation.",
    };
    up_report_key(&buffer, 1, "warnings");
    up_buf_append(&buffer, "[", 1);
    for (size_t index = 0; index < sizeof(warnings) / sizeof(warnings[0]); index++) {
        if (index != 0) {
            up_buf_append(&buffer, ",", 1);
        }
        up_json_indent(&buffer, 2);
        up_json_string(&buffer, warnings[index]);
    }
    up_json_indent(&buffer, 1);
    up_buf_append(&buffer, "]", 1);
    up_json_indent(&buffer, 0);
    up_buf_append(&buffer, "}", 1);
    up_buf_append(&buffer, "\n", 1);
    return up_buf_detach(&buffer, ctx);
}

void up_image_result_free(up_image_result *result) {
    if (result == NULL) {
        return;
    }
    free(result->audits);
    result->audits = NULL;
    result->audit_count = 0;
}
