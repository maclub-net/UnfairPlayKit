//
//  up_report.h
//  CUnfairPlay
//
//  Decryption report serialization. Field order and JSON shape follow
//  internal/fairplay/report.go so the host app can decode both engines.
//

#ifndef UP_REPORT_H
#define UP_REPORT_H

#include "up_license.h"

typedef struct {
    const up_encrypted_image *image;
    char architecture[32];
    char encrypted_sha256[65];
    char decrypted_sha256[65];
    char first_plaintext_page_sha256[65];
    char ordered_page_keys_sha256[65];
    char app_mask_sha256[65];
    int pages;
    up_code_directory_audit *audits;
    size_t audit_count;
} up_image_result;

void up_image_result_free(up_image_result *result);

/// Builds `unfairplay-decryption-v1` as indented JSON with a trailing newline,
/// matching `json.Encoder` with a two-space indent.
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
                                const char *ipa_sha256);

#endif /* UP_REPORT_H */
