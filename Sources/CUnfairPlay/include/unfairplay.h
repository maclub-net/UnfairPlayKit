//
//  unfairplay.h
//  CUnfairPlay
//
//  In-process FairPlay enrollment model reader and IPA decryptor.
//
//  Calling convention (aligned with the CSAP style used elsewhere in this
//  workspace): every entry point returns 1 on success and 0 on failure, the
//  failure detail is retrieved with up_last_error(), and every returned string
//  is owned by the caller and released with up_string_free().
//
//  A context is not thread safe. Create one context per task and do not share
//  it across threads.
//

#ifndef UNFAIRPLAY_H
#define UNFAIRPLAY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct up_context up_context;

/// Creates a context bound to a model directory. The directory may be NULL or
/// empty, which means "no model bound to this context".
up_context *up_context_create(const char *model_directory);

/// Releases the context and every model pack it holds.
void up_context_free(up_context *ctx);

/// Returns the most recent failure description, or an empty string.
const char *up_last_error(up_context *ctx);

/// Releases a string returned through a char ** out parameter.
void up_string_free(char *value);

/// Native engine version, for diagnostics only.
const char *up_version(void);

/// Scans the bound model directory and returns an `unfairplay-models-v1` JSON
/// document. Mirrors the Go implementation's hard checks: 0700 directory,
/// 0600 regular `.bin` files, no symlinks, at most 256 models, at least one.
int up_models_report(up_context *ctx, char **json_out);

/// Diagnoses an IPA against the bound model directory and returns an
/// `unfairplay-doctor-v1` JSON document. `ipa_path` may be NULL or empty, in
/// which case only the model side is inspected.
int up_doctor(up_context *ctx, const char *ipa_path, char **json_out);

/// Decrypts `ipa_path` into `output_path` and writes the private report to
/// `report_path`. Returns the CLI-compatible result JSON documented in
/// DecryptResult. `force` allows replacing existing files.
int up_decrypt(up_context *ctx,
               const char *ipa_path,
               const char *output_path,
               const char *report_path,
               int force,
               char **result_json_out);

// MARK: - Enrollment setup primitives

/// One `*/SC_Info/*.sinf` member found inside an IPA.
typedef struct {
    /// Member path inside the archive. Released with `up_setup_free_ipa_sinfs`.
    char *member;
    /// `%08x:%08x` when the SINF selector parsed, otherwise an empty string.
    char selector[18];
} up_setup_sinf;

/// Lists every `*/SC_Info/*.sinf` member in central-directory order.
/// Unparsable selectors are reported with an empty selector instead of failing.
int up_setup_list_ipa_sinfs(up_context *ctx,
                            const char *ipa_path,
                            up_setup_sinf **entries,
                            size_t *count);

void up_setup_free_ipa_sinfs(up_setup_sinf *entries, size_t count);

/// Reads one exact IPA member; a missing member is an error.
int up_setup_read_ipa_member(up_context *ctx,
                             const char *ipa_path,
                             const char *member,
                             uint8_t **bytes,
                             size_t *length);

void up_setup_free_bytes(uint8_t *bytes);

/// Parses a SINF byte range and writes its selector as `%08x:%08x`.
int up_setup_sinf_selector(up_context *ctx,
                           const uint8_t *blob,
                           size_t length,
                           char output[18]);

/// Copies the arm64e slice of `source` (fat or thin) into `destination` as a
/// mode-0600 file and reports its SHA-256 and byte count.
int up_setup_thin_fairplayd(up_context *ctx,
                            const char *source,
                            const char *destination,
                            char sha256[65],
                            int64_t *written);

/// SHA-256 and byte count of a regular file.
int up_setup_file_sha256(up_context *ctx,
                         const char *path,
                         char sha256[65],
                         int64_t *bytes);

// MARK: - Native recovery

/// Generated interpreter assets. Every asset is read-only for the duration of
/// one run; the caller keeps ownership.
typedef struct {
    const uint8_t *model_gz;
    size_t model_gz_length;
    const uint8_t *compact_cfg_gz;
    size_t compact_cfg_gz_length;
    const uint8_t *safe_extracted_gz;
    size_t safe_extracted_gz_length;
    const uint8_t *frame_gz;
    size_t frame_gz_length;
    const uint8_t *kernels;
    size_t kernels_length;
} up_recovery_assets;

/// Runtime inputs for one enrollment run. All paths are mode-0600 regular
/// files, matching the Go reference's private-input contract.
typedef struct {
    /// Sorted `suffix=path` pairs matching the virtual files the parser opens.
    const char *const *file_mappings;
    size_t file_mapping_count;
    /// Six raw bytes, or a `aa:bb:cc:dd:ee:ff` style text address.
    const char *hardware_path;
    /// Installed executable path written into the account-entry parser.
    const char *executable_path;
    /// Exact-build `fairplayd` slice enabling the extracted block table.
    const char *reference_path;
    /// Zero selects the default selection budget.
    int selection_max_blocks;
} up_recovery_options;

typedef struct {
    /// `FPSENR2` enrollment model. Released with `up_recovery_result_free`.
    uint8_t *model;
    size_t model_length;
    char state_sha256[65];
    int iterations;
    int extracted_block_hits;
} up_recovery_result;

/// Runs the enrollment CFGs and returns the generated enrollment model.
int up_recovery_run(up_context *ctx,
                    const up_recovery_assets *assets,
                    const up_recovery_options *options,
                    up_recovery_result *result);

void up_recovery_result_free(up_recovery_result *result);

#ifdef __cplusplus
}
#endif

#endif /* UNFAIRPLAY_H */
