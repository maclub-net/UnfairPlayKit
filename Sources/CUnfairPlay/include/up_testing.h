//
//  up_testing.h
//  CUnfairPlay
//
//  Test surface. These helpers expose the internal pure functions so the
//  package's tests can compare them against vectors produced by the Go
//  upstream. They are not part of the supported API.
//

#ifndef UP_TESTING_H
#define UP_TESTING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void up_test_app_mask(const uint8_t logical[16], uint8_t mask[16]);

void up_test_page_key(const uint8_t mask[16],
                      const uint8_t wrapped[16],
                      uint64_t offset,
                      int little_endian,
                      uint8_t key[16]);

/// Returns 1 on success, 0 on failure with a NUL-terminated message in `error_out`
/// (released with up_string_free).
int up_test_parse_model(const uint8_t *pack,
                        size_t length,
                        uint32_t *version,
                        int *has_selector,
                        uint32_t *selector_user,
                        uint32_t *selector_key,
                        char **error_out);

int up_test_sinf_selector(const uint8_t *sinf,
                          size_t length,
                          uint32_t *user,
                          uint32_t *key,
                          char **error_out);

/// Parses `pack`, decodes `sinf`, and returns the logical key. `profile_mismatch`
/// follows the Go sentinel of the same name.
int up_test_resolve_logical_key(const uint8_t *sinf,
                                size_t sinf_length,
                                const uint8_t *pack,
                                size_t pack_length,
                                uint8_t logical[16],
                                uint32_t *model_version,
                                int *profile_mismatch,
                                char **error_out);

/// Writes `payload` to `path` as a stored and a deflated member, re-reads both
/// members (full, prefix, and raw extents), copies every member with
/// `up_zip_writer_add_raw` into `copy_path`, and re-reads the copy. Returns 1
/// when both archives round-trip byte for byte.
int up_test_zip_round_trip(const char *path,
                           const char *copy_path,
                           const uint8_t *payload,
                           size_t length,
                           char **error_out);

/// Parses `blob` and copies the 32-byte page-key records for
/// (`cpu_type`, `cpu_subtype`) into `records`. `records_capacity` must cover
/// the returned `record_count`.
int up_test_supf_records(const uint8_t *blob,
                         size_t length,
                         uint32_t cpu_type,
                         uint32_t cpu_subtype,
                         uint8_t *records,
                         size_t records_capacity,
                         size_t *record_count,
                         size_t *architecture_count,
                         char **error_out);

#ifdef __cplusplus
}
#endif

#endif /* UP_TESTING_H */
