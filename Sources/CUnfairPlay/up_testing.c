//
//  up_testing.c
//  CUnfairPlay
//

#include "up_testing.h"

#include "up_internal.h"
#include "up_model.h"
#include "up_pagekey.h"
#include "up_sinf.h"
#include "up_supf.h"
#include "up_zip.h"

static void up_test_copy_error(up_context *ctx, char **error_out) {
    if (error_out == NULL) {
        return;
    }
    const char *message = up_last_error(ctx);
    size_t length = strlen(message);
    char *copy = malloc(length + 1);
    if (copy == NULL) {
        *error_out = NULL;
        return;
    }
    memcpy(copy, message, length + 1);
    *error_out = copy;
}

void up_test_app_mask(const uint8_t logical[16], uint8_t mask[16]) {
    up_app_mask_from_logical_key(logical, mask);
}

void up_test_page_key(const uint8_t mask[16],
                      const uint8_t wrapped[16],
                      uint64_t offset,
                      int little_endian,
                      uint8_t key[16]) {
    up_page_deriver deriver;
    up_page_deriver_init(&deriver, mask);
    up_page_key(&deriver, wrapped, offset, little_endian != 0, key);
}

int up_test_parse_model(const uint8_t *pack,
                        size_t length,
                        uint32_t *version,
                        int *has_selector,
                        uint32_t *selector_user,
                        uint32_t *selector_key,
                        char **error_out) {
    up_context *ctx = up_context_create(NULL);
    up_model model;
    int result = up_model_parse(ctx, pack, length, &model);
    if (result && version != NULL) {
        *version = model.version;
    }
    if (result && has_selector != NULL) {
        *has_selector = model.has_selector ? 1 : 0;
    }
    if (result && selector_user != NULL) {
        *selector_user = model.selector.user;
    }
    if (result && selector_key != NULL) {
        *selector_key = model.selector.key;
    }
    if (!result) {
        up_test_copy_error(ctx, error_out);
    } else if (error_out != NULL) {
        *error_out = NULL;
    }
    up_context_free(ctx);
    return result;
}

int up_test_sinf_selector(const uint8_t *sinf,
                          size_t length,
                          uint32_t *user,
                          uint32_t *key,
                          char **error_out) {
    up_context *ctx = up_context_create(NULL);
    up_selector selector;
    int result = up_sinf_read_selector(ctx, sinf, length, &selector);
    if (result) {
        if (user != NULL) {
            *user = selector.user;
        }
        if (key != NULL) {
            *key = selector.key;
        }
    }
    if (!result) {
        up_test_copy_error(ctx, error_out);
    } else if (error_out != NULL) {
        *error_out = NULL;
    }
    up_context_free(ctx);
    return result;
}

int up_test_resolve_logical_key(const uint8_t *sinf,
                                size_t sinf_length,
                                const uint8_t *pack,
                                size_t pack_length,
                                uint8_t logical[16],
                                uint32_t *model_version,
                                int *profile_mismatch,
                                char **error_out) {
    up_context *ctx = up_context_create(NULL);
    up_model model;
    int status = up_model_parse(ctx, pack, pack_length, &model);
    if (!status) {
        up_test_copy_error(ctx, error_out);
        up_context_free(ctx);
        return 0;
    }
    bool mismatch = false;
    status = up_resolve_logical_key(ctx, sinf, sinf_length, &model, logical, NULL, &mismatch);
    if (model_version != NULL) {
        *model_version = model.version;
    }
    if (profile_mismatch != NULL) {
        *profile_mismatch = mismatch ? 1 : 0;
    }
    if (!status) {
        up_test_copy_error(ctx, error_out);
    } else if (error_out != NULL) {
        *error_out = NULL;
    }
    up_context_free(ctx);
    return status;
}

// MARK: - ZIP

static void up_test_zip_init_entry(up_zip_entry *entry,
                                   char *name,
                                   uint16_t method,
                                   uint32_t external_attributes) {
    memset(entry, 0, sizeof(*entry));
    entry->name = name;
    entry->method = method;
    entry->version_made_by = 20;
    entry->version_needed = 20;
    entry->external_attributes = external_attributes;
}

/// Reads `name` back three ways: whole member, prefix, and raw extent.
static int up_test_zip_check_member(up_context *ctx,
                                    const up_zip *archive,
                                    const char *name,
                                    const uint8_t *payload,
                                    size_t length) {
    size_t index = up_zip_find(archive, name);
    if (index == SIZE_MAX) {
        return up_fail(ctx, "zip: member %s is missing", name);
    }
    const up_zip_entry *entry = &archive->entries[index];
    uint8_t *bytes = NULL;
    size_t byte_count = 0;
    if (!up_zip_read(ctx, archive, entry, &bytes, &byte_count)) {
        return 0;
    }
    int status = 1;
    if (byte_count != length || memcmp(bytes, payload, length) != 0) {
        status = up_fail(ctx, "zip: member %s content changed", name);
    }
    free(bytes);
    if (!status) {
        return 0;
    }
    size_t limit = length / 2;
    bytes = NULL;
    byte_count = 0;
    if (!up_zip_read_prefix(ctx, archive, entry, limit, &bytes, &byte_count)) {
        return 0;
    }
    if (byte_count != limit || memcmp(bytes, payload, limit) != 0) {
        status = up_fail(ctx, "zip: member %s prefix changed", name);
    }
    free(bytes);
    if (!status) {
        return 0;
    }
    const uint8_t *raw = NULL;
    size_t raw_length = 0;
    if (!up_zip_raw(ctx, archive, entry, &raw, &raw_length)) {
        return 0;
    }
    if (raw_length != (size_t)entry->compressed_size) {
        return up_fail(ctx, "zip: member %s raw extent changed", name);
    }
    return 1;
}

int up_test_zip_round_trip(const char *path,
                           const char *copy_path,
                           const uint8_t *payload,
                           size_t length,
                           char **error_out) {
    up_context *ctx = up_context_create(NULL);
    if (ctx == NULL) {
        if (error_out != NULL) {
            *error_out = NULL;
        }
        return 0;
    }
    up_zip_writer writer;
    up_zip_writer copy_writer;
    up_zip archive;
    up_zip copy_archive;
    memset(&writer, 0, sizeof(writer));
    memset(&copy_writer, 0, sizeof(copy_writer));
    memset(&archive, 0, sizeof(archive));
    memset(&copy_archive, 0, sizeof(copy_archive));
    archive.descriptor = -1;
    copy_archive.descriptor = -1;
    char stored_name[] = "stored.bin";
    char deflated_name[] = "deflated.bin";
    char directory_name[] = "folder/";
    up_zip_entry stored;
    up_zip_entry deflated;
    up_zip_entry directory;
    up_test_zip_init_entry(&stored, stored_name, 0, 0);
    up_test_zip_init_entry(&deflated, deflated_name, 8, 0);
    up_test_zip_init_entry(&directory, directory_name, 0, 0x10);
    size_t original_deflated = SIZE_MAX;
    size_t copied_deflated = SIZE_MAX;
    size_t copied_directory = SIZE_MAX;
    const up_zip_entry *original_entry = NULL;
    const up_zip_entry *copied_entry = NULL;
    size_t entry_index = 0;
    int status = 1;

    if (!up_zip_writer_open(ctx, path, &writer)) {
        status = 0;
        goto finish;
    }
    if (!up_zip_writer_add_bytes(ctx, &writer, &stored, payload, length) ||
        !up_zip_writer_add_bytes(ctx, &writer, &deflated, payload, length) ||
        !up_zip_writer_add_bytes(ctx, &writer, &directory, NULL, 0)) {
        up_zip_writer_abort(&writer);
        status = 0;
        goto finish;
    }
    if (!up_zip_writer_finish(ctx, &writer)) {
        status = 0;
        goto finish;
    }
    if (!up_zip_open(ctx, path, &archive)) {
        status = 0;
        goto finish;
    }
    if (!up_test_zip_check_member(ctx, &archive, stored_name, payload, length) ||
        !up_test_zip_check_member(ctx, &archive, deflated_name, payload, length)) {
        status = 0;
        goto finish;
    }

    if (!up_zip_writer_open(ctx, copy_path, &copy_writer)) {
        status = 0;
        goto finish;
    }
    for (entry_index = 0; entry_index < archive.count; entry_index++) {
        const up_zip_entry *entry = &archive.entries[entry_index];
        const uint8_t *raw = NULL;
        size_t raw_length = 0;
        if (!up_zip_raw(ctx, &archive, entry, &raw, &raw_length) ||
            !up_zip_writer_add_raw(ctx, &copy_writer, entry, raw, raw_length)) {
            up_zip_writer_abort(&copy_writer);
            status = 0;
            goto finish;
        }
    }
    if (!up_zip_writer_finish(ctx, &copy_writer)) {
        status = 0;
        goto finish;
    }
    if (!up_zip_open(ctx, copy_path, &copy_archive)) {
        status = 0;
        goto finish;
    }
    if (!up_test_zip_check_member(ctx, &copy_archive, stored_name, payload, length) ||
        !up_test_zip_check_member(ctx, &copy_archive, deflated_name, payload, length)) {
        status = 0;
        goto finish;
    }
    original_deflated = up_zip_find(&archive, deflated_name);
    copied_deflated = up_zip_find(&copy_archive, deflated_name);
    copied_directory = up_zip_find(&copy_archive, directory_name);
    if (original_deflated == SIZE_MAX || copied_deflated == SIZE_MAX) {
        status = up_fail(ctx, "zip: member %s is missing after the raw copy", deflated_name);
        goto finish;
    }
    original_entry = &archive.entries[original_deflated];
    copied_entry = &copy_archive.entries[copied_deflated];
    if (original_entry->compressed_size != copied_entry->compressed_size ||
        original_entry->uncompressed_size != copied_entry->uncompressed_size ||
        original_entry->crc32 != copied_entry->crc32 ||
        original_entry->method != copied_entry->method) {
        status = up_fail(ctx, "zip: raw copy changed %s", deflated_name);
        goto finish;
    }
    if (copied_directory == SIZE_MAX ||
        !up_zip_entry_is_directory(&copy_archive.entries[copied_directory])) {
        status = up_fail(ctx, "zip: directory member %s changed", directory_name);
        goto finish;
    }

finish:
    if (!status) {
        up_test_copy_error(ctx, error_out);
    } else if (error_out != NULL) {
        *error_out = NULL;
    }
    up_zip_close(&archive);
    up_zip_close(&copy_archive);
    up_context_free(ctx);
    return status;
}

// MARK: - SUPF

int up_test_supf_records(const uint8_t *blob,
                         size_t length,
                         uint32_t cpu_type,
                         uint32_t cpu_subtype,
                         uint8_t *records,
                         size_t records_capacity,
                         size_t *record_count,
                         size_t *architecture_count,
                         char **error_out) {
    up_context *ctx = up_context_create(NULL);
    if (ctx == NULL) {
        if (error_out != NULL) {
            *error_out = NULL;
        }
        return 0;
    }
    up_supf_table table;
    memset(&table, 0, sizeof(table));
    const uint8_t *source = NULL;
    size_t count = 0;
    int status = up_supf_parse(ctx, blob, length, &table);
    if (status) {
        status = up_supf_records(&table, cpu_type, cpu_subtype, &source, &count);
        if (!status) {
            up_fail(ctx, "SUPF has no matching architecture 0x%x/0x%x", (unsigned)cpu_type,
                    (unsigned)cpu_subtype);
        }
    }
    if (status && count * 32 > records_capacity) {
        status = up_fail(ctx, "SUPF record buffer is too small");
    }
    if (status && count != 0) {
        memcpy(records, source, count * 32);
    }
    if (record_count != NULL) {
        *record_count = status ? count : 0;
    }
    if (architecture_count != NULL) {
        *architecture_count = table.count;
    }
    if (!status) {
        up_test_copy_error(ctx, error_out);
    } else if (error_out != NULL) {
        *error_out = NULL;
    }
    up_supf_free(&table);
    up_context_free(ctx);
    return status;
}

