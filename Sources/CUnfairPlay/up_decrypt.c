//
//  up_decrypt.c
//  CUnfairPlay
//
//  Port of DecryptIPA and its path/publish helpers. The ARM64 first-page
//  decoder from golang.org/x/arch is intentionally absent; SINF structural
//  validation is the fail-closed gate and the report records
//  `first_page_audit: "not-performed"`.
//

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "up_crypto.h"
#include "up_ipa.h"
#include "up_license.h"
#include "up_macho.h"
#include "up_pagekey.h"
#include "up_report.h"
#include "up_supf.h"

// MARK: - Paths

static char *up_copy_string(const char *value) {
    size_t length = strlen(value);
    char *copy = malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, value, length + 1);
    }
    return copy;
}

static char *up_join_strings(const char *left, const char *right) {
    size_t left_length = strlen(left);
    size_t right_length = strlen(right);
    char *result = malloc(left_length + right_length + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, left, left_length);
    memcpy(result + left_length, right, right_length);
    result[left_length + right_length] = '\0';
    return result;
}

static char *up_absolute_path(const char *path) {
    if (path[0] == '/') {
        return up_copy_string(path);
    }
    char directory[PATH_MAX];
    if (getcwd(directory, sizeof(directory)) == NULL) {
        return NULL;
    }
    char *prefix = up_join_strings(directory, "/");
    if (prefix == NULL) {
        return NULL;
    }
    char *result = up_join_strings(prefix, path);
    free(prefix);
    return result;
}

static char *up_directory_of(const char *path) {
    size_t end = strlen(path);
    while (end > 1 && path[end - 1] == '/') {
        end--;
    }
    size_t cut = end;
    while (cut > 0 && path[cut - 1] != '/') {
        cut--;
    }
    if (cut == 0) {
        return up_copy_string(".");
    }
    if (cut == 1) {
        return up_copy_string("/");
    }
    char *result = malloc(cut);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, path, cut - 1);
    result[cut - 1] = '\0';
    return result;
}

static char *up_base_of(const char *path) {
    size_t end = strlen(path);
    while (end > 1 && path[end - 1] == '/') {
        end--;
    }
    size_t start = end;
    while (start > 0 && path[start - 1] != '/') {
        start--;
    }
    size_t length = end - start;
    char *result = malloc(length + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, path + start, length);
    result[length] = '\0';
    return result;
}

/// `filepath.EvalSymlinks` with a recursive parent fallback for new files.
static int up_canonical_path(up_context *ctx, const char *name, char **out) {
    *out = NULL;
    if (name == NULL || name[0] == '\0') {
        return up_fail(ctx, "FairPlay file path is empty");
    }
    char *absolute = up_absolute_path(name);
    if (absolute == NULL) {
        return up_fail(ctx, "resolve FairPlay path: %s", strerror(errno));
    }
    char resolved[PATH_MAX];
    if (realpath(absolute, resolved) != NULL) {
        free(absolute);
        *out = up_copy_string(resolved);
        if (*out == NULL) {
            return up_fail(ctx, "out of memory");
        }
        return 1;
    }
    int error = errno;
    if (error != ENOENT) {
        free(absolute);
        return up_fail(ctx, "resolve FairPlay path: %s", strerror(error));
    }
    struct stat info;
    if (lstat(absolute, &info) == 0 && S_ISLNK(info.st_mode)) {
        int status = up_fail(ctx, "dangling symlink: %s", absolute);
        free(absolute);
        return status;
    }
    char *parent = up_directory_of(absolute);
    if (parent == NULL) {
        free(absolute);
        return up_fail(ctx, "out of memory");
    }
    if (strcmp(parent, absolute) == 0) {
        int status = up_fail(ctx, "resolve FairPlay path: %s", strerror(error));
        free(parent);
        free(absolute);
        return status;
    }
    char *resolved_parent = NULL;
    if (!up_canonical_path(ctx, parent, &resolved_parent)) {
        free(parent);
        free(absolute);
        return 0;
    }
    char *base = up_base_of(absolute);
    free(parent);
    free(absolute);
    if (base == NULL) {
        free(resolved_parent);
        return up_fail(ctx, "out of memory");
    }
    char *prefix = up_join_strings(resolved_parent, "/");
    free(resolved_parent);
    if (prefix == NULL) {
        free(base);
        return up_fail(ctx, "out of memory");
    }
    char *result = up_join_strings(prefix, base);
    free(prefix);
    free(base);
    if (result == NULL) {
        return up_fail(ctx, "out of memory");
    }
    *out = result;
    return 1;
}

static bool up_paths_alias(const char *left, const char *right) {
    if (strcmp(left, right) == 0 || strcasecmp(left, right) == 0) {
        return true;
    }
    struct stat left_info;
    struct stat right_info;
    if (stat(left, &left_info) != 0 || stat(right, &right_info) != 0) {
        return false;
    }
    return left_info.st_dev == right_info.st_dev && left_info.st_ino == right_info.st_ino;
}

typedef struct {
    char *input;
    char *output;
    char *report;
    char *model;
} up_paths;

static void up_paths_free(up_paths *paths) {
    free(paths->input);
    free(paths->output);
    free(paths->report);
    free(paths->model);
    memset(paths, 0, sizeof(*paths));
}

static int up_validate_paths(up_context *ctx,
                             const char *input,
                             const char *output,
                             const char *report,
                             const char *model,
                             bool force,
                             up_paths *out) {
    memset(out, 0, sizeof(*out));
    if (!up_canonical_path(ctx, input, &out->input)) {
        return 0;
    }
    struct stat info;
    if (stat(out->input, &info) != 0) {
        int error = errno;
        up_paths_free(out);
        return up_fail(ctx, "inspect FairPlay input: %s", strerror(error));
    }
    if (!S_ISREG(info.st_mode)) {
        int status = up_fail(ctx, "FairPlay input must be a regular file: %s", out->input);
        up_paths_free(out);
        return status;
    }
    if (model != NULL && model[0] != '\0') {
        if (!up_canonical_path(ctx, model, &out->model)) {
            up_paths_free(out);
            return 0;
        }
        if (stat(out->model, &info) != 0) {
            int error = errno;
            up_paths_free(out);
            return up_fail(ctx, "inspect FairPlay enrollment model: %s", strerror(error));
        }
        if (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode)) {
            int status =
                up_fail(ctx, "FairPlay enrollment model must be a regular file or directory: %s",
                        out->model);
            up_paths_free(out);
            return status;
        }
    }
    const char *destination_names[2] = {output, report};
    char **destinations[2] = {&out->output, &out->report};
    for (size_t index = 0; index < 2; index++) {
        bool existed = false;
        if (lstat(destination_names[index], &info) == 0) {
            existed = true;
            if (!S_ISREG(info.st_mode)) {
                int status = up_fail(
                    ctx, "FairPlay destination must be a regular file, not a symlink or directory: %s",
                    destination_names[index]);
                up_paths_free(out);
                return status;
            }
        } else if (errno != ENOENT) {
            int error = errno;
            up_paths_free(out);
            return up_fail(ctx, "inspect FairPlay destination: %s", strerror(error));
        }
        if (!up_canonical_path(ctx, destination_names[index], destinations[index])) {
            up_paths_free(out);
            return 0;
        }
        if (up_paths_alias(*destinations[index], out->input) ||
            (out->model != NULL && up_paths_alias(*destinations[index], out->model))) {
            int status = up_fail(ctx, "refusing to overwrite FairPlay input or private state: %s",
                                 *destinations[index]);
            up_paths_free(out);
            return status;
        }
        if (existed && !force) {
            int status = up_fail(ctx, "refusing to replace %s", *destinations[index]);
            up_paths_free(out);
            return status;
        }
    }
    if (up_paths_alias(out->output, out->report)) {
        up_paths_free(out);
        return up_fail(ctx, "FairPlay output and report paths must be distinct");
    }
    return 1;
}

int up_mkdir_all(up_context *ctx, const char *path, mode_t mode) {
    struct stat info;
    if (stat(path, &info) == 0) {
        if (S_ISDIR(info.st_mode)) {
            return 1;
        }
        return up_fail(ctx, "create directory %s: %s", path, strerror(ENOTDIR));
    }
    if (errno != ENOENT) {
        return up_fail(ctx, "create directory %s: %s", path, strerror(errno));
    }
    char *parent = up_directory_of(path);
    if (parent == NULL) {
        return up_fail(ctx, "out of memory");
    }
    int status = strcmp(parent, path) == 0 ? 1 : up_mkdir_all(ctx, parent, mode);
    free(parent);
    if (!status) {
        return 0;
    }
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        return up_fail(ctx, "create directory %s: %s", path, strerror(errno));
    }
    return 1;
}

/// Creates `/dir/.fairplay-XXXXXX` with mkstemp and returns the path.
static char *up_create_temporary(up_context *ctx, const char *directory) {
    char *prefix = up_join_strings(directory, "/.fairplay-XXXXXX");
    if (prefix == NULL) {
        up_fail(ctx, "out of memory");
        return NULL;
    }
    int descriptor = mkstemp(prefix);
    if (descriptor < 0) {
        int error = errno;
        up_fail(ctx, "create temporary file: %s", strerror(error));
        free(prefix);
        return NULL;
    }
    close(descriptor);
    return prefix;
}

// MARK: - Publication

typedef struct {
    char *temporary;
    char *destination;
    char *backup;
    struct stat info;
    bool published;
} up_staged_file;

static char *up_backup_destination(up_context *ctx, const char *destination) {
    struct stat info;
    if (lstat(destination, &info) != 0) {
        if (errno == ENOENT) {
            return up_copy_string("");
        }
        up_fail(ctx, "inspect destination %s: %s", destination, strerror(errno));
        return NULL;
    }
    if (!S_ISREG(info.st_mode)) {
        up_fail(ctx, "refusing to replace non-regular destination %s", destination);
        return NULL;
    }
    char *directory = up_directory_of(destination);
    if (directory == NULL) {
        up_fail(ctx, "out of memory");
        return NULL;
    }
    char *prefix = up_join_strings(directory, "/.fairplay-backup-XXXXXX");
    free(directory);
    if (prefix == NULL) {
        up_fail(ctx, "out of memory");
        return NULL;
    }
    if (mkdtemp(prefix) == NULL) {
        int error = errno;
        up_fail(ctx, "create backup directory: %s", strerror(error));
        free(prefix);
        return NULL;
    }
    char *backup = up_join_strings(prefix, "/previous");
    free(prefix);
    if (backup == NULL) {
        up_fail(ctx, "out of memory");
        return NULL;
    }
    if (link(destination, backup) != 0) {
        int error = errno;
        up_fail(ctx, "backup %s: %s", destination, strerror(error));
        char *containing = up_directory_of(backup);
        if (containing != NULL) {
            rmdir(containing);
            free(containing);
        }
        free(backup);
        return NULL;
    }
    return backup;
}

static void up_remove_backup(char *backup) {
    if (backup == NULL || backup[0] == '\0') {
        return;
    }
    unlink(backup);
    char *directory = up_directory_of(backup);
    if (directory != NULL) {
        rmdir(directory);
        free(directory);
    }
}

static void up_rollback_files(up_staged_file *files, size_t count) {
    for (size_t index = count; index > 0; index--) {
        up_staged_file *file = &files[index - 1];
        if (!file->published) {
            continue;
        }
        struct stat current;
        if (lstat(file->destination, &current) == 0 &&
            current.st_dev == file->info.st_dev && current.st_ino == file->info.st_ino) {
            if (file->backup != NULL && file->backup[0] != '\0') {
                rename(file->backup, file->destination);
            } else {
                unlink(file->destination);
            }
        }
        up_remove_backup(file->backup);
    }
}

static int up_publish_files(up_context *ctx, up_staged_file *files, size_t count, bool force) {
    for (size_t index = 0; index < count; index++) {
        up_staged_file *file = &files[index];
        if (stat(file->temporary, &file->info) != 0) {
            int error = errno;
            up_rollback_files(files, index);
            return up_fail(ctx, "publish %s: %s", file->destination, strerror(error));
        }
        int error = 0;
        if (force) {
            file->backup = up_backup_destination(ctx, file->destination);
            if (file->backup == NULL) {
                up_rollback_files(files, index);
                return 0;
            }
            if (rename(file->temporary, file->destination) != 0) {
                error = errno;
                up_remove_backup(file->backup);
                free(file->backup);
                file->backup = NULL;
            }
        } else if (link(file->temporary, file->destination) != 0) {
            error = errno;
        }
        if (error != 0) {
            up_rollback_files(files, index);
            return up_fail(ctx, "publish %s: %s", file->destination, strerror(error));
        }
        file->published = true;
    }
    for (size_t index = 0; index < count; index++) {
        up_remove_backup(files[index].backup);
    }
    return 1;
}

// MARK: - Image decryption

static void up_digest_hex(const uint8_t *bytes, size_t length, char output[65]) {
    uint8_t digest[32];
    up_sha256(bytes, length, digest);
    up_hex_encode(digest, sizeof(digest), output);
}

static int up_decrypt_image(up_context *ctx,
                            uint8_t *output,
                            size_t output_length,
                            const up_encrypted_image *image,
                            const uint8_t *records,
                            size_t record_count,
                            const uint8_t mask[16],
                            up_page_deriver *deriver,
                            up_image_result *result) {
    memset(result, 0, sizeof(*result));
    result->image = image;
    if (image->layout.crypt_id != 1) {
        return up_fail(ctx, "%s: expected cryptid 1", image->member);
    }
    size_t start = image->layout.crypt_offset;
    size_t end = start + image->layout.crypt_size;
    size_t identifier = (size_t)image->layout.crypt_id_offset;
    if (image->layout.crypt_id_offset < 0 || identifier + 4 > start ||
        end < start || end > output_length) {
        return up_fail(ctx, "%s: invalid FairPlay mutation ranges", image->member);
    }
    up_digest_hex(output, output_length, result->encrypted_sha256);
    uint8_t prefix_digest[32];
    uint8_t header_digest[32];
    uint8_t suffix_digest[32];
    up_sha256(output, identifier, prefix_digest);
    up_sha256(output + identifier + 4, start - identifier - 4, header_digest);
    up_sha256(output + end, output_length - end, suffix_digest);

    up_code_directory_audit *audits = NULL;
    size_t audit_count = 0;
    if (!up_audit_code_directories(ctx, output, output_length, &image->layout, &audits,
                                   &audit_count)) {
        return 0;
    }
    for (size_t index = 0; index < audit_count; index++) {
        if (audits[index].matched_slots != audits[index].slot_count) {
            free(audits);
            return up_fail(ctx, "%s: encrypted source fails CodeDirectory", image->member);
        }
    }
    result->audits = audits;
    result->audit_count = audit_count;

    if (record_count * UP_PAGE_BYTES != image->layout.crypt_size) {
        up_image_result_free(result);
        return up_fail(ctx, "%s: encrypted page geometry changed", image->member);
    }
    if (start + UP_PAGE_BYTES > output_length) {
        up_image_result_free(result);
        return up_fail(ctx, "%s: encrypted page geometry changed", image->member);
    }
    up_sha256_ctx *keys_hash = up_sha256_create();
    if (keys_hash == NULL) {
        up_image_result_free(result);
        return up_fail(ctx, "out of memory");
    }
    for (size_t index = 0; index < record_count; index++) {
        const uint8_t *record = records + index * 32;
        uint8_t key[16];
        uint64_t offset = image->slice_offset + image->layout.crypt_offset +
                          (uint64_t)index * UP_PAGE_BYTES;
        up_page_key(deriver, record, offset, false, key);
        up_sha256_update(keys_hash, key, sizeof(key));
        uint8_t *page = output + start + index * UP_PAGE_BYTES;
        bool decrypted = up_aes_cbc(false, key, record + 16, page, UP_PAGE_BYTES, page);
        memset(key, 0, sizeof(key));
        if (!decrypted) {
            up_sha256_release(keys_hash);
            up_image_result_free(result);
            return up_fail(ctx, "%s: AES-CBC decryption failed", image->member);
        }
    }
    uint8_t keys_digest[32];
    up_sha256_final(keys_hash, keys_digest);
    up_sha256_release(keys_hash);
    up_hex_encode(keys_digest, sizeof(keys_digest), result->ordered_page_keys_sha256);

    up_digest_hex(output + start, UP_PAGE_BYTES, result->first_plaintext_page_sha256);

    output[identifier] = 0;
    output[identifier + 1] = 0;
    output[identifier + 2] = 0;
    output[identifier + 3] = 0;
    uint8_t check[32];
    up_sha256(output, identifier, check);
    if (memcmp(check, prefix_digest, sizeof(check)) != 0) {
        up_image_result_free(result);
        return up_fail(ctx, "%s: mutation escaped FairPlay range", image->member);
    }
    up_sha256(output + identifier + 4, start - identifier - 4, check);
    if (memcmp(check, header_digest, sizeof(check)) != 0) {
        up_image_result_free(result);
        return up_fail(ctx, "%s: mutation escaped FairPlay range", image->member);
    }
    up_sha256(output + end, output_length - end, check);
    if (memcmp(check, suffix_digest, sizeof(check)) != 0) {
        up_image_result_free(result);
        return up_fail(ctx, "%s: mutation escaped FairPlay range", image->member);
    }

    up_digest_hex(output, output_length, result->decrypted_sha256);
    up_macho_architecture(image->layout.cpu_type, image->layout.cpu_subtype,
                          result->architecture);
    up_digest_hex(mask, 16, result->app_mask_sha256);
    result->pages = (int)record_count;
    return 1;
}

/// Port of validateInventoriedImages.
static int up_validate_inventoried_images(up_context *ctx,
                                          const uint8_t *blob,
                                          size_t length,
                                          const up_encrypted_image *const *images,
                                          size_t image_count) {
    if (image_count == 0) {
        return up_fail(ctx, "encrypted image inventory is empty");
    }
    up_macho_slice *slices = NULL;
    size_t slice_count = 0;
    if (!up_parse_macho_slices(ctx, blob, length, length, &slices, &slice_count)) {
        return 0;
    }
    up_macho_slice **encrypted = calloc(slice_count == 0 ? 1 : slice_count, sizeof(void *));
    if (encrypted == NULL) {
        up_macho_slices_free(slices, slice_count);
        return up_fail(ctx, "out of memory");
    }
    size_t encrypted_count = 0;
    for (size_t index = 0; index < slice_count; index++) {
        if (slices[index].layout.crypt_id != 0) {
            encrypted[encrypted_count++] = &slices[index];
        }
    }
    int status = 1;
    if (encrypted_count != image_count) {
        status = up_fail(ctx, "encrypted slice inventory changed");
    }
    for (size_t index = 0; index < encrypted_count && status; index++) {
        const up_macho_slice *slice = encrypted[index];
        const up_encrypted_image *image = images[index];
        if (slice->offset != image->slice_offset || slice->size != image->slice_size ||
            !up_macho_layout_equal(&slice->layout, &image->layout)) {
            status = up_fail(ctx, "encrypted slice %zu changed after inventory", index);
            break;
        }
    }
    free(encrypted);
    up_macho_slices_free(slices, slice_count);
    return status;
}

// MARK: - IPA rewrite

static const up_license *up_license_for(const up_license_set *licenses, const char *member) {
    for (size_t index = 0; index < licenses->count; index++) {
        if (strcmp(licenses->items[index].member, member) == 0) {
            return &licenses->items[index];
        }
    }
    return NULL;
}

static int up_file_sha256(up_context *ctx, const char *path, char output[65]) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return up_fail(ctx, "hash output: %s", strerror(errno));
    }
    up_sha256_ctx *hash = up_sha256_create();
    if (hash == NULL) {
        fclose(file);
        return up_fail(ctx, "out of memory");
    }
    uint8_t chunk[65536];
    size_t read = 0;
    while ((read = fread(chunk, 1, sizeof(chunk), file)) != 0) {
        up_sha256_update(hash, chunk, read);
    }
    if (ferror(file)) {
        int error = errno;
        fclose(file);
        up_sha256_release(hash);
        return up_fail(ctx, "hash output: %s", strerror(error));
    }
    fclose(file);
    uint8_t digest[32];
    up_sha256_final(hash, digest);
    up_sha256_release(hash);
    up_hex_encode(digest, sizeof(digest), output);
    return 1;
}

static int up_write_report_file(up_context *ctx, const char *path, const char *json) {
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        return up_fail(ctx, "write report: %s", strerror(errno));
    }
    size_t length = strlen(json);
    bool written = fwrite(json, 1, length, file) == length;
    if (written && fflush(file) != 0) {
        written = false;
    }
    if (written && fsync(fileno(file)) != 0) {
        written = false;
    }
    int error = errno;
    if (fclose(file) != 0 && written) {
        written = false;
        error = errno;
    }
    if (!written) {
        return up_fail(ctx, "write report: %s", strerror(error));
    }
    return 1;
}

typedef struct {
    const up_license *license;
    char hash[65];
} up_license_digest;

static int up_compare_license_digests(const void *left, const void *right) {
    const up_license_digest *left_value = left;
    const up_license_digest *right_value = right;
    return strcmp(left_value->license->member, right_value->license->member);
}

int up_decrypt(up_context *ctx,
               const char *ipa_path,
               const char *output_path,
               const char *report_path,
               int force,
               char **result_json_out) {
    if (result_json_out != NULL) {
        *result_json_out = NULL;
    }
    up_paths paths;
    if (!up_validate_paths(ctx, ipa_path, output_path, report_path, ctx->model_directory,
                           force != 0, &paths)) {
        return 0;
    }
    int status = 1;
    up_ipa_inventory inventory;
    memset(&inventory, 0, sizeof(inventory));
    inventory.archive.descriptor = -1;
    up_license_set licenses;
    memset(&licenses, 0, sizeof(licenses));
    up_image_result *image_results = NULL;
    size_t image_result_count = 0;
    size_t pages = 0;
    char *output_temporary = NULL;
    char *report_temporary = NULL;
    char *report_json = NULL;
    up_license_digest *digests = NULL;
    uint8_t digest[32];
    up_zip_writer writer;
    memset(&writer, 0, sizeof(writer));
    up_buf_init(&writer.central);

    char *output_directory = up_directory_of(paths.output);
    char *report_directory = up_directory_of(paths.report);
    if (output_directory == NULL || report_directory == NULL) {
        status = up_fail(ctx, "out of memory");
        goto cleanup;
    }
    if (!up_mkdir_all(ctx, output_directory, 0700) ||
        !up_mkdir_all(ctx, report_directory, 0700)) {
        status = 0;
        goto cleanup;
    }
    if (!up_ipa_inventory_open(ctx, paths.input, &inventory)) {
        status = 0;
        goto cleanup;
    }
    if (!up_resolve_ipa_licenses(ctx, &inventory, paths.model, &licenses)) {
        status = 0;
        goto cleanup;
    }
    output_temporary = up_create_temporary(ctx, output_directory);
    if (output_temporary == NULL) {
        status = 0;
        goto cleanup;
    }
    if (!up_zip_writer_open(ctx, output_temporary, &writer)) {
        status = 0;
        goto cleanup;
    }
    for (size_t index = 0; index < inventory.archive.count && status; index++) {
        const up_zip_entry *entry = &inventory.archive.entries[index];
        if (up_zip_entry_is_directory(entry)) {
            size_t first = up_name_index_find(&inventory.index, &inventory.archive, entry->name);
            if (first != index) {
                continue; // Duplicate empty directory markers were validated.
            }
        }
        const up_encrypted_image *member_images[64];
        size_t member_image_count = 0;
        for (size_t image_index = 0; image_index < inventory.image_count; image_index++) {
            if (strcmp(inventory.images[image_index].member, entry->name) == 0) {
                if (member_image_count == sizeof(member_images) / sizeof(member_images[0])) {
                    status = up_fail(ctx, "%s: too many encrypted slices", entry->name);
                    break;
                }
                member_images[member_image_count++] = &inventory.images[image_index];
            }
        }
        if (!status) {
            break;
        }
        if (member_image_count == 0) {
            const uint8_t *raw = NULL;
            size_t raw_length = 0;
            if (!up_zip_raw(ctx, &inventory.archive, entry, &raw, &raw_length)) {
                status = 0;
                break;
            }
            if (!up_zip_writer_add_raw(ctx, &writer, entry, raw, raw_length)) {
                status = 0;
                break;
            }
            continue;
        }
        size_t blob_length = 0;
        const uint8_t *cached = up_ipa_cached(&inventory, entry->name, &blob_length);
        uint8_t *blob = NULL;
        if (cached == NULL) {
            if (!up_zip_read(ctx, &inventory.archive, entry, &blob, &blob_length)) {
                status = 0;
                break;
            }
        } else {
            blob = malloc(blob_length == 0 ? 1 : blob_length);
            if (blob == NULL) {
                status = up_fail(ctx, "out of memory");
                break;
            }
            memcpy(blob, cached, blob_length);
        }
        if (!up_validate_inventoried_images(ctx, blob, blob_length, member_images,
                                            member_image_count)) {
            char *detail = up_copy_string(up_last_error(ctx));
            status = up_fail(ctx, "%s: %s", entry->name,
                             detail == NULL ? "encrypted slice inventory changed" : detail);
            free(detail);
            free(blob);
            break;
        }
        const up_license *license = up_license_for(&licenses, member_images[0]->sinf_member);
        if (license == NULL) {
            status = up_fail(ctx, "missing license material for SINF \"%s\"",
                             member_images[0]->sinf_member);
            free(blob);
            break;
        }
        const up_supf_table *table = NULL;
        for (size_t table_index = 0; table_index < inventory.table_count; table_index++) {
            if (strcmp(inventory.tables[table_index].name, member_images[0]->supf_member) == 0) {
                table = &inventory.tables[table_index].table;
                break;
            }
        }
        if (table == NULL) {
            status = up_fail(ctx, "%s: inventoried SUPF is unavailable", entry->name);
            free(blob);
            break;
        }
        for (size_t image_index = 0; image_index < member_image_count && status; image_index++) {
            const up_encrypted_image *image = member_images[image_index];
            if (image->slice_offset + image->slice_size < image->slice_offset ||
                image->slice_offset + image->slice_size > blob_length) {
                status = up_fail(ctx, "%s slice changed after inventory", image->member);
                break;
            }
            const uint8_t *records = NULL;
            size_t record_count = 0;
            if (!up_supf_records(table, image->layout.cpu_type, image->layout.cpu_subtype,
                                 &records, &record_count)) {
                status = up_fail(ctx, "SUPF has no matching architecture 0x%x/0x%x",
                                 (unsigned)image->layout.cpu_type,
                                 (unsigned)image->layout.cpu_subtype);
                break;
            }
            up_image_result *grown = realloc(image_results,
                                             (image_result_count + 1) * sizeof(up_image_result));
            if (grown == NULL) {
                status = up_fail(ctx, "out of memory");
                break;
            }
            image_results = grown;
            up_page_deriver deriver;
            memcpy(&deriver, &license->material.deriver, sizeof(deriver));
            if (!up_decrypt_image(ctx, blob + image->slice_offset, image->slice_size, image,
                                  records, record_count, license->material.mask, &deriver,
                                  &image_results[image_result_count])) {
                status = 0;
                break;
            }
            image_result_count++;
            pages += record_count;
        }
        if (status && !up_zip_writer_add_bytes(ctx, &writer, entry, blob, blob_length)) {
            status = 0;
        }
        free(blob);
    }
    if (status && !up_zip_writer_finish(ctx, &writer)) {
        status = 0;
    }
    up_zip_writer_abort(&writer);
    if (!status) {
        goto cleanup;
    }
    char output_sha256[65];
    if (!up_file_sha256(ctx, output_temporary, output_sha256)) {
        status = 0;
        goto cleanup;
    }
    char input_sha256[65];
    up_sha256(inventory.archive.bytes, inventory.archive.length, digest);
    up_hex_encode(digest, sizeof(digest), input_sha256);

    const char *provider_name = "";
    const char *model_name = "";
    char shared_key_hash[65] = "";
    digests = calloc(licenses.count == 0 ? 1 : licenses.count, sizeof(up_license_digest));
    if (digests == NULL) {
        status = up_fail(ctx, "out of memory");
        goto cleanup;
    }
    for (size_t index = 0; index < licenses.count; index++) {
        up_digest_hex(licenses.items[index].material.logical, 16, digests[index].hash);
        digests[index].license = &licenses.items[index];
        if (index == 0) {
            snprintf(shared_key_hash, sizeof(shared_key_hash), "%s", digests[index].hash);
            provider_name = licenses.items[index].material.provider_kind;
            model_name = licenses.items[index].material.model_name;
            continue;
        }
        if (strcmp(shared_key_hash, digests[index].hash) != 0) {
            shared_key_hash[0] = '\0';
        }
        if (strcmp(provider_name, licenses.items[index].material.provider_kind) != 0) {
            provider_name = "multiple";
        }
        if (strcmp(model_name, licenses.items[index].material.model_name) != 0) {
            model_name = "multiple";
        }
    }
    qsort(digests, licenses.count, sizeof(up_license_digest), up_compare_license_digests);
    report_json = up_report_decryption_json(
        ctx, inventory.path, inventory.bytes, input_sha256, paths.output, output_sha256,
        &licenses, image_results, image_result_count, pages, provider_name, model_name,
        inventory.sha256);
    if (report_json == NULL) {
        status = 0;
        goto cleanup;
    }
    report_temporary = up_create_temporary(ctx, report_directory);
    if (report_temporary == NULL || !up_write_report_file(ctx, report_temporary, report_json)) {
        status = 0;
        goto cleanup;
    }
    up_paths revalidated;
    if (!up_validate_paths(ctx, paths.input, paths.output, paths.report, paths.model,
                           force != 0, &revalidated)) {
        status = 0;
        goto cleanup;
    }
    up_paths_free(&revalidated);
    up_staged_file staged[2];
    memset(staged, 0, sizeof(staged));
    staged[0].temporary = output_temporary;
    staged[0].destination = paths.output;
    staged[1].temporary = report_temporary;
    staged[1].destination = paths.report;
    if (!up_publish_files(ctx, staged, 2, force != 0)) {
        status = 0;
        goto cleanup;
    }
    output_temporary = NULL;
    report_temporary = NULL;

    if (result_json_out != NULL) {
        up_buf result;
        up_buf_init(&result);
        up_buf_append(&result, "{", 1);
        up_json_indent(&result, 1);
        up_json_key(&result, "OutputPath");
        up_json_string(&result, paths.output);
        up_buf_append(&result, ",", 1);
        up_json_indent(&result, 1);
        up_json_key(&result, "OutputSHA256");
        up_json_string(&result, output_sha256);
        up_buf_append(&result, ",", 1);
        up_json_indent(&result, 1);
        up_json_key(&result, "ReportPath");
        up_json_string(&result, paths.report);
        up_buf_append(&result, ",", 1);
        up_json_indent(&result, 1);
        up_json_key(&result, "EncryptedImages");
        up_json_uint(&result, image_result_count);
        up_buf_append(&result, ",", 1);
        up_json_indent(&result, 1);
        up_json_key(&result, "DecryptedPages");
        up_json_uint(&result, pages);
        up_buf_append(&result, ",", 1);
        up_json_indent(&result, 1);
        up_json_key(&result, "LogicalKeySHA256");
        up_json_string(&result, shared_key_hash);
        up_buf_append(&result, ",", 1);
        up_json_indent(&result, 1);
        up_json_key(&result, "LogicalKeySHA256BySINF");
        up_buf_append(&result, "{", 1);
        for (size_t index = 0; index < licenses.count; index++) {
            if (index != 0) {
                up_buf_append(&result, ",", 1);
            }
            up_json_indent(&result, 2);
            up_json_key(&result, digests[index].license->member);
            up_json_string(&result, digests[index].hash);
        }
        if (licenses.count != 0) {
            up_json_indent(&result, 1);
        }
        up_buf_append(&result, "}", 1);
        up_json_indent(&result, 0);
        up_buf_append(&result, "}", 1);
        up_buf_append(&result, "\n", 1);
        *result_json_out = up_buf_detach(&result, ctx);
        if (*result_json_out == NULL) {
            status = 0;
        }
    }

cleanup:
    free(digests);
    up_zip_writer_abort(&writer);
    if (status == 0 && ctx->error == NULL) {
        up_fail(ctx, "unspecified decryption failure");
    }
    if (report_json != NULL) {
        free(report_json);
    }
    if (output_temporary != NULL) {
        unlink(output_temporary);
        free(output_temporary);
    }
    if (report_temporary != NULL) {
        unlink(report_temporary);
        free(report_temporary);
    }
    free(output_directory);
    free(report_directory);
    for (size_t index = 0; index < image_result_count; index++) {
        up_image_result_free(&image_results[index]);
    }
    free(image_results);
    up_license_set_free(&licenses);
    up_ipa_inventory_close(&inventory);
    up_paths_free(&paths);
    return status;
}
