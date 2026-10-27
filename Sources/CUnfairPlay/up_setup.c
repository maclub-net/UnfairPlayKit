//
//  up_setup.c
//  CUnfairPlay
//
//  File-level primitives for the native enrollment setup. The ZIP, Mach-O and
//  hashing implementations are the ones the decryptor already uses, so the
//  setup path cannot drift from the decryption path.
//

#include "unfairplay.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "up_crypto.h"
#include "up_internal.h"
#include "up_macho.h"
#include "up_model.h"
#include "up_zip.h"

#define UP_SETUP_ARM64_CPU_TYPE UINT32_C(0x0100000c)
#define UP_SETUP_ARM64E_SUBTYPE UINT32_C(2)
#define UP_SETUP_READ_CHUNK (1024 * 1024)

static bool up_setup_ends_with_sinf(const char *name) {
    size_t length = strlen(name);
    if (length < 5) {
        return false;
    }
    const char *suffix = name + length - 5;
    char lower[6];
    for (size_t index = 0; index < 5; index++) {
        char value = suffix[index];
        lower[index] = (value >= 'A' && value <= 'Z') ? (char)(value - 'A' + 'a') : value;
    }
    lower[5] = '\0';
    return strcmp(lower, ".sinf") == 0;
}

int up_setup_list_ipa_sinfs(up_context *ctx,
                            const char *ipa_path,
                            up_setup_sinf **entries,
                            size_t *count) {
    *entries = NULL;
    *count = 0;
    up_zip archive;
    if (!up_zip_open(ctx, ipa_path, &archive)) {
        return 0;
    }
    up_setup_sinf *list = calloc(archive.count == 0 ? 1 : archive.count, sizeof(up_setup_sinf));
    if (list == NULL) {
        up_zip_close(&archive);
        return up_fail(ctx, "out of memory listing IPA SINF members");
    }
    size_t found = 0;
    for (size_t index = 0; index < archive.count; index++) {
        const up_zip_entry *entry = &archive.entries[index];
        if (entry->name == NULL || strstr(entry->name, "/SC_Info/") == NULL ||
            !up_setup_ends_with_sinf(entry->name)) {
            continue;
        }
        char *member = strdup(entry->name);
        if (member == NULL) {
            free(list);
            up_zip_close(&archive);
            return up_fail(ctx, "out of memory listing IPA SINF members");
        }
        list[found].member = member;
        list[found].selector[0] = '\0';

        uint8_t *bytes = NULL;
        size_t length = 0;
        if (!up_zip_read(ctx, &archive, entry, &bytes, &length)) {
            // A member read failed; the Go capture fails the same way instead
            // of skipping a broken SINF.
            for (size_t index = 0; index <= found; index++) {
                free(list[index].member);
            }
            free(list);
            up_zip_close(&archive);
            return 0;
        }
        up_selector selector;
        if (up_sinf_read_selector(ctx, bytes, length, &selector)) {
            up_selector_identifier(selector, list[found].selector);
        }
        free(bytes);
        found++;
    }
    up_zip_close(&archive);
    if (found == 0) {
        free(list);
        return up_fail(ctx, "IPA contains no SC_Info SINF members");
    }
    *entries = list;
    *count = found;
    return 1;
}

void up_setup_free_ipa_sinfs(up_setup_sinf *entries, size_t count) {
    if (entries == NULL) {
        return;
    }
    for (size_t index = 0; index < count; index++) {
        free(entries[index].member);
    }
    free(entries);
}

int up_setup_read_ipa_member(up_context *ctx,
                             const char *ipa_path,
                             const char *member,
                             uint8_t **bytes,
                             size_t *length) {
    *bytes = NULL;
    *length = 0;
    up_zip archive;
    if (!up_zip_open(ctx, ipa_path, &archive)) {
        return 0;
    }
    size_t index = up_zip_find(&archive, member);
    if (index == SIZE_MAX) {
        up_zip_close(&archive);
        return up_fail(ctx, "IPA member not found: %s", member);
    }
    bool ok = up_zip_read(ctx, &archive, &archive.entries[index], bytes, length);
    up_zip_close(&archive);
    return ok;
}

void up_setup_free_bytes(uint8_t *bytes) {
    free(bytes);
}

int up_setup_sinf_selector(up_context *ctx,
                           const uint8_t *blob,
                           size_t length,
                           char output[18]) {
    output[0] = '\0';
    up_selector selector;
    if (!up_sinf_read_selector(ctx, blob, length, &selector)) {
        return 0;
    }
    up_selector_identifier(selector, output);
    return 1;
}

static bool up_setup_read_file(up_context *ctx,
                               const char *path,
                               uint8_t **bytes,
                               size_t *length) {
    *bytes = NULL;
    *length = 0;
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return up_fail(ctx, "open %s: %s", path, strerror(errno));
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        int error = errno;
        fclose(file);
        return up_fail(ctx, "size %s: %s", path, strerror(error));
    }
    long size = ftell(file);
    if (size < 0) {
        int error = errno;
        fclose(file);
        return up_fail(ctx, "size %s: %s", path, strerror(error));
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        int error = errno;
        fclose(file);
        return up_fail(ctx, "seek %s: %s", path, strerror(error));
    }
    uint8_t *buffer = malloc((size_t)size == 0 ? 1 : (size_t)size);
    if (buffer == NULL) {
        fclose(file);
        return up_fail(ctx, "out of memory reading %s", path);
    }
    size_t read = fread(buffer, 1, (size_t)size, file);
    int error = errno;
    fclose(file);
    if (read != (size_t)size) {
        free(buffer);
        return up_fail(ctx, "read %s: %s", path, strerror(error));
    }
    *bytes = buffer;
    *length = read;
    return 1;
}

static bool up_setup_is_arm64e(const up_macho_slice *slice) {
    if (slice->layout.cpu_type != UP_SETUP_ARM64_CPU_TYPE) {
        return false;
    }
    return (slice->layout.cpu_subtype & UINT32_C(0x00ffffff)) == UP_SETUP_ARM64E_SUBTYPE;
}

int up_setup_thin_fairplayd(up_context *ctx,
                            const char *source,
                            const char *destination,
                            char sha256[65],
                            int64_t *written) {
    *written = 0;
    sha256[0] = '\0';
    uint8_t *blob = NULL;
    size_t length = 0;
    if (!up_setup_read_file(ctx, source, &blob, &length)) {
        return 0;
    }
    up_macho_slice *slices = NULL;
    size_t count = 0;
    if (!up_parse_macho_slices(ctx, blob, length, (uint64_t)length, &slices, &count)) {
        free(blob);
        return 0;
    }
    const up_macho_slice *selected = NULL;
    for (size_t index = 0; index < count; index++) {
        const up_macho_slice *candidate = &slices[index];
        if (!up_setup_is_arm64e(candidate)) {
            continue;
        }
        if (selected == NULL) {
            selected = candidate;
        }
        // Prefer the slice without capability bits, matching the Go capture.
        if ((candidate->layout.cpu_subtype & UINT32_C(0xff000000)) == 0) {
            selected = candidate;
            break;
        }
    }
    if (selected == NULL) {
        free(blob);
        up_macho_slices_free(slices, count);
        return up_fail(ctx, "fairplayd has no arm64e slice");
    }
    if (selected->offset > length || selected->size > length - selected->offset) {
        free(blob);
        up_macho_slices_free(slices, count);
        return up_fail(ctx, "fairplayd arm64e slice exceeds the file");
    }
    int descriptor = open(destination, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) {
        int error = errno;
        free(blob);
        up_macho_slices_free(slices, count);
        return up_fail(ctx, "create %s: %s", destination, strerror(error));
    }
    up_sha256_ctx *hash = up_sha256_create();
    const uint8_t *start = blob + selected->offset;
    size_t remaining = (size_t)selected->size;
    bool ok = hash != NULL;
    while (ok && remaining > 0) {
        size_t chunk = remaining > UP_SETUP_READ_CHUNK ? UP_SETUP_READ_CHUNK : remaining;
        ssize_t wrote = write(descriptor, start, chunk);
        if (wrote < 0) {
            ok = false;
            up_fail(ctx, "write %s: %s", destination, strerror(errno));
            break;
        }
        up_sha256_update(hash, start, (size_t)wrote);
        start += wrote;
        remaining -= (size_t)wrote;
    }
    int close_error = close(descriptor);
    if (ok && close_error != 0) {
        ok = false;
        up_fail(ctx, "close %s: %s", destination, strerror(errno));
    }
    if (ok) {
        uint8_t digest[32];
        up_sha256_final(hash, digest);
        up_hex_encode(digest, sizeof(digest), sha256);
        *written = (int64_t)selected->size;
    }
    up_sha256_release(hash);
    free(blob);
    up_macho_slices_free(slices, count);
    return ok ? 1 : 0;
}

int up_setup_file_sha256(up_context *ctx,
                         const char *path,
                         char sha256[65],
                         int64_t *bytes) {
    sha256[0] = '\0';
    *bytes = 0;
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return up_fail(ctx, "open %s: %s", path, strerror(errno));
    }
    up_sha256_ctx *hash = up_sha256_create();
    if (hash == NULL) {
        fclose(file);
        return up_fail(ctx, "out of memory hashing %s", path);
    }
    uint8_t *chunk = malloc(UP_SETUP_READ_CHUNK);
    if (chunk == NULL) {
        up_sha256_release(hash);
        fclose(file);
        return up_fail(ctx, "out of memory hashing %s", path);
    }
    bool ok = true;
    int64_t total = 0;
    for (;;) {
        size_t read = fread(chunk, 1, UP_SETUP_READ_CHUNK, file);
        if (read > 0) {
            up_sha256_update(hash, chunk, read);
            total += (int64_t)read;
        }
        if (read < UP_SETUP_READ_CHUNK) {
            if (ferror(file)) {
                ok = false;
                up_fail(ctx, "read %s: %s", path, strerror(errno));
            }
            break;
        }
    }
    free(chunk);
    fclose(file);
    if (!ok) {
        up_sha256_release(hash);
        return 0;
    }
    uint8_t digest[32];
    up_sha256_final(hash, digest);
    up_hex_encode(digest, sizeof(digest), sha256);
    *bytes = total;
    up_sha256_release(hash);
    return 1;
}
