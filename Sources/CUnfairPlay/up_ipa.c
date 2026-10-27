//
//  up_ipa.c
//  CUnfairPlay
//
//  Port of openIPAInventory. The archive stays mapped for the whole decrypt
//  operation so unchanged members can be copied without a second read.
//

#include "up_ipa.h"

#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "up_crypto.h"

#define UP_MH_MAGIC32 UINT32_C(0xfeedface)
#define UP_MH_MAGIC64 UINT32_C(0xfeedfacf)
#define UP_MH_CIGAM32 UINT32_C(0xcefaedfe)
#define UP_MH_CIGAM64 UINT32_C(0xcffaedfe)
#define UP_FAT_MAGIC UINT32_C(0xcafebabe)
#define UP_FAT_CIGAM UINT32_C(0xbebafeca)
#define UP_FAT_MAGIC64 UINT32_C(0xcafebabf)
#define UP_FAT_CIGAM64 UINT32_C(0xbfbafeca)

static uint32_t up_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint32_t up_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static bool up_is_fat_macho(const uint8_t *blob, size_t length) {
    if (length < 4) {
        return false;
    }
    switch (up_be32(blob)) {
    case UP_FAT_MAGIC:
    case UP_FAT_CIGAM:
    case UP_FAT_MAGIC64:
    case UP_FAT_CIGAM64:
        return true;
    default:
        return false;
    }
}

static bool up_is_known_unsupported_macho(const uint8_t *blob, size_t length) {
    if (length < 4) {
        return false;
    }
    uint32_t magic = up_le32(blob);
    return magic == UP_MH_CIGAM32 || magic == UP_MH_CIGAM64;
}

static bool up_has_suffix(const char *value, const char *suffix) {
    size_t value_length = strlen(value);
    size_t suffix_length = strlen(suffix);
    if (suffix_length > value_length) {
        return false;
    }
    return strcmp(value + value_length - suffix_length, suffix) == 0;
}

static bool up_has_suffix_folded(const char *value, const char *suffix) {
    size_t value_length = strlen(value);
    size_t suffix_length = strlen(suffix);
    if (suffix_length > value_length) {
        return false;
    }
    for (size_t index = 0; index < suffix_length; index++) {
        char left = value[value_length - suffix_length + index];
        char right = suffix[index];
        if (left >= 'A' && left <= 'Z') {
            left = (char)(left - 'A' + 'a');
        }
        if (right >= 'A' && right <= 'Z') {
            right = (char)(right - 'A' + 'a');
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

static bool up_ends_with_slash(const char *name) {
    size_t length = strlen(name);
    return length != 0 && name[length - 1] == '/';
}

static char *up_concatenate(const char *left, const char *right) {
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
        return up_concatenate(path, "");
    }
    char directory[PATH_MAX];
    if (getcwd(directory, sizeof(directory)) == NULL) {
        return NULL;
    }
    char *prefix = up_concatenate(directory, "/");
    if (prefix == NULL) {
        return NULL;
    }
    char *result = up_concatenate(prefix, path);
    free(prefix);
    return result;
}

static char *up_path_dir(const char *name) {
    const char *slash = strrchr(name, '/');
    if (slash == NULL) {
        return up_concatenate(".", "");
    }
    if (slash == name) {
        return up_concatenate("/", "");
    }
    size_t length = (size_t)(slash - name);
    char *result = malloc(length + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, name, length);
    result[length] = '\0';
    return result;
}

static const char *up_path_base(const char *name) {
    const char *slash = strrchr(name, '/');
    return slash == NULL ? name : slash + 1;
}

/// `path.Join(directory, rest)` for the cleaned, non-empty `rest` values used
/// by the SINF/SUPF naming rules.
static char *up_path_join(const char *directory, const char *rest) {
    if (strcmp(directory, ".") == 0) {
        return up_concatenate(rest, "");
    }
    if (strcmp(directory, "/") == 0) {
        char *suffix = up_concatenate("/", rest);
        return suffix;
    }
    char *prefix = up_concatenate(directory, "/");
    if (prefix == NULL) {
        return NULL;
    }
    char *result = up_concatenate(prefix, rest);
    free(prefix);
    return result;
}

// MARK: - Name index

static uint64_t up_name_hash(const char *name) {
    uint64_t hash = UINT64_C(1469598103934665603);
    for (const unsigned char *cursor = (const unsigned char *)name; *cursor != 0; cursor++) {
        hash ^= (uint64_t)*cursor;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

int up_name_index_build(up_context *ctx, const up_zip *archive, up_name_index *out) {
    memset(out, 0, sizeof(*out));
    size_t capacity = 16;
    while (capacity < (archive->count + 1) * 2) {
        if (capacity > SIZE_MAX / 2) {
            return up_fail(ctx, "out of memory");
        }
        capacity *= 2;
    }
    size_t *slots = calloc(capacity, sizeof(size_t));
    if (slots == NULL) {
        return up_fail(ctx, "out of memory");
    }
    for (size_t index = 0; index < archive->count; index++) {
        uint64_t hash = up_name_hash(archive->entries[index].name);
        size_t slot = (size_t)hash & (capacity - 1);
        while (slots[slot] != 0) {
            size_t previous = slots[slot] - 1;
            if (strcmp(archive->entries[previous].name, archive->entries[index].name) == 0) {
                break;
            }
            slot = (slot + 1) & (capacity - 1);
        }
        if (slots[slot] == 0) {
            slots[slot] = index + 1;
        }
    }
    out->slots = slots;
    out->capacity = capacity;
    return 1;
}

void up_name_index_free(up_name_index *index) {
    if (index == NULL) {
        return;
    }
    free(index->slots);
    index->slots = NULL;
    index->capacity = 0;
}

size_t up_name_index_find(const up_name_index *index, const up_zip *archive, const char *name) {
    if (index == NULL || index->capacity == 0) {
        return SIZE_MAX;
    }
    uint64_t hash = up_name_hash(name);
    size_t slot = (size_t)hash & (index->capacity - 1);
    while (index->slots[slot] != 0) {
        size_t candidate = index->slots[slot] - 1;
        if (strcmp(archive->entries[candidate].name, name) == 0) {
            return candidate;
        }
        slot = (slot + 1) & (index->capacity - 1);
    }
    return SIZE_MAX;
}

// MARK: - Companion names

/// `adjacentSINF`: <dir>/SC_Info/<base>.sinf
static char *up_adjacent_sinf(const char *member) {
    char *directory = up_path_dir(member);
    if (directory == NULL) {
        return NULL;
    }
    const char *base = up_path_base(member);
    char *rest = up_concatenate("SC_Info/", base);
    if (rest == NULL) {
        free(directory);
        return NULL;
    }
    char *with_suffix = up_concatenate(rest, ".sinf");
    free(rest);
    if (with_suffix == NULL) {
        free(directory);
        return NULL;
    }
    char *result = up_path_join(directory, with_suffix);
    free(directory);
    free(with_suffix);
    return result;
}

static int up_compare_strings(const void *left, const void *right) {
    const char *const *left_value = left;
    const char *const *right_value = right;
    return strcmp(*left_value, *right_value);
}

static int up_sinf_name(up_context *ctx,
                        const up_ipa_inventory *inventory,
                        const char *member,
                        char **out) {
    *out = NULL;
    char *adjacent = up_adjacent_sinf(member);
    if (adjacent == NULL) {
        return up_fail(ctx, "out of memory");
    }
    if (up_name_index_find(&inventory->index, &inventory->archive, adjacent) != SIZE_MAX) {
        *out = adjacent;
        return 1;
    }
    free(adjacent);
    char *directory = up_path_dir(member);
    if (directory == NULL) {
        return up_fail(ctx, "out of memory");
    }
    while (strcmp(directory, ".") != 0 && strcmp(directory, "/") != 0) {
        char *prefix = up_path_join(directory, "SC_Info/");
        if (prefix == NULL) {
            free(directory);
            return up_fail(ctx, "out of memory");
        }
        size_t prefix_length = strlen(prefix);
        char **candidates = NULL;
        size_t candidate_count = 0;
        for (size_t index = 0; index < inventory->archive.count; index++) {
            const char *name = inventory->archive.entries[index].name;
            if (strncmp(name, prefix, prefix_length) != 0) {
                continue;
            }
            const char *remainder = name + prefix_length;
            if (strchr(remainder, '/') != NULL || !up_has_suffix_folded(remainder, ".sinf")) {
                continue;
            }
            char **grown = realloc(candidates, (candidate_count + 1) * sizeof(char *));
            if (grown == NULL) {
                for (size_t inner = 0; inner < candidate_count; inner++) {
                    free(candidates[inner]);
                }
                free(candidates);
                free(prefix);
                free(directory);
                return up_fail(ctx, "out of memory");
            }
            candidates = grown;
            candidates[candidate_count] = up_concatenate(name, "");
            if (candidates[candidate_count] == NULL) {
                for (size_t inner = 0; inner < candidate_count; inner++) {
                    free(candidates[inner]);
                }
                free(candidates);
                free(prefix);
                free(directory);
                return up_fail(ctx, "out of memory");
            }
            candidate_count++;
        }
        free(prefix);
        if (candidate_count != 0) {
            qsort(candidates, candidate_count, sizeof(char *), up_compare_strings);
        }
        if (candidate_count == 1) {
            *out = candidates[0];
            free(candidates);
            free(directory);
            return 1;
        }
        if (candidate_count > 1) {
            up_buf joined;
            up_buf_init(&joined);
            for (size_t index = 0; index < candidate_count; index++) {
                if (index != 0) {
                    up_buf_append(&joined, ", ", 2);
                }
                up_buf_append(&joined, candidates[index], strlen(candidates[index]));
            }
            int status = 0;
            if (!joined.failed) {
                status = up_fail(ctx, "encrypted Mach-O \"%s\" has ambiguous containing SINFs: %s",
                                 member, joined.bytes);
            } else {
                status = up_fail(ctx, "out of memory");
            }
            up_buf_free(&joined);
            for (size_t index = 0; index < candidate_count; index++) {
                free(candidates[index]);
            }
            free(candidates);
            free(directory);
            return status;
        }
        char *parent = up_path_dir(directory);
        free(directory);
        if (parent == NULL) {
            return up_fail(ctx, "out of memory");
        }
        directory = parent;
    }
    free(directory);
    return up_fail(ctx, "encrypted Mach-O \"%s\" has no adjacent or containing SINF", member);
}

/// `supfName`: `.v5.supf` first, then `.supf`.
static char *up_supf_name(const up_ipa_inventory *inventory, const char *member) {
    static const char *const suffixes[] = {".v5.supf", ".supf"};
    char *directory = up_path_dir(member);
    if (directory == NULL) {
        return NULL;
    }
    const char *base = up_path_base(member);
    for (size_t index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++) {
        char *rest = up_concatenate("SC_Info/", base);
        if (rest == NULL) {
            free(directory);
            return NULL;
        }
        char *with_suffix = up_concatenate(rest, suffixes[index]);
        free(rest);
        if (with_suffix == NULL) {
            free(directory);
            return NULL;
        }
        char *candidate = up_path_join(directory, with_suffix);
        free(with_suffix);
        if (candidate == NULL) {
            free(directory);
            return NULL;
        }
        if (up_name_index_find(&inventory->index, &inventory->archive, candidate) != SIZE_MAX) {
            free(directory);
            return candidate;
        }
        free(candidate);
    }
    free(directory);
    return up_concatenate("", "");
}

// MARK: - Inventory

static int up_wrap_member_error(up_context *ctx, const char *member) {
    const char *detail = up_last_error(ctx);
    char *copy = up_concatenate(detail, "");
    if (copy == NULL) {
        return up_fail(ctx, "%s: failed", member);
    }
    int status = up_fail(ctx, "%s: %s", member, copy);
    free(copy);
    return status;
}

const up_zip_entry *up_ipa_entry(up_context *ctx,
                                 const up_ipa_inventory *inventory,
                                 const char *name) {
    size_t index = up_name_index_find(&inventory->index, &inventory->archive, name);
    if (index == SIZE_MAX) {
        up_fail(ctx, "IPA member \"%s\" is missing", name);
        return NULL;
    }
    return &inventory->archive.entries[index];
}

int up_ipa_supf(up_context *ctx,
                up_ipa_inventory *inventory,
                const char *name,
                up_supf_table **out) {
    for (size_t index = 0; index < inventory->table_count; index++) {
        if (strcmp(inventory->tables[index].name, name) == 0) {
            *out = &inventory->tables[index].table;
            return 1;
        }
    }
    const up_zip_entry *entry = up_ipa_entry(ctx, inventory, name);
    if (entry == NULL) {
        return 0;
    }
    uint8_t *blob = NULL;
    size_t blob_length = 0;
    if (!up_zip_read(ctx, &inventory->archive, entry, &blob, &blob_length)) {
        return 0;
    }
    up_supf_table table;
    int status = up_supf_parse(ctx, blob, blob_length, &table);
    free(blob);
    if (!status) {
        return 0;
    }
    up_supf_cache *grown =
        realloc(inventory->tables, (inventory->table_count + 1) * sizeof(up_supf_cache));
    if (grown == NULL) {
        up_supf_free(&table);
        return up_fail(ctx, "out of memory");
    }
    inventory->tables = grown;
    up_supf_cache *cache = &inventory->tables[inventory->table_count];
    cache->name = up_concatenate(name, "");
    if (cache->name == NULL) {
        up_supf_free(&table);
        return up_fail(ctx, "out of memory");
    }
    cache->table = table;
    inventory->table_count++;
    *out = &cache->table;
    return 1;
}

const uint8_t *up_ipa_cached(const up_ipa_inventory *inventory, const char *name, size_t *length) {
    *length = 0;
    for (size_t index = 0; index < inventory->cached_count; index++) {
        if (strcmp(inventory->cached[index].name, name) == 0) {
            *length = inventory->cached[index].length;
            return inventory->cached[index].bytes;
        }
    }
    return NULL;
}

static int up_inventory_cache(up_context *ctx,
                              up_ipa_inventory *inventory,
                              const char *name,
                              uint8_t *bytes,
                              size_t length) {
    up_cached_member *grown =
        realloc(inventory->cached, (inventory->cached_count + 1) * sizeof(up_cached_member));
    if (grown == NULL) {
        return up_fail(ctx, "out of memory");
    }
    inventory->cached = grown;
    up_cached_member *cache = &inventory->cached[inventory->cached_count];
    cache->name = up_concatenate(name, "");
    if (cache->name == NULL) {
        return up_fail(ctx, "out of memory");
    }
    cache->bytes = bytes;
    cache->length = length;
    inventory->cached_count++;
    return 1;
}

void up_ipa_inventory_close(up_ipa_inventory *inventory) {
    if (inventory == NULL) {
        return;
    }
    for (size_t index = 0; index < inventory->sinf_count; index++) {
        free(inventory->sinf_members[index]);
    }
    free(inventory->sinf_members);
    inventory->sinf_members = NULL;
    inventory->sinf_count = 0;
    for (size_t index = 0; index < inventory->image_count; index++) {
        free(inventory->images[index].member);
        free(inventory->images[index].supf_member);
        free(inventory->images[index].sinf_member);
        up_macho_layout_free(&inventory->images[index].layout);
    }
    free(inventory->images);
    inventory->images = NULL;
    inventory->image_count = 0;
    for (size_t index = 0; index < inventory->table_count; index++) {
        free(inventory->tables[index].name);
        up_supf_free(&inventory->tables[index].table);
    }
    free(inventory->tables);
    inventory->tables = NULL;
    inventory->table_count = 0;
    for (size_t index = 0; index < inventory->cached_count; index++) {
        free(inventory->cached[index].name);
        free(inventory->cached[index].bytes);
    }
    free(inventory->cached);
    inventory->cached = NULL;
    inventory->cached_count = 0;
    up_name_index_free(&inventory->index);
    up_zip_close(&inventory->archive);
    free(inventory->path);
    inventory->path = NULL;
}

static int up_inventory_probe(up_context *ctx,
                              up_ipa_inventory *inventory,
                              const up_zip_entry *entry,
                              uint8_t **probe_out,
                              size_t *probe_length_out,
                              bool *whole_out) {
    *probe_out = NULL;
    *probe_length_out = 0;
    *whole_out = false;
    uint8_t *probe = NULL;
    size_t probe_length = 0;
    if (!up_zip_read_prefix(ctx, &inventory->archive, entry, 32, &probe, &probe_length)) {
        return 0;
    }
    if (probe_length < 4) {
        *probe_out = probe;
        *probe_length_out = probe_length;
        return 1;
    }
    uint32_t magic = up_le32(probe);
    if (magic == UP_MH_MAGIC32 || magic == UP_MH_MAGIC64) {
        size_t header_bytes = magic == UP_MH_MAGIC64 ? 32 : 28;
        if (probe_length < header_bytes) {
            *probe_out = probe;
            *probe_length_out = probe_length;
            return 1;
        }
        uint32_t commands_bytes = up_le32(probe + 20);
        uint64_t required = (uint64_t)header_bytes + commands_bytes;
        if (required < header_bytes || required > 1048576 ||
            required > entry->uncompressed_size) {
            free(probe);
            return up_fail(ctx, "Mach-O load-command extent is invalid");
        }
        if (required > probe_length) {
            uint8_t *grown = NULL;
            size_t grown_length = 0;
            if (!up_zip_read_prefix(ctx, &inventory->archive, entry, (size_t)required, &grown,
                                    &grown_length)) {
                free(probe);
                return 0;
            }
            free(probe);
            probe = grown;
            probe_length = grown_length;
        }
        *probe_out = probe;
        *probe_length_out = probe_length;
        return 1;
    }
    if (up_is_fat_macho(probe, probe_length)) {
        uint8_t *whole = NULL;
        size_t whole_length = 0;
        if (!up_zip_read(ctx, &inventory->archive, entry, &whole, &whole_length)) {
            free(probe);
            return 0;
        }
        free(probe);
        *probe_out = whole;
        *probe_length_out = whole_length;
        *whole_out = true;
        return 1;
    }
    *probe_out = probe;
    *probe_length_out = probe_length;
    return 1;
}

static int up_inventory_append_image(up_context *ctx,
                                     up_ipa_inventory *inventory,
                                     const char *member,
                                     const char *supf_member,
                                     const char *sinf_member,
                                     const up_macho_slice *slice) {
    up_encrypted_image *grown =
        realloc(inventory->images, (inventory->image_count + 1) * sizeof(up_encrypted_image));
    if (grown == NULL) {
        return up_fail(ctx, "out of memory");
    }
    inventory->images = grown;
    up_encrypted_image *image = &inventory->images[inventory->image_count];
    memset(image, 0, sizeof(*image));
    image->member = up_concatenate(member, "");
    image->supf_member = up_concatenate(supf_member, "");
    image->sinf_member = up_concatenate(sinf_member, "");
    if (image->member == NULL || image->supf_member == NULL || image->sinf_member == NULL) {
        free(image->member);
        free(image->supf_member);
        free(image->sinf_member);
        return up_fail(ctx, "out of memory");
    }
    image->slice_offset = slice->offset;
    image->slice_size = slice->size;
    image->layout = slice->layout;
    inventory->image_count++;
    return 1;
}

int up_ipa_inventory_open(up_context *ctx, const char *path, up_ipa_inventory *out) {
    memset(out, 0, sizeof(*out));
    out->archive.descriptor = -1;
    out->path = up_absolute_path(path);
    if (out->path == NULL) {
        return up_fail(ctx, "resolve IPA path: %s", strerror(errno));
    }
    struct stat info;
    if (stat(out->path, &info) != 0) {
        int error = errno;
        up_ipa_inventory_close(out);
        return up_fail(ctx, "inspect IPA: %s", strerror(error));
    }
    out->bytes = (int64_t)info.st_size;
    if (!up_zip_open(ctx, out->path, &out->archive)) {
        up_ipa_inventory_close(out);
        return 0;
    }
    uint8_t digest[32];
    up_sha256(out->archive.bytes, out->archive.length, digest);
    up_hex_encode(digest, sizeof(digest), out->sha256);
    if (!up_name_index_build(ctx, &out->archive, &out->index)) {
        up_ipa_inventory_close(out);
        return 0;
    }

    // Duplicate members and SINF collection.
    for (size_t index = 0; index < out->archive.count; index++) {
        const up_zip_entry *entry = &out->archive.entries[index];
        size_t previous = up_name_index_find(&out->index, &out->archive, entry->name);
        if (previous != SIZE_MAX && previous != index) {
            const up_zip_entry *first = &out->archive.entries[previous];
            if (up_ends_with_slash(entry->name) && up_ends_with_slash(first->name) &&
                first->uncompressed_size == 0 && entry->uncompressed_size == 0) {
                continue;
            }
            int status = up_fail(ctx, "duplicate IPA member \"%s\"", entry->name);
            up_ipa_inventory_close(out);
            return status;
        }
        if (up_has_suffix(entry->name, ".sinf")) {
            char **grown = realloc(out->sinf_members, (out->sinf_count + 1) * sizeof(char *));
            if (grown == NULL) {
                up_ipa_inventory_close(out);
                return up_fail(ctx, "out of memory");
            }
            out->sinf_members = grown;
            out->sinf_members[out->sinf_count] = up_concatenate(entry->name, "");
            if (out->sinf_members[out->sinf_count] == NULL) {
                up_ipa_inventory_close(out);
                return up_fail(ctx, "out of memory");
            }
            out->sinf_count++;
        }
    }

    int status = 1;
    for (size_t index = 0; index < out->archive.count && status; index++) {
        const up_zip_entry *entry = &out->archive.entries[index];
        if (up_zip_entry_is_directory(entry)) {
            continue;
        }
        uint8_t *probe = NULL;
        size_t probe_length = 0;
        bool whole = false;
        if (!up_inventory_probe(ctx, out, entry, &probe, &probe_length, &whole)) {
            status = up_wrap_member_error(ctx, entry->name);
            break;
        }
        if (probe_length < 4) {
            free(probe);
            continue;
        }
        uint32_t magic = up_le32(probe);
        if (magic != UP_MH_MAGIC32 && magic != UP_MH_MAGIC64 &&
            !up_is_fat_macho(probe, probe_length)) {
            bool unsupported = up_is_known_unsupported_macho(probe, probe_length);
            free(probe);
            if (unsupported) {
                status = up_fail(
                    ctx,
                    "%s: unsupported Mach-O format; cannot establish complete encryption inventory",
                    entry->name);
                break;
            }
            continue;
        }
        up_macho_slice *slices = NULL;
        size_t slice_count = 0;
        if (!up_parse_macho_slices(ctx, probe, probe_length, entry->uncompressed_size, &slices,
                                   &slice_count)) {
            free(probe);
            status = up_wrap_member_error(ctx, entry->name);
            break;
        }
        size_t encrypted_count = 0;
        for (size_t slice_index = 0; slice_index < slice_count; slice_index++) {
            if (slices[slice_index].layout.crypt_id != 0) {
                encrypted_count++;
            }
        }
        if (encrypted_count == 0) {
            up_macho_slices_free(slices, slice_count);
            free(probe);
            continue;
        }
        char *supf_member = up_supf_name(out, entry->name);
        if (supf_member == NULL) {
            up_macho_slices_free(slices, slice_count);
            free(probe);
            status = up_fail(ctx, "out of memory");
            break;
        }
        if (supf_member[0] == '\0') {
            free(supf_member);
            up_macho_slices_free(slices, slice_count);
            free(probe);
            status = up_fail(ctx, "encrypted Mach-O \"%s\" has no adjacent SUPF", entry->name);
            break;
        }
        char *sinf_member = NULL;
        if (!up_sinf_name(ctx, out, entry->name, &sinf_member)) {
            free(supf_member);
            up_macho_slices_free(slices, slice_count);
            free(probe);
            status = 0;
            break;
        }
        up_supf_table *table = NULL;
        if (!up_ipa_supf(ctx, out, supf_member, &table)) {
            free(sinf_member);
            free(supf_member);
            up_macho_slices_free(slices, slice_count);
            free(probe);
            status = 0;
            break;
        }
        for (size_t slice_index = 0; slice_index < slice_count && status; slice_index++) {
            const up_macho_slice *slice = &slices[slice_index];
            if (slice->layout.crypt_id == 0) {
                continue;
            }
            const uint8_t *records = NULL;
            size_t record_count = 0;
            if (!up_supf_records(table, slice->layout.cpu_type, slice->layout.cpu_subtype, &records,
                                 &record_count)) {
                status = up_fail(ctx, "%s: SUPF has no matching architecture 0x%x/0x%x", entry->name,
                                 (unsigned)slice->layout.cpu_type,
                                 (unsigned)slice->layout.cpu_subtype);
                break;
            }
            if (record_count != (size_t)(slice->layout.crypt_size / UP_PAGE_BYTES)) {
                status = up_fail(ctx,
                                 "%s: SUPF page count mismatch for architecture %#x/%#x",
                                 entry->name, (unsigned)slice->layout.cpu_type,
                                 (unsigned)slice->layout.cpu_subtype);
                break;
            }
            if (!up_inventory_append_image(ctx, out, entry->name, supf_member, sinf_member,
                                           slice)) {
                status = 0;
                break;
            }
            // Ownership of the layout (including the instruction ranges) moved
            // into the image list.
            slices[slice_index].layout.ranges = NULL;
            slices[slice_index].layout.range_count = 0;
        }
        free(sinf_member);
        free(supf_member);
        up_macho_slices_free(slices, slice_count);
        if (status && whole) {
            if (!up_inventory_cache(ctx, out, entry->name, probe, probe_length)) {
                status = 0;
                break;
            }
            probe = NULL;
        }
        free(probe);
    }
    if (status && out->image_count == 0) {
        status = up_fail(ctx, "IPA contains no supported encrypted Mach-O images");
    }
    if (!status) {
        up_ipa_inventory_close(out);
        return 0;
    }
    return 1;
}
