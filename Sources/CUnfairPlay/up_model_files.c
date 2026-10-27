//
//  up_model_files.c
//  CUnfairPlay
//
//  Model directory rules from internal/fairplay/model_files.go: 0700 directory,
//  0600 regular `.bin` files, no symlinks, at most 256 packs, at least one.
//  Any violation rejects the whole registry, exactly like the Go version.
//

#include "up_model.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static bool up_permissions_are_private(mode_t mode) {
    return (mode & 077) == 0;
}

static char *up_join_path(const char *directory, const char *name) {
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    bool needs_separator = directory_length > 0 && directory[directory_length - 1] != '/';
    char *result = malloc(directory_length + (needs_separator ? 1 : 0) + name_length + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, directory, directory_length);
    size_t cursor = directory_length;
    if (needs_separator) {
        result[cursor++] = '/';
    }
    memcpy(result + cursor, name, name_length);
    result[cursor + name_length] = '\0';
    return result;
}

static bool up_has_bin_extension(const char *name) {
    size_t length = strlen(name);
    if (length < 4 || name[length - 4] != '.') {
        return false;
    }
    const char *suffix = name + length - 3;
    return (suffix[0] == 'b' || suffix[0] == 'B') && (suffix[1] == 'i' || suffix[1] == 'I') &&
           (suffix[2] == 'n' || suffix[2] == 'N');
}

void up_model_pack_free(up_model_pack *pack) {
    if (pack == NULL) {
        return;
    }
    if (pack->bytes != NULL) {
        memset(pack->bytes, 0, pack->length);
    }
    free(pack->bytes);
    free(pack->path);
    pack->bytes = NULL;
    pack->path = NULL;
    pack->length = 0;
}

void up_model_registry_free(up_model_registry *registry) {
    if (registry == NULL) {
        return;
    }
    for (size_t index = 0; index < registry->count; index++) {
        up_model_pack_free(&registry->packs[index]);
    }
    free(registry->packs);
    registry->packs = NULL;
    registry->count = 0;
}

int up_read_model_file(up_context *ctx, const char *path, up_model_pack *out) {
    memset(out, 0, sizeof(*out));
    struct stat info;
    if (stat(path, &info) != 0) {
        return up_fail(ctx, "inspect FairPlay enrollment model: %s", strerror(errno));
    }
    if (!S_ISREG(info.st_mode)) {
        return up_fail(ctx, "FairPlay enrollment model is not a regular file");
    }
    if (!up_permissions_are_private(info.st_mode)) {
        return up_fail(
            ctx, "FairPlay enrollment model file must not be accessible by group or other users");
    }
    if (info.st_size < 0) {
        return up_fail(ctx, "read FairPlay enrollment model: invalid size");
    }
    size_t length = (size_t)info.st_size;
    uint8_t *bytes = malloc(length == 0 ? 1 : length);
    if (bytes == NULL) {
        return up_fail(ctx, "out of memory");
    }
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        free(bytes);
        return up_fail(ctx, "read FairPlay enrollment model: %s", strerror(errno));
    }
    size_t read_bytes = fread(bytes, 1, length, file);
    int close_error = fclose(file);
    if (read_bytes != length || close_error != 0) {
        memset(bytes, 0, length);
        free(bytes);
        return up_fail(ctx, "read FairPlay enrollment model: %s",
                       strerror(read_bytes != length ? EIO : errno));
    }
    char *copy = malloc(strlen(path) + 1);
    if (copy == NULL) {
        memset(bytes, 0, length);
        free(bytes);
        return up_fail(ctx, "out of memory");
    }
    strcpy(copy, path);
    out->bytes = bytes;
    out->length = length;
    out->path = copy;
    return 1;
}

static int up_compare_names(const void *left, const void *right) {
    const char *const *left_name = left;
    const char *const *right_name = right;
    return strcmp(*left_name, *right_name);
}

int up_read_model_registry(up_context *ctx, const char *path, up_model_registry *out) {
    memset(out, 0, sizeof(*out));
    struct stat info;
    if (stat(path, &info) != 0) {
        return up_fail(ctx, "inspect FairPlay enrollment model registry: %s", strerror(errno));
    }
    if (!S_ISDIR(info.st_mode)) {
        return up_fail(ctx, "FairPlay enrollment model registry is not a directory");
    }
    if (!up_permissions_are_private(info.st_mode)) {
        return up_fail(
            ctx,
            "FairPlay enrollment model directory must not be accessible by group or other users");
    }
    DIR *directory = opendir(path);
    if (directory == NULL) {
        return up_fail(ctx, "read FairPlay enrollment model registry: %s", strerror(errno));
    }
    char **names = NULL;
    size_t name_count = 0;
    struct dirent *entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!up_has_bin_extension(entry->d_name)) {
            continue;
        }
        char **grown = realloc(names, (name_count + 1) * sizeof(char *));
        if (grown == NULL) {
            closedir(directory);
            for (size_t index = 0; index < name_count; index++) {
                free(names[index]);
            }
            free(names);
            return up_fail(ctx, "out of memory");
        }
        names = grown;
        names[name_count] = malloc(strlen(entry->d_name) + 1);
        if (names[name_count] == NULL) {
            closedir(directory);
            for (size_t index = 0; index < name_count; index++) {
                free(names[index]);
            }
            free(names);
            return up_fail(ctx, "out of memory");
        }
        strcpy(names[name_count], entry->d_name);
        name_count++;
    }
    closedir(directory);
    qsort(names, name_count, sizeof(char *), up_compare_names);

    up_model_registry registry = {NULL, 0};
    int status = 1;
    for (size_t index = 0; index < name_count; index++) {
        if (registry.count == UP_MAX_MODELS) {
            status = up_fail(ctx,
                             "FairPlay enrollment model registry contains more than %d models",
                             UP_MAX_MODELS);
            break;
        }
        char *member_path = up_join_path(path, names[index]);
        if (member_path == NULL) {
            status = up_fail(ctx, "out of memory");
            break;
        }
        struct lstat_result {
            struct stat info;
            int error;
        } link;
        link.error = lstat(member_path, &link.info);
        if (link.error == 0 && S_ISLNK(link.info.st_mode)) {
            status = up_fail(ctx, "FairPlay enrollment model registry contains a symlink: %s",
                             names[index]);
            free(member_path);
            break;
        }
        up_model_pack *grown =
            realloc(registry.packs, (registry.count + 1) * sizeof(up_model_pack));
        if (grown == NULL) {
            free(member_path);
            status = up_fail(ctx, "out of memory");
            break;
        }
        registry.packs = grown;
        up_model_pack pack;
        if (!up_read_model_file(ctx, member_path, &pack)) {
            free(member_path);
            status = 0;
            break;
        }
        free(member_path);
        registry.packs[registry.count++] = pack;
    }
    for (size_t index = 0; index < name_count; index++) {
        free(names[index]);
    }
    free(names);
    if (!status) {
        up_model_registry_free(&registry);
        return 0;
    }
    if (registry.count == 0) {
        up_model_registry_free(&registry);
        return up_fail(ctx, "FairPlay enrollment model registry contains no .bin models");
    }
    *out = registry;
    return 1;
}
