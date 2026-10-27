//
//  up_doctor.c
//  CUnfairPlay
//
//  `up_models_report` and `up_doctor`. Doctor port mirrors DoctorFairPlay with
//  capture disabled and the host block omitted: the host block is not part of
//  the Swift contract and does not influence readiness when an IPA and a model
//  are supplied.
//

#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "include/unfairplay.h"

#include "up_crypto.h"
#include "up_ipa.h"
#include "up_license.h"
#include "up_model.h"
#include "up_sinf.h"

// MARK: - Strings and checks

typedef struct {
    char **items;
    size_t count;
} up_string_list;

static void up_string_list_free(up_string_list *list) {
    for (size_t index = 0; index < list->count; index++) {
        free(list->items[index]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static int up_string_list_append(up_context *ctx, up_string_list *list, const char *value) {
    char **grown = realloc(list->items, (list->count + 1) * sizeof(char *));
    if (grown == NULL) {
        return up_fail(ctx, "out of memory");
    }
    list->items = grown;
    list->items[list->count] = malloc(strlen(value) + 1);
    if (list->items[list->count] == NULL) {
        return up_fail(ctx, "out of memory");
    }
    memcpy(list->items[list->count], value, strlen(value) + 1);
    list->count++;
    return 1;
}

static int up_string_list_appendf(up_context *ctx, up_string_list *list, const char *format, ...) {
    char stack[512];
    va_list arguments;
    va_start(arguments, format);
    int needed = vsnprintf(stack, sizeof(stack), format, arguments);
    va_end(arguments);
    if (needed < 0) {
        return up_fail(ctx, "formatting failure");
    }
    if ((size_t)needed < sizeof(stack)) {
        return up_string_list_append(ctx, list, stack);
    }
    char *heap = malloc((size_t)needed + 1);
    if (heap == NULL) {
        return up_fail(ctx, "out of memory");
    }
    va_start(arguments, format);
    vsnprintf(heap, (size_t)needed + 1, format, arguments);
    va_end(arguments);
    int status = up_string_list_append(ctx, list, heap);
    free(heap);
    return status;
}

typedef struct {
    char name[48];
    bool value;
} up_check;

typedef struct {
    up_check items[16];
    size_t count;
} up_check_set;

static void up_check_set_put(up_check_set *set, const char *name, bool value) {
    for (size_t index = 0; index < set->count; index++) {
        if (strcmp(set->items[index].name, name) == 0) {
            set->items[index].value = value;
            return;
        }
    }
    if (set->count < sizeof(set->items) / sizeof(set->items[0])) {
        snprintf(set->items[set->count].name, sizeof(set->items[0].name), "%s", name);
        set->items[set->count].value = value;
        set->count++;
    }
}

static bool up_check_set_get(const up_check_set *set, const char *name) {
    for (size_t index = 0; index < set->count; index++) {
        if (strcmp(set->items[index].name, name) == 0) {
            return set->items[index].value;
        }
    }
    return false;
}

static int up_compare_checks(const void *left, const void *right) {
    const up_check *left_value = left;
    const up_check *right_value = right;
    return strcmp(left_value->name, right_value->name);
}

// MARK: - Diagnostics

typedef struct {
    char *path;
    char *error;
    char sha256[65];
    int64_t bytes;
    up_selector selector;
    char selector_id[18];
    size_t private_bytes;
    char **atoms;
    size_t atom_count;
    bool current_layout;
    bool legacy_markers;
} up_sinf_diagnostic;

static void up_sinf_diagnostics_free(up_sinf_diagnostic *diagnostics, size_t count) {
    for (size_t index = 0; index < count; index++) {
        free(diagnostics[index].path);
        free(diagnostics[index].error);
        for (size_t atom = 0; atom < diagnostics[index].atom_count; atom++) {
            free(diagnostics[index].atoms[atom]);
        }
        free(diagnostics[index].atoms);
    }
    free(diagnostics);
}

static int up_inspect_sinf(up_context *ctx,
                           const uint8_t *data,
                           size_t length,
                           up_sinf_diagnostic *out) {
    uint8_t digest[32];
    up_sha256(data, length, digest);
    up_hex_encode(digest, sizeof(digest), out->sha256);
    out->bytes = (int64_t)length;
    up_atoms fields = {NULL, 0};
    if (!up_sinf_fields(ctx, data, length, &fields)) {
        return 0;
    }
    up_selector selector;
    if (!up_sinf_selector(ctx, data, length, &fields, &selector)) {
        up_atoms_free(&fields);
        return 0;
    }
    out->selector = selector;
    snprintf(out->selector_id, sizeof(out->selector_id), "%08x:%08x", selector.user, selector.key);
    for (size_t index = 0; index < fields.count; index++) {
        char **grown = realloc(out->atoms, (out->atom_count + 1) * sizeof(char *));
        if (grown == NULL) {
            up_atoms_free(&fields);
            return up_fail(ctx, "out of memory");
        }
        out->atoms = grown;
        out->atoms[out->atom_count] = malloc(5);
        if (out->atoms[out->atom_count] == NULL) {
            up_atoms_free(&fields);
            return up_fail(ctx, "out of memory");
        }
        memcpy(out->atoms[out->atom_count], fields.items[index].type, 5);
        out->atom_count++;
        if (strcmp(fields.items[index].type, "priv") == 0) {
            out->private_bytes = fields.items[index].end - fields.items[index].start;
        }
        if (strcmp(fields.items[index].type, "crdt") == 0 ||
            strcmp(fields.items[index].type, "asdt") == 0) {
            out->legacy_markers = true;
        }
    }
    up_atoms_free(&fields);
    out->current_layout = out->private_bytes == 440 || out->private_bytes == 448;
    return 1;
}

static char *up_join_errors(const up_string_list *list) {
    up_buf joined;
    up_buf_init(&joined);
    for (size_t index = 0; index < list->count; index++) {
        if (index != 0) {
            up_buf_append(&joined, "\n", 1);
        }
        up_buf_append(&joined, list->items[index], strlen(list->items[index]));
    }
    if (joined.failed) {
        up_buf_free(&joined);
        return NULL;
    }
    char *result = malloc(joined.length + 1);
    if (result != NULL) {
        memcpy(result, joined.bytes, joined.length + 1);
    }
    up_buf_free(&joined);
    return result;
}

static int up_compare_sinf_paths(const void *left, const void *right) {
    const up_sinf_diagnostic *left_value = left;
    const up_sinf_diagnostic *right_value = right;
    return strcmp(left_value->path, right_value->path);
}

/// Port of inspectIPASINFs. `used` is NULL to scan every license.
static int up_inspect_ipa_sinfs(up_context *ctx,
                                const up_zip *archive,
                                const char *const *used,
                                size_t used_count,
                                up_sinf_diagnostic **out,
                                size_t *count,
                                char **error_text) {
    *out = NULL;
    *count = 0;
    *error_text = NULL;
    up_sinf_diagnostic *diagnostics = NULL;
    size_t diagnostic_count = 0;
    up_string_list failures;
    memset(&failures, 0, sizeof(failures));
    for (size_t index = 0; index < archive->count; index++) {
        const up_zip_entry *entry = &archive->entries[index];
        bool include = false;
        if (used != NULL) {
            for (size_t used_index = 0; used_index < used_count; used_index++) {
                if (strcmp(entry->name, used[used_index]) == 0) {
                    include = true;
                    break;
                }
            }
        } else {
            size_t name_length = strlen(entry->name);
            bool in_sci = strstr(entry->name, "/SC_Info/") != NULL ||
                          strncmp(entry->name, "SC_Info/", 8) == 0;
            bool sinf = name_length >= 5;
            if (sinf) {
                char suffix[6];
                for (size_t offset = 0; offset < 5; offset++) {
                    char character = entry->name[name_length - 5 + offset];
                    if (character >= 'A' && character <= 'Z') {
                        character = (char)(character - 'A' + 'a');
                    }
                    suffix[offset] = character;
                }
                suffix[5] = '\0';
                sinf = strcmp(suffix, ".sinf") == 0;
            }
            include = in_sci && sinf;
        }
        if (!include) {
            continue;
        }
        up_sinf_diagnostic value;
        memset(&value, 0, sizeof(value));
        value.path = malloc(strlen(entry->name) + 1);
        if (value.path == NULL) {
            up_string_list_free(&failures);
            return up_fail(ctx, "out of memory");
        }
        memcpy(value.path, entry->name, strlen(entry->name) + 1);
        uint8_t *data = NULL;
        size_t length = 0;
        bool ok = up_zip_read(ctx, archive, entry, &data, &length);
        if (ok) {
            ok = up_inspect_sinf(ctx, data, length, &value);
            free(data);
        }
        if (!ok) {
            const char *current = up_last_error(ctx);
            value.error = malloc(strlen(current == NULL ? "unknown error" : current) + 1);
            if (value.error == NULL) {
                up_sinf_diagnostics_free(diagnostics, diagnostic_count);
                free(value.path);
                up_string_list_free(&failures);
                return up_fail(ctx, "out of memory");
            }
            strcpy(value.error, current == NULL ? "unknown error" : current);
            up_string_list_appendf(ctx, &failures, "inspect %s: %s", entry->name, value.error);
        }
        up_sinf_diagnostic *grown =
            realloc(diagnostics, (diagnostic_count + 1) * sizeof(up_sinf_diagnostic));
        if (grown == NULL) {
            free(value.path);
            free(value.error);
            for (size_t atom = 0; atom < value.atom_count; atom++) {
                free(value.atoms[atom]);
            }
            free(value.atoms);
            up_sinf_diagnostics_free(diagnostics, diagnostic_count);
            up_string_list_free(&failures);
            return up_fail(ctx, "out of memory");
        }
        diagnostics = grown;
        diagnostics[diagnostic_count++] = value;
    }
    if (diagnostic_count == 0) {
        up_string_list_append(ctx, &failures, "IPA contains no SINF files");
    } else {
        qsort(diagnostics, diagnostic_count, sizeof(up_sinf_diagnostic), up_compare_sinf_paths);
    }
    if (failures.count != 0) {
        *error_text = up_join_errors(&failures);
        if (*error_text == NULL) {
            up_sinf_diagnostics_free(diagnostics, diagnostic_count);
            up_string_list_free(&failures);
            return up_fail(ctx, "out of memory");
        }
    }
    up_string_list_free(&failures);
    *out = diagnostics;
    *count = diagnostic_count;
    return 1;
}

typedef struct {
    char *path;
    char sha256[65];
    int64_t bytes;
    uint32_t version;
    char evaluator_source_sha256[65];
    bool has_selector;
    up_selector selector;
    char selector_id[18];
} up_model_diagnostic;

static void up_model_diagnostics_free(up_model_diagnostic *diagnostics, size_t count) {
    for (size_t index = 0; index < count; index++) {
        free(diagnostics[index].path);
    }
    free(diagnostics);
}

static int up_inspect_model_pack(up_context *ctx,
                                 const up_model_pack *pack,
                                 const char *path,
                                 up_model_diagnostic *out) {
    memset(out, 0, sizeof(*out));
    out->path = malloc(strlen(path) + 1);
    if (out->path == NULL) {
        return up_fail(ctx, "out of memory");
    }
    memcpy(out->path, path, strlen(path) + 1);
    up_model model;
    if (!up_model_parse(ctx, pack->bytes, pack->length, &model)) {
        return 0;
    }
    uint8_t digest[32];
    up_sha256(pack->bytes, pack->length, digest);
    up_hex_encode(digest, sizeof(digest), out->sha256);
    out->bytes = (int64_t)pack->length;
    out->version = model.version;
    up_hex_encode(model.fairplayd_hash, sizeof(model.fairplayd_hash),
                  out->evaluator_source_sha256);
    if (model.has_selector) {
        out->has_selector = true;
        out->selector = model.selector;
        snprintf(out->selector_id, sizeof(out->selector_id), "%08x:%08x", model.selector.user,
                 model.selector.key);
    }
    return 1;
}

static int up_inspect_models(up_context *ctx,
                             const up_model_registry *registry,
                             up_model_diagnostic **out,
                             size_t *count) {
    *out = NULL;
    *count = 0;
    up_model_diagnostic *diagnostics = calloc(registry->count == 0 ? 1 : registry->count,
                                              sizeof(up_model_diagnostic));
    if (diagnostics == NULL) {
        return up_fail(ctx, "out of memory");
    }
    size_t diagnostic_count = 0;
    int status = 1;
    for (size_t index = 0; index < registry->count; index++) {
        if (!up_inspect_model_pack(ctx, &registry->packs[index], registry->packs[index].path,
                                   &diagnostics[diagnostic_count])) {
            status = 0;
            break;
        }
        diagnostic_count++;
    }
    if (!status) {
        up_model_diagnostics_free(diagnostics, diagnostic_count);
        return 0;
    }
    *out = diagnostics;
    *count = diagnostic_count;
    return 1;
}

// MARK: - Model matching

static int up_validated_model_for_sinf(up_context *ctx,
                                       const up_ipa_inventory *inventory,
                                       const char *member,
                                       const up_model_registry *registry,
                                       bool registry_mode,
                                       const up_model_diagnostic *models,
                                       size_t model_count,
                                       char **selected_path) {
    *selected_path = NULL;
    const up_zip_entry *entry = up_ipa_entry(ctx, inventory, member);
    if (entry == NULL) {
        return 0;
    }
    uint8_t *sinf = NULL;
    size_t sinf_length = 0;
    if (!up_zip_read(ctx, &inventory->archive, entry, &sinf, &sinf_length)) {
        return 0;
    }
    up_key_material material;
    bool resolved =
        registry_mode
            ? up_resolve_with_registry(ctx, sinf, sinf_length, registry, &material, NULL)
            : up_resolve_with_model(ctx, sinf, sinf_length, registry->packs[0].bytes,
                                    registry->packs[0].length, &material, NULL);
    free(sinf);
    if (!resolved) {
        return 0;
    }
    for (size_t index = 0; index < model_count; index++) {
        if (strcmp(models[index].sha256, material.model_sha256) == 0) {
            *selected_path = malloc(strlen(models[index].path) + 1);
            if (*selected_path == NULL) {
                return up_fail(ctx, "out of memory");
            }
            memcpy(*selected_path, models[index].path, strlen(models[index].path) + 1);
            return 1;
        }
    }
    return up_fail(ctx, "validated enrollment model is missing from diagnostics");
}

// MARK: - JSON

static void up_json_string_list(up_buf *buffer, const up_string_list *list, int level) {
    up_buf_append(buffer, "[", 1);
    for (size_t index = 0; index < list->count; index++) {
        if (index != 0) {
            up_buf_append(buffer, ",", 1);
        }
        up_json_indent(buffer, level + 1);
        up_json_string(buffer, list->items[index]);
    }
    if (list->count != 0) {
        up_json_indent(buffer, level);
    }
    up_buf_append(buffer, "]", 1);
}

static void up_json_sinf_diagnostics(up_buf *buffer,
                                     const up_sinf_diagnostic *diagnostics,
                                     size_t count) {
    up_buf_append(buffer, "[", 1);
    for (size_t index = 0; index < count; index++) {
        const up_sinf_diagnostic *value = &diagnostics[index];
        if (index != 0) {
            up_buf_append(buffer, ",", 1);
        }
        up_json_indent(buffer, 2);
        up_buf_append(buffer, "{", 1);
        if (value->error != NULL) {
            up_json_indent(buffer, 3);
            up_json_key(buffer, "error");
            up_json_string(buffer, value->error);
            up_buf_append(buffer, ",", 1);
        }
        up_json_indent(buffer, 3);
        up_json_key(buffer, "path");
        up_json_string(buffer, value->path);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "sha256");
        up_json_string(buffer, value->sha256);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "bytes");
        up_json_int(buffer, value->bytes);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "selector");
        up_buf_append(buffer, "{", 1);
        up_json_indent(buffer, 4);
        up_json_key(buffer, "user");
        up_json_uint(buffer, value->selector.user);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 4);
        up_json_key(buffer, "key");
        up_json_uint(buffer, value->selector.key);
        up_json_indent(buffer, 3);
        up_buf_append(buffer, "}", 1);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "selector_id");
        up_json_string(buffer, value->selector_id);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "private_bytes");
        up_json_uint(buffer, value->private_bytes);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "atoms");
        if (value->atom_count == 0) {
            up_buf_append(buffer, "null", 4);
        } else {
            up_buf_append(buffer, "[", 1);
            for (size_t atom = 0; atom < value->atom_count; atom++) {
                if (atom != 0) {
                    up_buf_append(buffer, ",", 1);
                }
                up_json_indent(buffer, 4);
                up_json_string(buffer, value->atoms[atom]);
            }
            up_json_indent(buffer, 3);
            up_buf_append(buffer, "]", 1);
        }
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "current_layout");
        up_json_bool(buffer, value->current_layout);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "legacy_markers");
        up_json_bool(buffer, value->legacy_markers);
        up_json_indent(buffer, 2);
        up_buf_append(buffer, "}", 1);
    }
    if (count != 0) {
        up_json_indent(buffer, 1);
    }
    up_buf_append(buffer, "]", 1);
}

static void up_json_model_diagnostics(up_buf *buffer,
                                      const up_model_diagnostic *diagnostics,
                                      size_t count) {
    up_buf_append(buffer, "[", 1);
    for (size_t index = 0; index < count; index++) {
        const up_model_diagnostic *value = &diagnostics[index];
        if (index != 0) {
            up_buf_append(buffer, ",", 1);
        }
        up_json_indent(buffer, 2);
        up_buf_append(buffer, "{", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "path");
        up_json_string(buffer, value->path);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "sha256");
        up_json_string(buffer, value->sha256);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "bytes");
        up_json_int(buffer, value->bytes);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "version");
        up_json_uint(buffer, value->version);
        up_buf_append(buffer, ",", 1);
        up_json_indent(buffer, 3);
        up_json_key(buffer, "evaluator_source_sha256");
        up_json_string(buffer, value->evaluator_source_sha256);
        if (value->has_selector) {
            up_buf_append(buffer, ",", 1);
            up_json_indent(buffer, 3);
            up_json_key(buffer, "selector");
            up_buf_append(buffer, "{", 1);
            up_json_indent(buffer, 4);
            up_json_key(buffer, "user");
            up_json_uint(buffer, value->selector.user);
            up_buf_append(buffer, ",", 1);
            up_json_indent(buffer, 4);
            up_json_key(buffer, "key");
            up_json_uint(buffer, value->selector.key);
            up_json_indent(buffer, 3);
            up_buf_append(buffer, "}", 1);
            up_buf_append(buffer, ",", 1);
            up_json_indent(buffer, 3);
            up_json_key(buffer, "selector_id");
            up_json_string(buffer, value->selector_id);
        }
        up_json_indent(buffer, 2);
        up_buf_append(buffer, "}", 1);
    }
    if (count != 0) {
        up_json_indent(buffer, 1);
    }
    up_buf_append(buffer, "]", 1);
}

// MARK: - Models report

static int up_load_model_registry(up_context *ctx,
                                  const char *path,
                                  up_model_registry *out,
                                  bool *is_directory) {
    memset(out, 0, sizeof(*out));
    *is_directory = false;
    struct stat info;
    if (stat(path, &info) != 0) {
        return up_fail(ctx, "inspect FairPlay enrollment model: %s", strerror(errno));
    }
    if (S_ISDIR(info.st_mode)) {
        *is_directory = true;
        return up_read_model_registry(ctx, path, out);
    }
    up_model_pack pack;
    if (!up_read_model_file(ctx, path, &pack)) {
        return 0;
    }
    out->packs = malloc(sizeof(up_model_pack));
    if (out->packs == NULL) {
        up_model_pack_free(&pack);
        return up_fail(ctx, "out of memory");
    }
    out->packs[0] = pack;
    out->count = 1;
    return 1;
}

int up_models_report(up_context *ctx, char **json_out) {
    if (json_out == NULL) {
        return up_fail(ctx, "model report output is required");
    }
    *json_out = NULL;
    if (ctx->model_directory == NULL || ctx->model_directory[0] == '\0') {
        return up_fail(ctx, "no saved enrollment models");
    }
    up_model_registry registry;
    bool is_directory = false;
    if (!up_load_model_registry(ctx, ctx->model_directory, &registry, &is_directory)) {
        return 0;
    }
    up_model_diagnostic *models = NULL;
    size_t model_count = 0;
    int status = up_inspect_models(ctx, &registry, &models, &model_count);
    if (status) {
        up_buf buffer;
        up_buf_init(&buffer);
        up_buf_append(&buffer, "{", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "schema");
        up_json_string(&buffer, "unfairplay-models-v1");
        up_buf_append(&buffer, ",", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "directory");
        up_json_string(&buffer, ctx->model_directory);
        up_buf_append(&buffer, ",", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "models");
        up_json_model_diagnostics(&buffer, models, model_count);
        up_json_indent(&buffer, 0);
        up_buf_append(&buffer, "}", 1);
        up_buf_append(&buffer, "\n", 1);
        if (buffer.failed) {
            status = up_fail(ctx, "out of memory");
            up_buf_free(&buffer);
        } else {
            *json_out = up_buf_detach(&buffer, ctx);
            if (*json_out == NULL) {
                status = 0;
            }
        }
    }
    up_model_diagnostics_free(models, model_count);
    up_model_registry_free(&registry);
    (void)is_directory;
    return status;
}

// MARK: - Doctor

int up_doctor(up_context *ctx, const char *ipa_path, char **json_out) {
    if (json_out == NULL) {
        return up_fail(ctx, "doctor report output is required");
    }
    *json_out = NULL;
    bool have_ipa = ipa_path != NULL && ipa_path[0] != '\0';
    const char *model_path =
        (ctx->model_directory != NULL && ctx->model_directory[0] != '\0') ? ctx->model_directory
                                                                          : NULL;
    up_string_list errors;
    up_string_list warnings;
    up_string_list actions;
    memset(&errors, 0, sizeof(errors));
    memset(&warnings, 0, sizeof(warnings));
    memset(&actions, 0, sizeof(actions));
    up_check_set checks;
    memset(&checks, 0, sizeof(checks));
    up_sinf_diagnostic *sinfs = NULL;
    size_t sinf_count = 0;
    up_model_diagnostic *models = NULL;
    size_t model_count = 0;
    up_model_registry registry;
    memset(&registry, 0, sizeof(registry));
    bool registry_mode = false;
    up_ipa_inventory inventory;
    memset(&inventory, 0, sizeof(inventory));
    inventory.archive.descriptor = -1;
    bool inventory_open = false;
    int status = 1;
    char *compatible_model = NULL;
    char **compatible_sinf = NULL;
    char **compatible_path = NULL;
    size_t compatible_count = 0;

    if (have_ipa) {
        inventory_open = up_ipa_inventory_open(ctx, ipa_path, &inventory);
        if (!inventory_open) {
            char *detail = up_last_error(ctx) == NULL ? NULL : strdup(up_last_error(ctx));
            status = up_string_list_appendf(ctx, &errors, "ipa inventory: %s",
                                            detail == NULL ? "unknown error" : detail);
            free(detail);
        } else {
            up_check_set_put(&checks, "ipa_inventory", true);
        }
        if (!status) {
            goto finish;
        }
        const char *const *used = NULL;
        size_t used_count = 0;
        char **used_names = NULL;
        if (inventory_open) {
            used_names = calloc(inventory.image_count == 0 ? 1 : inventory.image_count,
                                sizeof(char *));
            if (used_names == NULL) {
                status = up_fail(ctx, "out of memory");
                goto finish;
            }
            for (size_t index = 0; index < inventory.image_count; index++) {
                const char *name = inventory.images[index].sinf_member;
                bool seen = false;
                for (size_t inner = 0; inner < used_count; inner++) {
                    if (strcmp(used_names[inner], name) == 0) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    used_names[used_count++] = (char *)name;
                }
            }
            used = (const char *const *)used_names;
        }
        char *sinf_error = NULL;
        if (inventory_open) {
            up_zip archive = inventory.archive;
            status = up_inspect_ipa_sinfs(ctx, &archive, used, used_count, &sinfs, &sinf_count,
                                          &sinf_error);
        } else {
            up_zip archive;
            memset(&archive, 0, sizeof(archive));
            archive.descriptor = -1;
            if (up_zip_open(ctx, ipa_path, &archive)) {
                status = up_inspect_ipa_sinfs(ctx, &archive, NULL, 0, &sinfs, &sinf_count,
                                              &sinf_error);
                up_zip_close(&archive);
            } else {
                const char *detail = up_last_error(ctx);
                status = up_string_list_appendf(
                    ctx, &errors, "ipa: %s",
                    detail == NULL || detail[0] == '\0' ? "unknown error" : detail);
            }
        }
        free(used_names);
        if (!status) {
            free(sinf_error);
            goto finish;
        }
        if (sinf_error != NULL) {
            status = up_string_list_appendf(ctx, &errors, "ipa: %s", sinf_error);
            free(sinf_error);
            if (!status) {
                goto finish;
            }
        }
        if (sinf_count > 0) {
            up_check_set_put(&checks, "ipa_sinf", sinf_error == NULL);
            bool current = sinf_error == NULL;
            for (size_t index = 0; index < sinf_count; index++) {
                current = current && sinfs[index].current_layout;
            }
            up_check_set_put(&checks, "current_sinf_layout", current);
            if (!current) {
                status = up_string_list_append(
                    ctx, &warnings,
                    "one or more inspected SINF files use an unsupported or legacy layout");
                if (!status) {
                    goto finish;
                }
            }
        }
    }
    if (sinf_count != 0) {
        status = up_string_list_append(
            ctx, &warnings,
            "SINF geometry cannot prove account age; untested migrated or legacy enrollment "
            "layouts still fail closed");
        if (!status) {
            goto finish;
        }
    }
    if (model_path != NULL) {
        if (!up_load_model_registry(ctx, model_path, &registry, &registry_mode)) {
            char *detail = up_last_error(ctx) == NULL ? NULL : strdup(up_last_error(ctx));
            status = up_string_list_appendf(ctx, &errors, "model: %s",
                                            detail == NULL ? "unknown error" : detail);
            free(detail);
            if (!status) {
                goto finish;
            }
        } else {
            if (!up_inspect_models(ctx, &registry, &models, &model_count)) {
                char *detail = up_last_error(ctx) == NULL ? NULL : strdup(up_last_error(ctx));
                status = up_string_list_appendf(ctx, &errors, "model: %s",
                                                detail == NULL ? "unknown error" : detail);
                free(detail);
                if (!status) {
                    goto finish;
                }
            } else {
                up_check_set_put(&checks, "model_valid", true);
            }
        }
    }
    if (sinf_count != 0 && model_count != 0) {
        bool all_selectors = true;
        bool all_validated = true;
        // Go passes the raw `--model` value here, which is the directory in
        // registry mode, not the first pack inside it.
        const char *resolved_model_path = model_path;
        for (size_t index = 0; index < sinf_count; index++) {
            const up_sinf_diagnostic *sinf = &sinfs[index];
            bool matched = false;
            for (size_t model_index = 0; model_index < model_count; model_index++) {
                const up_model_diagnostic *model = &models[model_index];
                if ((strcmp(model->selector_id, sinf->selector_id) == 0) ||
                    (!model->has_selector && model_count == 1)) {
                    matched = true;
                }
            }
            if (!matched) {
                all_selectors = false;
                all_validated = false;
                status = up_string_list_appendf(ctx, &errors, "no enrollment model matches SINF %s",
                                                sinf->path);
                if (!status) {
                    goto finish;
                }
                continue;
            }
            char *selected = NULL;
            if (!up_validated_model_for_sinf(ctx, &inventory, sinf->path, &registry,
                                             registry_mode, models, model_count, &selected)) {
                all_validated = false;
                char *detail = up_last_error(ctx) == NULL ? NULL : strdup(up_last_error(ctx));
                status = up_string_list_appendf(ctx, &errors, "model validation for %s: %s",
                                                sinf->path,
                                                detail == NULL ? "unknown error" : detail);
                free(detail);
                if (!status) {
                    goto finish;
                }
            } else {
                char **grown_sinf =
                    realloc(compatible_sinf, (compatible_count + 1) * sizeof(char *));
                char **grown_path =
                    realloc(compatible_path, (compatible_count + 1) * sizeof(char *));
                if (grown_sinf == NULL || grown_path == NULL) {
                    free(grown_sinf == NULL ? compatible_sinf : grown_sinf);
                    free(grown_path == NULL ? compatible_path : grown_path);
                    compatible_sinf = NULL;
                    compatible_path = NULL;
                    free(selected);
                    status = up_fail(ctx, "out of memory");
                    goto finish;
                }
                compatible_sinf = grown_sinf;
                compatible_path = grown_path;
                compatible_sinf[compatible_count] = strdup(sinf->path);
                compatible_path[compatible_count] = strdup(selected);
                if (compatible_sinf[compatible_count] == NULL ||
                    compatible_path[compatible_count] == NULL) {
                    free(compatible_sinf[compatible_count]);
                    free(compatible_path[compatible_count]);
                    free(compatible_sinf);
                    free(compatible_path);
                    compatible_sinf = NULL;
                    compatible_path = NULL;
                    compatible_count = 0;
                    free(selected);
                    status = up_fail(ctx, "out of memory");
                    goto finish;
                }
                compatible_count++;
                if (compatible_model == NULL) {
                    // Ownership of `selected` moves to `compatible_model`.
                    compatible_model = selected;
                    selected = NULL;
                } else if (strcmp(compatible_model, selected) != 0) {
                    free(compatible_model);
                    compatible_model = strdup(resolved_model_path);
                    if (compatible_model == NULL) {
                        free(selected);
                        status = up_fail(ctx, "out of memory");
                        goto finish;
                    }
                }
                free(selected);
            }
        }
        if (!all_validated && compatible_model != NULL) {
            free(compatible_model);
            compatible_model = NULL;
        }
        up_check_set_put(&checks, "selector_match", all_selectors);
        up_check_set_put(&checks, "sinf_model_validation", all_validated);
    }
    status = up_string_list_append(ctx, &actions,
                                   "collect native enrollment with fairplay-enroll collect");
    if (!status) {
        goto finish;
    }
    if (model_path != NULL && compatible_model != NULL) {
        status = up_string_list_append(ctx, &actions,
                                       "run unfairplay decrypt with the validated model");
        if (!status) {
            goto finish;
        }
    }
    {
        bool ready = false;
        if (sinf_count != 0 || model_path != NULL) {
            ready = errors.count == 0 && up_check_set_get(&checks, "current_sinf_layout") &&
                    (model_path == NULL || up_check_set_get(&checks, "sinf_model_validation"));
        }
        bool decrypt_ready = model_path != NULL && ready && compatible_model != NULL;

        up_buf buffer;
        up_buf_init(&buffer);
        char created_at[32];
        time_t now = time(NULL);
        struct tm utc;
        gmtime_r(&now, &utc);
        strftime(created_at, sizeof(created_at), "%Y-%m-%dT%H:%M:%SZ", &utc);
        up_buf_append(&buffer, "{", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "schema");
        up_json_string(&buffer, "unfairplay-doctor-v1");
        up_buf_append(&buffer, ",", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "created_at");
        up_json_string(&buffer, created_at);
        up_buf_append(&buffer, ",", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "ready");
        up_json_bool(&buffer, ready);
        up_buf_append(&buffer, ",", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "decrypt_ready");
        up_json_bool(&buffer, decrypt_ready);
        up_buf_append(&buffer, ",", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "capture_verified");
        up_json_bool(&buffer, false);
        if (sinf_count != 0) {
            up_buf_append(&buffer, ",", 1);
            up_json_indent(&buffer, 1);
            up_json_key(&buffer, "sinf");
            up_json_sinf_diagnostics(&buffer, sinfs, sinf_count);
        }
        if (model_count != 0) {
            up_buf_append(&buffer, ",", 1);
            up_json_indent(&buffer, 1);
            up_json_key(&buffer, "models");
            up_json_model_diagnostics(&buffer, models, model_count);
        }
        if (compatible_model != NULL) {
            up_buf_append(&buffer, ",", 1);
            up_json_indent(&buffer, 1);
            up_json_key(&buffer, "compatible_model");
            up_json_string(&buffer, compatible_model);
        }
        if (compatible_count != 0) {
            up_buf_append(&buffer, ",", 1);
            up_json_indent(&buffer, 1);
            up_json_key(&buffer, "compatible_models_by_sinf");
            up_buf_append(&buffer, "{", 1);
            for (size_t index = 0; index < compatible_count; index++) {
                if (index != 0) {
                    up_buf_append(&buffer, ",", 1);
                }
                up_json_indent(&buffer, 2);
                up_json_key(&buffer, compatible_sinf[index]);
                up_json_string(&buffer, compatible_path[index]);
            }
            up_json_indent(&buffer, 1);
            up_buf_append(&buffer, "}", 1);
        }
        up_buf_append(&buffer, ",", 1);
        up_json_indent(&buffer, 1);
        up_json_key(&buffer, "checks");
        up_check sorted_checks[16];
        memcpy(sorted_checks, checks.items, checks.count * sizeof(up_check));
        qsort(sorted_checks, checks.count, sizeof(up_check), up_compare_checks);
        up_buf_append(&buffer, "{", 1);
        for (size_t index = 0; index < checks.count; index++) {
            if (index != 0) {
                up_buf_append(&buffer, ",", 1);
            }
            up_json_indent(&buffer, 2);
            up_json_key(&buffer, sorted_checks[index].name);
            up_json_bool(&buffer, sorted_checks[index].value);
        }
        if (checks.count != 0) {
            up_json_indent(&buffer, 1);
        }
        up_buf_append(&buffer, "}", 1);
        if (errors.count != 0) {
            up_buf_append(&buffer, ",", 1);
            up_json_indent(&buffer, 1);
            up_json_key(&buffer, "errors");
            up_json_string_list(&buffer, &errors, 1);
        }
        if (warnings.count != 0) {
            up_buf_append(&buffer, ",", 1);
            up_json_indent(&buffer, 1);
            up_json_key(&buffer, "warnings");
            up_json_string_list(&buffer, &warnings, 1);
        }
        if (actions.count != 0) {
            up_buf_append(&buffer, ",", 1);
            up_json_indent(&buffer, 1);
            up_json_key(&buffer, "next_actions");
            up_json_string_list(&buffer, &actions, 1);
        }
        up_json_indent(&buffer, 0);
        up_buf_append(&buffer, "}", 1);
        if (buffer.failed) {
            status = up_fail(ctx, "out of memory");
            up_buf_free(&buffer);
        } else {
            *json_out = up_buf_detach(&buffer, ctx);
            if (*json_out == NULL) {
                status = 0;
            }
        }
    }
finish:
    free(compatible_model);
    for (size_t index = 0; index < compatible_count; index++) {
        free(compatible_sinf[index]);
        free(compatible_path[index]);
    }
    free(compatible_sinf);
    free(compatible_path);
    up_string_list_free(&errors);
    up_string_list_free(&warnings);
    up_string_list_free(&actions);
    up_sinf_diagnostics_free(sinfs, sinf_count);
    up_model_diagnostics_free(models, model_count);
    up_model_registry_free(&registry);
    if (inventory_open) {
        up_ipa_inventory_close(&inventory);
    }
    return status;
}
