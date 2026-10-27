//
//  up_context.c
//  CUnfairPlay
//
//  Context lifecycle, error reporting, and the small JSON writer used by every
//  report. The accepted input is always produced by this library, so the
//  writer only needs to emit, never to parse.
//

#include "up_internal.h"

#include <ctype.h>

static char *up_format(const char *format, va_list arguments) {
    va_list copy;
    va_copy(copy, arguments);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0) {
        return NULL;
    }
    char *result = malloc((size_t)needed + 1);
    if (result == NULL) {
        return NULL;
    }
    vsnprintf(result, (size_t)needed + 1, format, arguments);
    return result;
}

int up_fail(up_context *ctx, const char *format, ...) {
    if (ctx != NULL) {
        va_list arguments;
        va_start(arguments, format);
        char *message = up_format(format, arguments);
        va_end(arguments);
        free(ctx->error);
        ctx->error = message;
    }
    return 0;
}

const char *up_last_error(up_context *ctx) {
    if (ctx == NULL || ctx->error == NULL) {
        return "";
    }
    return ctx->error;
}

const char *up_version(void) {
    return "0.2.0-native";
}

up_context *up_context_create(const char *model_directory) {
    up_context *ctx = calloc(1, sizeof(up_context));
    if (ctx == NULL) {
        return NULL;
    }
    if (model_directory != NULL && model_directory[0] != '\0') {
        size_t length = strlen(model_directory);
        ctx->model_directory = malloc(length + 1);
        if (ctx->model_directory == NULL) {
            free(ctx);
            return NULL;
        }
        memcpy(ctx->model_directory, model_directory, length + 1);
    }
    return ctx;
}

void up_context_free(up_context *ctx) {
    if (ctx == NULL) {
        return;
    }
    free(ctx->model_directory);
    free(ctx->error);
    free(ctx);
}

void up_string_free(char *value) {
    free(value);
}

// MARK: - Buffers

void up_buf_init(up_buf *buf) {
    memset(buf, 0, sizeof(*buf));
}

void up_buf_free(up_buf *buf) {
    if (buf == NULL) {
        return;
    }
    free(buf->bytes);
    buf->bytes = NULL;
    buf->length = 0;
    buf->capacity = 0;
    buf->failed = false;
}

bool up_buf_reserve(up_buf *buf, size_t extra) {
    if (buf->failed) {
        return false;
    }
    if (extra > SIZE_MAX - buf->length - 1) {
        buf->failed = true;
        return false;
    }
    size_t needed = buf->length + extra + 1;
    if (needed <= buf->capacity) {
        return true;
    }
    size_t capacity = buf->capacity == 0 ? 256 : buf->capacity;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    char *grown = realloc(buf->bytes, capacity);
    if (grown == NULL) {
        buf->failed = true;
        return false;
    }
    buf->bytes = grown;
    buf->capacity = capacity;
    return true;
}

void up_buf_append(up_buf *buf, const void *bytes, size_t length) {
    if (length == 0 || !up_buf_reserve(buf, length)) {
        return;
    }
    memcpy(buf->bytes + buf->length, bytes, length);
    buf->length += length;
    buf->bytes[buf->length] = '\0';
}

void up_buf_printf(up_buf *buf, const char *format, ...) {
    if (buf->failed) {
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    va_list copy;
    va_copy(copy, arguments);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0 || !up_buf_reserve(buf, (size_t)needed)) {
        va_end(arguments);
        buf->failed = true;
        return;
    }
    vsnprintf(buf->bytes + buf->length, (size_t)needed + 1, format, arguments);
    va_end(arguments);
    buf->length += (size_t)needed;
}

char *up_buf_detach(up_buf *buf, up_context *ctx) {
    if (buf->failed || buf->bytes == NULL) {
        up_buf_free(buf);
        up_fail(ctx, "out of memory while building a report");
        return NULL;
    }
    char *result = buf->bytes;
    buf->bytes = NULL;
    buf->length = 0;
    buf->capacity = 0;
    return result;
}

// MARK: - JSON

static void up_json_escape(up_buf *buf, const char *value, size_t length) {
    size_t start = 0;
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)value[index];
        const char *replacement = NULL;
        char encoded[8];
        switch (byte) {
        case '"':
            replacement = "\\\"";
            break;
        case '\\':
            replacement = "\\\\";
            break;
        case '\b':
            replacement = "\\b";
            break;
        case '\f':
            replacement = "\\f";
            break;
        case '\n':
            replacement = "\\n";
            break;
        case '\r':
            replacement = "\\r";
            break;
        case '\t':
            replacement = "\\t";
            break;
        case '<':
        case '>':
        case '&':
            // Go's encoding/json escapes these by default.
            snprintf(encoded, sizeof(encoded), "\\u%04x", byte);
            replacement = encoded;
            break;
        default:
            if (byte < 0x20) {
                snprintf(encoded, sizeof(encoded), "\\u%04x", byte);
                replacement = encoded;
            }
            break;
        }
        if (replacement == NULL) {
            continue;
        }
        if (index > start) {
            up_buf_append(buf, value + start, index - start);
        }
        up_buf_append(buf, replacement, strlen(replacement));
        start = index + 1;
    }
    if (length > start) {
        up_buf_append(buf, value + start, length - start);
    }
}

void up_json_string_len(up_buf *buf, const char *value, size_t length) {
    up_buf_append(buf, "\"", 1);
    if (value != NULL) {
        up_json_escape(buf, value, length);
    }
    up_buf_append(buf, "\"", 1);
}

void up_json_string(up_buf *buf, const char *value) {
    if (value == NULL) {
        up_buf_append(buf, "null", 4);
        return;
    }
    up_json_string_len(buf, value, strlen(value));
}

void up_json_uint(up_buf *buf, uint64_t value) {
    up_buf_printf(buf, "%llu", (unsigned long long)value);
}

void up_json_int(up_buf *buf, int64_t value) {
    up_buf_printf(buf, "%lld", (long long)value);
}

void up_json_bool(up_buf *buf, bool value) {
    up_buf_append(buf, value ? "true" : "false", value ? 4 : 5);
}

void up_json_key(up_buf *buf, const char *key) {
    up_json_string(buf, key);
    up_buf_append(buf, ":", 1);
}

void up_json_indent(up_buf *buf, int level) {
    up_buf_append(buf, "\n", 1);
    for (int index = 0; index < level; index++) {
        up_buf_append(buf, "  ", 2);
    }
}

// MARK: - Utilities

void up_hex_encode(const uint8_t *bytes, size_t length, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < length; index++) {
        output[index * 2] = digits[bytes[index] >> 4];
        output[index * 2 + 1] = digits[bytes[index] & 0x0f];
    }
    output[length * 2] = '\0';
}
