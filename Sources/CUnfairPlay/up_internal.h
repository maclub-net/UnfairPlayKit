//
//  up_internal.h
//  CUnfairPlay
//
//  Shared internal helpers. Not part of the public module surface.
//

#ifndef UP_INTERNAL_H
#define UP_INTERNAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unfairplay.h"

struct up_context {
    /// Absolute model directory, or NULL when no model path was supplied.
    char *model_directory;
    /// Most recent failure description, or NULL.
    char *error;
};

/// Replaces the context error with a formatted description and returns 0.
int up_fail(up_context *ctx, const char *format, ...);

/// Growable byte buffer used for JSON serialization.
typedef struct {
    char *bytes;
    size_t length;
    size_t capacity;
    bool failed; ///< Set when an allocation failed; every append becomes a no-op.
} up_buf;

void up_buf_init(up_buf *buf);
void up_buf_free(up_buf *buf);
bool up_buf_reserve(up_buf *buf, size_t extra);
void up_buf_append(up_buf *buf, const void *bytes, size_t length);
void up_buf_printf(up_buf *buf, const char *format, ...) __attribute__((format(printf, 2, 3)));

/// Hands the buffer contents to the caller and resets the buffer. Returns NULL
/// when the buffer failed to grow, in which case the context records the error.
char *up_buf_detach(up_buf *buf, up_context *ctx);

// MARK: - JSON

/// Appends a quoted, escaped JSON string.
void up_json_string(up_buf *buf, const char *value);
/// Appends a quoted, escaped JSON string for a byte range that may not be
/// NUL-terminated, stopping at the first NUL like Go's encoding/json does not.
void up_json_string_len(up_buf *buf, const char *value, size_t length);
void up_json_uint(up_buf *buf, uint64_t value);
void up_json_int(up_buf *buf, int64_t value);
void up_json_bool(up_buf *buf, bool value);

/// Appends `"key":` (including the colon) for the next value.
void up_json_key(up_buf *buf, const char *key);

/// Appends a newline followed by `level` two-space indents, matching
/// `json.MarshalIndent(value, "", "  ")`.
void up_json_indent(up_buf *buf, int level);

// MARK: - Utilities

/// Writes `buffer_length` bytes as lowercase hexadecimal plus a NUL.
/// `output` must hold `buffer_length * 2 + 1` bytes.
void up_hex_encode(const uint8_t *bytes, size_t length, char *output);

#endif /* UP_INTERNAL_H */
