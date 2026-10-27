//
//  up_zip.h
//  CUnfairPlay
//
//  Minimal ZIP reader/writer covering what the decryption path needs:
//   - EOCD and ZIP64 central-directory parsing over a read-only mapping
//   - raw inflate (method 8) and stored copies (method 0), with CRC checks
//   - prefix reads so a non-Mach-O member is not fully decompressed
//   - writing: unchanged members are copied with their original compressed
//     bytes; rewritten members are deflated again (content equivalent, not
//     byte identical to Go's archive/zip output)
//

#ifndef UP_ZIP_H
#define UP_ZIP_H

#include "up_internal.h"

typedef struct {
    uint16_t version_made_by;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t method;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint64_t local_offset;
    uint16_t internal_attributes;
    uint32_t external_attributes;
    char *name;
    char *comment;
    /// Byte offset of the member data, resolved on first use.
    size_t data_offset;
    bool data_offset_known;
} up_zip_entry;

typedef struct {
    uint8_t *bytes;
    size_t length;
    int descriptor;
    up_zip_entry *entries;
    size_t count;
} up_zip;

bool up_zip_entry_is_directory(const up_zip_entry *entry);

int up_zip_open(up_context *ctx, const char *path, up_zip *out);
void up_zip_close(up_zip *archive);

/// Index of the first entry named `name`, or SIZE_MAX.
size_t up_zip_find(const up_zip *archive, const char *name);

/// Reads the whole member and checks its CRC.
int up_zip_read(up_context *ctx,
                const up_zip *archive,
                const up_zip_entry *entry,
                uint8_t **bytes,
                size_t *length);

/// Reads at most `limit` decompressed bytes. The CRC is not checked because
/// the member is not consumed to the end.
int up_zip_read_prefix(up_context *ctx,
                       const up_zip *archive,
                       const up_zip_entry *entry,
                       size_t limit,
                       uint8_t **bytes,
                       size_t *length);

/// Borrows the original compressed bytes from the mapping.
int up_zip_raw(up_context *ctx,
               const up_zip *archive,
               const up_zip_entry *entry,
               const uint8_t **bytes,
               size_t *length);

typedef struct {
    FILE *file;
    uint64_t offset;
    up_buf central;
    uint64_t entry_count;
    bool zip64_used;
    bool failed;
} up_zip_writer;

int up_zip_writer_open(up_context *ctx, const char *path, up_zip_writer *writer);

/// Copy of the Go `zip.Writer.Copy`: original compressed bytes are preserved.
int up_zip_writer_add_raw(up_context *ctx,
                          up_zip_writer *writer,
                          const up_zip_entry *entry,
                          const uint8_t *raw,
                          size_t raw_length);

/// Equivalent of `CreateHeader` followed by a write: metadata is preserved
/// but the body is compressed again.
int up_zip_writer_add_bytes(up_context *ctx,
                            up_zip_writer *writer,
                            const up_zip_entry *entry,
                            const uint8_t *bytes,
                            size_t length);

int up_zip_writer_finish(up_context *ctx, up_zip_writer *writer);

/// Closes the file without writing the directory. Used when the pipeline
/// aborts before `finish`.
void up_zip_writer_abort(up_zip_writer *writer);

#endif /* UP_ZIP_H */
