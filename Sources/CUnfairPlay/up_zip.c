//
//  up_zip.c
//  CUnfairPlay
//
//  ZIP support built on the system zlib. The reader maps the archive once and
//  walks the central directory; the writer reproduces the parts of
//  archive/zip the decryptor relies on, including ZIP64.
//

#include "up_zip.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#define UP_ZIP_LOCAL_SIGNATURE UINT32_C(0x04034b50)
#define UP_ZIP_CENTRAL_SIGNATURE UINT32_C(0x02014b50)
#define UP_ZIP_EOCD_SIGNATURE UINT32_C(0x06054b50)
#define UP_ZIP64_EOCD_SIGNATURE UINT32_C(0x06064b50)
#define UP_ZIP64_LOCATOR_SIGNATURE UINT32_C(0x07064b50)
#define UP_ZIP64_EXTRA_ID UINT16_C(0x0001)
#define UP_ZIP_FLAG_DATA_DESCRIPTOR UINT16_C(0x0008)
#define UP_ZIP_MAX64 UINT32_C(0xffffffff)
#define UP_ZIP_EOCD_BYTES 22

static uint16_t up_zip_le16(const uint8_t *bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t up_zip_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t up_zip_le64(const uint8_t *bytes) {
    return (uint64_t)up_zip_le32(bytes) | ((uint64_t)up_zip_le32(bytes + 4) << 32);
}

static void up_zip_put16(uint8_t *bytes, uint16_t value) {
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void up_zip_put32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void up_zip_put64(uint8_t *bytes, uint64_t value) {
    up_zip_put32(bytes, (uint32_t)value);
    up_zip_put32(bytes + 4, (uint32_t)(value >> 32));
}

static char *up_zip_string(const uint8_t *bytes, size_t length) {
    char *result = malloc(length + 1);
    if (result == NULL) {
        return NULL;
    }
    if (length != 0) {
        memcpy(result, bytes, length);
    }
    result[length] = '\0';
    return result;
}

bool up_zip_entry_is_directory(const up_zip_entry *entry) {
    size_t length = strlen(entry->name);
    return length != 0 && entry->name[length - 1] == '/';
}

void up_zip_close(up_zip *archive) {
    if (archive == NULL) {
        return;
    }
    if (archive->bytes != NULL && archive->length != 0) {
        munmap(archive->bytes, archive->length);
    }
    archive->bytes = NULL;
    archive->length = 0;
    if (archive->descriptor >= 0) {
        close(archive->descriptor);
        archive->descriptor = -1;
    }
    for (size_t index = 0; index < archive->count; index++) {
        free(archive->entries[index].name);
        free(archive->entries[index].comment);
    }
    free(archive->entries);
    archive->entries = NULL;
    archive->count = 0;
}

size_t up_zip_find(const up_zip *archive, const char *name) {
    for (size_t index = 0; index < archive->count; index++) {
        if (strcmp(archive->entries[index].name, name) == 0) {
            return index;
        }
    }
    return SIZE_MAX;
}

// MARK: - Reader

/// Scans the central directory extra field for ZIP64 sizes and local offset.
static bool up_zip_parse_zip64_extra(const uint8_t *extra,
                                     size_t extra_length,
                                     uint64_t *uncompressed,
                                     uint64_t *compressed,
                                     uint64_t *local_offset) {
    size_t cursor = 0;
    while (cursor + 4 <= extra_length) {
        uint16_t identifier = up_zip_le16(extra + cursor);
        uint16_t size = up_zip_le16(extra + cursor + 2);
        size_t start = cursor + 4;
        if (start + size > extra_length) {
            return false;
        }
        if (identifier == UP_ZIP64_EXTRA_ID) {
            size_t field = start;
            if (*uncompressed == UP_ZIP_MAX64) {
                if (field + 8 > start + size) {
                    return false;
                }
                *uncompressed = up_zip_le64(extra + field);
                field += 8;
            }
            if (*compressed == UP_ZIP_MAX64) {
                if (field + 8 > start + size) {
                    return false;
                }
                *compressed = up_zip_le64(extra + field);
                field += 8;
            }
            if (*local_offset == UP_ZIP_MAX64) {
                if (field + 8 > start + size) {
                    return false;
                }
                *local_offset = up_zip_le64(extra + field);
            }
            return true;
        }
        cursor = start + size;
    }
    return false;
}

/// Locates the end-of-central-directory record, including ZIP64.
static int up_zip_locate_directory(up_context *ctx,
                                   const uint8_t *bytes,
                                   size_t length,
                                   uint64_t *directory_offset,
                                   uint64_t *directory_size,
                                   uint64_t *entry_count) {
    if (length < UP_ZIP_EOCD_BYTES) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    size_t limit = length > (size_t)(UP_ZIP_EOCD_BYTES + 65535) ? length - UP_ZIP_EOCD_BYTES - 65535 : 0;
    size_t cursor = length - UP_ZIP_EOCD_BYTES;
    bool found = false;
    while (true) {
        if (up_zip_le32(bytes + cursor) == UP_ZIP_EOCD_SIGNATURE) {
            uint16_t comment_length = up_zip_le16(bytes + cursor + 20);
            if (cursor + UP_ZIP_EOCD_BYTES + comment_length <= length) {
                found = true;
                break;
            }
        }
        if (cursor == limit) {
            break;
        }
        cursor--;
    }
    if (!found) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    uint64_t count = up_zip_le16(bytes + cursor + 10);
    uint64_t size = up_zip_le32(bytes + cursor + 12);
    uint64_t offset = up_zip_le32(bytes + cursor + 16);
    if (count == 0xffff || size == UP_ZIP_MAX64 || offset == UP_ZIP_MAX64) {
        if (cursor < 20) {
            return up_fail(ctx, "zip: not a valid zip file");
        }
        const uint8_t *locator = bytes + cursor - 20;
        if (up_zip_le32(locator) != UP_ZIP64_LOCATOR_SIGNATURE) {
            return up_fail(ctx, "zip: not a valid zip file");
        }
        uint64_t zip64_offset = up_zip_le64(locator + 8);
        if (zip64_offset > length || length - (size_t)zip64_offset < 56) {
            return up_fail(ctx, "zip: not a valid zip file");
        }
        const uint8_t *record = bytes + zip64_offset;
        if (up_zip_le32(record) != UP_ZIP64_EOCD_SIGNATURE) {
            return up_fail(ctx, "zip: not a valid zip file");
        }
        count = up_zip_le64(record + 32);
        size = up_zip_le64(record + 40);
        offset = up_zip_le64(record + 48);
    }
    if (offset > length || size > length - offset) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    *directory_offset = offset;
    *directory_size = size;
    *entry_count = count;
    return 1;
}

static int up_zip_parse_entries(up_context *ctx,
                                const uint8_t *bytes,
                                size_t length,
                                uint64_t directory_offset,
                                uint64_t directory_size,
                                uint64_t entry_count,
                                up_zip_entry **entries_out,
                                size_t *count_out) {
    if (entry_count > 1000000) {
        return up_fail(ctx, "zip: central directory is too large");
    }
    up_zip_entry *entries = calloc(entry_count == 0 ? 1 : (size_t)entry_count, sizeof(up_zip_entry));
    if (entries == NULL) {
        return up_fail(ctx, "out of memory");
    }
    size_t parsed = 0;
    uint64_t cursor = directory_offset;
    uint64_t end = directory_offset + directory_size;
    int status = 1;
    while (parsed < entry_count && cursor < end) {
        if (cursor + 46 > end || cursor + 46 > length) {
            status = up_fail(ctx, "zip: not a valid zip file");
            break;
        }
        const uint8_t *record = bytes + cursor;
        if (up_zip_le32(record) != UP_ZIP_CENTRAL_SIGNATURE) {
            status = up_fail(ctx, "zip: not a valid zip file");
            break;
        }
        uint16_t name_length = up_zip_le16(record + 28);
        uint16_t extra_length = up_zip_le16(record + 30);
        uint16_t comment_length = up_zip_le16(record + 32);
        uint64_t record_length = 46 + (uint64_t)name_length + extra_length + comment_length;
        if (cursor + record_length > end || cursor + record_length > length) {
            status = up_fail(ctx, "zip: not a valid zip file");
            break;
        }
        up_zip_entry entry;
        memset(&entry, 0, sizeof(entry));
        entry.version_made_by = up_zip_le16(record + 4);
        entry.version_needed = up_zip_le16(record + 6);
        entry.flags = up_zip_le16(record + 8);
        entry.method = up_zip_le16(record + 10);
        entry.mod_time = up_zip_le16(record + 12);
        entry.mod_date = up_zip_le16(record + 14);
        entry.crc32 = up_zip_le32(record + 16);
        entry.compressed_size = up_zip_le32(record + 20);
        entry.uncompressed_size = up_zip_le32(record + 24);
        entry.internal_attributes = up_zip_le16(record + 36);
        entry.external_attributes = up_zip_le32(record + 38);
        entry.local_offset = up_zip_le32(record + 42);
        const uint8_t *name = record + 46;
        const uint8_t *extra = name + name_length;
        const uint8_t *comment = extra + extra_length;
        if (entry.compressed_size == UP_ZIP_MAX64 || entry.uncompressed_size == UP_ZIP_MAX64 ||
            entry.local_offset == UP_ZIP_MAX64) {
            if (!up_zip_parse_zip64_extra(extra, extra_length, &entry.uncompressed_size,
                                          &entry.compressed_size, &entry.local_offset)) {
                status = up_fail(ctx, "zip: not a valid zip file");
                break;
            }
        }
        entry.name = up_zip_string(name, name_length);
        entry.comment = up_zip_string(comment, comment_length);
        if (entry.name == NULL || entry.comment == NULL) {
            free(entry.name);
            free(entry.comment);
            status = up_fail(ctx, "out of memory");
            break;
        }
        entries[parsed++] = entry;
        cursor += record_length;
    }
    if (status && parsed != entry_count) {
        status = up_fail(ctx, "zip: not a valid zip file");
    }
    if (!status) {
        for (size_t index = 0; index < parsed; index++) {
            free(entries[index].name);
            free(entries[index].comment);
        }
        free(entries);
        return 0;
    }
    *entries_out = entries;
    *count_out = parsed;
    return 1;
}

int up_zip_open(up_context *ctx, const char *path, up_zip *out) {
    memset(out, 0, sizeof(*out));
    out->descriptor = -1;
    int descriptor = open(path, O_RDONLY);
    if (descriptor < 0) {
        return up_fail(ctx, "zip: open %s: %s", path, strerror(errno));
    }
    struct stat info;
    if (fstat(descriptor, &info) != 0) {
        int error = errno;
        close(descriptor);
        return up_fail(ctx, "zip: inspect %s: %s", path, strerror(error));
    }
    if (!S_ISREG(info.st_mode) || info.st_size <= 0) {
        close(descriptor);
        return up_fail(ctx, "zip: not a valid zip file");
    }
    size_t length = (size_t)info.st_size;
    void *mapping = mmap(NULL, length, PROT_READ, MAP_PRIVATE, descriptor, 0);
    if (mapping == MAP_FAILED) {
        int error = errno;
        close(descriptor);
        return up_fail(ctx, "zip: map %s: %s", path, strerror(error));
    }
    out->descriptor = descriptor;
    out->bytes = mapping;
    out->length = length;
    uint64_t directory_offset = 0;
    uint64_t directory_size = 0;
    uint64_t entry_count = 0;
    if (!up_zip_locate_directory(ctx, out->bytes, out->length, &directory_offset, &directory_size,
                                 &entry_count)) {
        up_zip_close(out);
        return 0;
    }
    if (!up_zip_parse_entries(ctx, out->bytes, out->length, directory_offset, directory_size,
                              entry_count, &out->entries, &out->count)) {
        up_zip_close(out);
        return 0;
    }
    return 1;
}

static int up_zip_data_offset(up_context *ctx, const up_zip *archive, const up_zip_entry *entry) {
    if (entry->data_offset_known) {
        return 1;
    }
    up_zip_entry *mutable_entry = (up_zip_entry *)entry;
    if (entry->local_offset > archive->length || archive->length - (size_t)entry->local_offset < 30) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    const uint8_t *header = archive->bytes + entry->local_offset;
    if (up_zip_le32(header) != UP_ZIP_LOCAL_SIGNATURE) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    uint16_t name_length = up_zip_le16(header + 26);
    uint16_t extra_length = up_zip_le16(header + 28);
    uint64_t offset = entry->local_offset + 30 + (uint64_t)name_length + extra_length;
    if (offset > archive->length) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    mutable_entry->data_offset = (size_t)offset;
    mutable_entry->data_offset_known = true;
    return 1;
}

static uint32_t up_zip_crc(const uint8_t *bytes, size_t length) {
    uLong crc = crc32(0L, Z_NULL, 0);
    size_t cursor = 0;
    while (cursor < length) {
        size_t chunk = length - cursor;
        if (chunk > UINT32_MAX) {
            chunk = UINT32_MAX;
        }
        crc = crc32(crc, bytes + cursor, (uInt)chunk);
        cursor += chunk;
    }
    return (uint32_t)crc;
}

/// Shared body reader. `full` selects trusted, CRC-checked reads; otherwise at
/// most `limit` bytes are produced.
static int up_zip_body(up_context *ctx,
                       const up_zip *archive,
                       const up_zip_entry *entry,
                       size_t limit,
                       bool full,
                       uint8_t **bytes_out,
                       size_t *length_out) {
    *bytes_out = NULL;
    *length_out = 0;
    if (entry->method != 0 && entry->method != 8) {
        return up_fail(ctx, "zip: unsupported compression method %u for %s", (unsigned)entry->method,
                       entry->name);
    }
    if (!up_zip_data_offset(ctx, archive, entry)) {
        return 0;
    }
    if (entry->compressed_size > archive->length ||
        entry->data_offset > archive->length - (size_t)entry->compressed_size) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    const uint8_t *raw = archive->bytes + entry->data_offset;
    size_t raw_length = (size_t)entry->compressed_size;

    size_t capacity;
    if (full) {
        capacity = (size_t)entry->uncompressed_size;
    } else {
        capacity = entry->uncompressed_size < (uint64_t)limit ? (size_t)entry->uncompressed_size
                                                              : limit;
    }
    if (entry->method == 0) {
        size_t available = raw_length;
        size_t produced = capacity < available ? capacity : available;
        uint8_t *copy = malloc(produced == 0 ? 1 : produced);
        if (copy == NULL) {
            return up_fail(ctx, "out of memory");
        }
        memcpy(copy, raw, produced);
        if (full && up_zip_crc(copy, produced) != entry->crc32) {
            free(copy);
            return up_fail(ctx, "zip: checksum error");
        }
        *bytes_out = copy;
        *length_out = produced;
        return 1;
    }

    uint8_t *output = malloc(capacity == 0 ? 1 : capacity);
    if (output == NULL) {
        return up_fail(ctx, "out of memory");
    }
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, -15) != Z_OK) {
        free(output);
        return up_fail(ctx, "zip: inflate initialization failed");
    }
    stream.next_in = (Bytef *)raw;
    stream.avail_in = 0;
    size_t consumed = 0;
    size_t produced = 0;
    int status = Z_OK;
    while (status != Z_STREAM_END && produced < capacity) {
        if (stream.avail_in == 0 && consumed < raw_length) {
            size_t chunk = raw_length - consumed;
            if (chunk > UINT32_MAX) {
                chunk = UINT32_MAX;
            }
            stream.next_in = (Bytef *)(raw + consumed);
            stream.avail_in = (uInt)chunk;
            consumed += chunk;
        }
        size_t remaining = capacity - produced;
        if (remaining > UINT32_MAX) {
            remaining = UINT32_MAX;
        }
        stream.next_out = (Bytef *)(output + produced);
        stream.avail_out = (uInt)remaining;
        status = inflate(&stream, Z_NO_FLUSH);
        produced += remaining - stream.avail_out;
        if (status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR) {
            inflateEnd(&stream);
            free(output);
            return up_fail(ctx, "zip: corrupt deflate stream");
        }
        if (status == Z_BUF_ERROR && stream.avail_in == 0 && consumed == raw_length &&
            stream.avail_out != 0) {
            inflateEnd(&stream);
            free(output);
            return up_fail(ctx, "zip: corrupt deflate stream");
        }
    }
    inflateEnd(&stream);
    if (full) {
        if (status != Z_STREAM_END) {
            free(output);
            return up_fail(ctx, "zip: corrupt deflate stream");
        }
        if (produced != (size_t)entry->uncompressed_size) {
            free(output);
            return up_fail(ctx, "zip: checksum error");
        }
        if (up_zip_crc(output, produced) != entry->crc32) {
            free(output);
            return up_fail(ctx, "zip: checksum error");
        }
    }
    *bytes_out = output;
    *length_out = produced;
    return 1;
}

int up_zip_read(up_context *ctx,
                const up_zip *archive,
                const up_zip_entry *entry,
                uint8_t **bytes,
                size_t *length) {
    return up_zip_body(ctx, archive, entry, 0, true, bytes, length);
}

int up_zip_read_prefix(up_context *ctx,
                       const up_zip *archive,
                       const up_zip_entry *entry,
                       size_t limit,
                       uint8_t **bytes,
                       size_t *length) {
    return up_zip_body(ctx, archive, entry, limit, false, bytes, length);
}

int up_zip_raw(up_context *ctx,
               const up_zip *archive,
               const up_zip_entry *entry,
               const uint8_t **bytes,
               size_t *length) {
    if (!up_zip_data_offset(ctx, archive, entry)) {
        return 0;
    }
    if (entry->compressed_size > archive->length ||
        entry->data_offset > archive->length - (size_t)entry->compressed_size) {
        return up_fail(ctx, "zip: not a valid zip file");
    }
    *bytes = archive->bytes + entry->data_offset;
    *length = (size_t)entry->compressed_size;
    return 1;
}

// MARK: - Writer

static bool up_zip_write(up_zip_writer *writer, const void *bytes, size_t length) {
    if (writer->failed) {
        return false;
    }
    if (length != 0 && fwrite(bytes, 1, length, writer->file) != length) {
        writer->failed = true;
        return false;
    }
    writer->offset += length;
    return true;
}

int up_zip_writer_open(up_context *ctx, const char *path, up_zip_writer *writer) {
    memset(writer, 0, sizeof(*writer));
    up_buf_init(&writer->central);
    writer->file = fopen(path, "wb");
    if (writer->file == NULL) {
        return up_fail(ctx, "zip: create %s: %s", path, strerror(errno));
    }
    return 1;
}

static void up_zip_writer_emit_zip64_extra(up_buf *buffer,
                                           uint64_t uncompressed,
                                           uint64_t compressed,
                                           uint64_t local_offset,
                                           bool include_sizes,
                                           bool include_offset) {
    size_t fields = (include_sizes ? 2 : 0) + (include_offset ? 1 : 0);
    uint8_t header[4];
    up_zip_put16(header, UP_ZIP64_EXTRA_ID);
    up_zip_put16(header + 2, (uint16_t)(fields * 8));
    up_buf_append(buffer, header, 4);
    uint8_t value[8];
    if (include_sizes) {
        up_zip_put64(value, uncompressed);
        up_buf_append(buffer, value, 8);
        up_zip_put64(value, compressed);
        up_buf_append(buffer, value, 8);
    }
    if (include_offset) {
        up_zip_put64(value, local_offset);
        up_buf_append(buffer, value, 8);
    }
}

static int up_zip_writer_record(up_context *ctx,
                                up_zip_writer *writer,
                                const up_zip_entry *entry,
                                uint16_t method,
                                uint32_t crc,
                                uint64_t uncompressed,
                                uint64_t compressed,
                                uint64_t local_offset,
                                const uint8_t *raw,
                                size_t raw_length) {
    bool zip64_sizes = uncompressed > UP_ZIP_MAX64 || compressed > UP_ZIP_MAX64;
    bool zip64_offset = local_offset > UP_ZIP_MAX64;
    if (zip64_sizes || zip64_offset) {
        writer->zip64_used = true;
    }

    uint8_t local[30];
    memset(local, 0, sizeof(local));
    up_zip_put32(local, UP_ZIP_LOCAL_SIGNATURE);
    uint16_t version_needed = entry->version_needed < 20 ? 20 : entry->version_needed;
    if (zip64_sizes) {
        version_needed = 45;
    }
    up_zip_put16(local + 4, version_needed);
    up_zip_put16(local + 6, (uint16_t)(entry->flags & ~UP_ZIP_FLAG_DATA_DESCRIPTOR));
    up_zip_put16(local + 8, method);
    up_zip_put16(local + 10, entry->mod_time);
    up_zip_put16(local + 12, entry->mod_date);
    up_zip_put32(local + 14, crc);
    up_zip_put32(local + 18, zip64_sizes ? UP_ZIP_MAX64 : (uint32_t)compressed);
    up_zip_put32(local + 22, zip64_sizes ? UP_ZIP_MAX64 : (uint32_t)uncompressed);
    up_zip_put16(local + 26, (uint16_t)strlen(entry->name));
    up_zip_put16(local + 28, zip64_sizes ? 20 : 0);
    if (!up_zip_write(writer, local, sizeof(local)) ||
        !up_zip_write(writer, entry->name, strlen(entry->name))) {
        return up_fail(ctx, "zip: write failed");
    }
    if (zip64_sizes) {
        up_buf extra;
        up_buf_init(&extra);
        up_zip_writer_emit_zip64_extra(&extra, uncompressed, compressed, 0, true, false);
        bool written = up_zip_write(writer, extra.bytes, extra.length);
        up_buf_free(&extra);
        if (!written) {
            return up_fail(ctx, "zip: write failed");
        }
    }
    if (!up_zip_write(writer, raw, raw_length)) {
        return up_fail(ctx, "zip: write failed");
    }

    uint8_t record[46];
    memset(record, 0, sizeof(record));
    up_zip_put32(record, UP_ZIP_CENTRAL_SIGNATURE);
    up_zip_put16(record + 4, entry->version_made_by == 0 ? (uint16_t)20 : entry->version_made_by);
    up_zip_put16(record + 6, version_needed);
    up_zip_put16(record + 8, (uint16_t)(entry->flags & ~UP_ZIP_FLAG_DATA_DESCRIPTOR));
    up_zip_put16(record + 10, method);
    up_zip_put16(record + 12, entry->mod_time);
    up_zip_put16(record + 14, entry->mod_date);
    up_zip_put32(record + 16, crc);
    up_zip_put32(record + 20, zip64_sizes ? UP_ZIP_MAX64 : (uint32_t)compressed);
    up_zip_put32(record + 24, zip64_sizes ? UP_ZIP_MAX64 : (uint32_t)uncompressed);
    uint16_t name_length = (uint16_t)strlen(entry->name);
    uint16_t comment_length = (uint16_t)(entry->comment == NULL ? 0 : strlen(entry->comment));
    up_zip_put16(record + 28, name_length);
    up_zip_put16(record + 32, comment_length);
    up_zip_put16(record + 34, 0);
    up_zip_put16(record + 36, entry->internal_attributes);
    up_zip_put32(record + 38, entry->external_attributes);
    up_zip_put32(record + 42, zip64_offset ? UP_ZIP_MAX64 : (uint32_t)local_offset);

    up_buf extra;
    up_buf_init(&extra);
    if (zip64_sizes || zip64_offset) {
        up_zip_writer_emit_zip64_extra(&extra, uncompressed, compressed, local_offset, zip64_sizes,
                                       zip64_offset);
    }
    up_zip_put16(record + 30, (uint16_t)extra.length);
    up_buf_append(&writer->central, record, sizeof(record));
    up_buf_append(&writer->central, entry->name, name_length);
    up_buf_append(&writer->central, extra.bytes, extra.length);
    if (comment_length != 0) {
        up_buf_append(&writer->central, entry->comment, comment_length);
    }
    up_buf_free(&extra);
    if (writer->central.failed) {
        return up_fail(ctx, "out of memory while building the ZIP directory");
    }
    writer->entry_count++;
    return 1;
}

int up_zip_writer_add_raw(up_context *ctx,
                          up_zip_writer *writer,
                          const up_zip_entry *entry,
                          const uint8_t *raw,
                          size_t raw_length) {
    if (raw_length != (size_t)entry->compressed_size) {
        return up_fail(ctx, "zip: compressed extent changed");
    }
    return up_zip_writer_record(ctx, writer, entry, entry->method, entry->crc32,
                                entry->uncompressed_size, entry->compressed_size, writer->offset,
                                raw, raw_length);
}

/// Compresses `bytes` into a single raw deflate stream.
static int up_zip_deflate(up_context *ctx,
                          const uint8_t *bytes,
                          size_t length,
                          uint8_t **output,
                          size_t *output_length) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) !=
        Z_OK) {
        return up_fail(ctx, "zip: deflate initialization failed");
    }
    up_buf buffer;
    up_buf_init(&buffer);
    size_t consumed = 0;
    int status = Z_OK;
    uint8_t chunk[16384];
    while (status != Z_STREAM_END) {
        if (stream.avail_in == 0 && consumed < length) {
            size_t part = length - consumed;
            if (part > UINT32_MAX) {
                part = UINT32_MAX;
            }
            stream.next_in = (Bytef *)(bytes + consumed);
            stream.avail_in = (uInt)part;
            consumed += part;
        }
        stream.next_out = chunk;
        stream.avail_out = sizeof(chunk);
        status = deflate(&stream, consumed == length ? Z_FINISH : Z_NO_FLUSH);
        if (status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR) {
            deflateEnd(&stream);
            up_buf_free(&buffer);
            return up_fail(ctx, "zip: deflate failed");
        }
        size_t produced = sizeof(chunk) - stream.avail_out;
        up_buf_append(&buffer, chunk, produced);
        if (buffer.failed) {
            deflateEnd(&stream);
            up_buf_free(&buffer);
            return up_fail(ctx, "out of memory");
        }
        if (status == Z_BUF_ERROR && consumed == length && produced == 0) {
            deflateEnd(&stream);
            up_buf_free(&buffer);
            return up_fail(ctx, "zip: deflate failed");
        }
    }
    deflateEnd(&stream);
    uint8_t *result = malloc(buffer.length == 0 ? 1 : buffer.length);
    if (result == NULL) {
        up_buf_free(&buffer);
        return up_fail(ctx, "out of memory");
    }
    if (buffer.length != 0) {
        memcpy(result, buffer.bytes, buffer.length);
    }
    *output = result;
    *output_length = buffer.length;
    up_buf_free(&buffer);
    return 1;
}

int up_zip_writer_add_bytes(up_context *ctx,
                            up_zip_writer *writer,
                            const up_zip_entry *entry,
                            const uint8_t *bytes,
                            size_t length) {
    uint32_t crc = up_zip_crc(bytes, length);
    if (entry->method == 0) {
        return up_zip_writer_record(ctx, writer, entry, 0, crc, length, length, writer->offset,
                                    bytes, length);
    }
    if (entry->method != 8) {
        return up_fail(ctx, "zip: unsupported compression method %u for %s",
                       (unsigned)entry->method, entry->name);
    }
    uint8_t *compressed = NULL;
    size_t compressed_length = 0;
    if (!up_zip_deflate(ctx, bytes, length, &compressed, &compressed_length)) {
        return 0;
    }
    int status = up_zip_writer_record(ctx, writer, entry, 8, crc, length, compressed_length,
                                      writer->offset, compressed, compressed_length);
    free(compressed);
    return status;
}

void up_zip_writer_abort(up_zip_writer *writer) {
    if (writer == NULL) {
        return;
    }
    if (writer->file != NULL) {
        fclose(writer->file);
        writer->file = NULL;
    }
    up_buf_free(&writer->central);
}

int up_zip_writer_finish(up_context *ctx, up_zip_writer *writer) {
    if (writer->file == NULL) {
        return up_fail(ctx, "zip: writer is closed");
    }
    if (writer->failed) {
        fclose(writer->file);
        writer->file = NULL;
        return up_fail(ctx, "zip: write failed");
    }
    uint64_t central_offset = writer->offset;
    uint64_t central_size = writer->central.length;
    if (!up_zip_write(writer, writer->central.bytes, writer->central.length) || writer->failed) {
        fclose(writer->file);
        writer->file = NULL;
        return up_fail(ctx, "zip: write failed");
    }
    bool zip64 = writer->zip64_used || writer->entry_count >= 0xffff ||
                 central_size > UP_ZIP_MAX64 || central_offset > UP_ZIP_MAX64;
    uint8_t buffer[56];
    if (zip64) {
        uint64_t zip64_offset = writer->offset;
        memset(buffer, 0, 56);
        up_zip_put32(buffer, UP_ZIP64_EOCD_SIGNATURE);
        up_zip_put64(buffer + 4, 44);
        up_zip_put16(buffer + 12, 45);
        up_zip_put16(buffer + 14, 45);
        up_zip_put64(buffer + 24, writer->entry_count);
        up_zip_put64(buffer + 32, writer->entry_count);
        up_zip_put64(buffer + 40, central_size);
        up_zip_put64(buffer + 48, central_offset);
        if (!up_zip_write(writer, buffer, 56)) {
            fclose(writer->file);
            writer->file = NULL;
            return up_fail(ctx, "zip: write failed");
        }
        memset(buffer, 0, 20);
        up_zip_put32(buffer, UP_ZIP64_LOCATOR_SIGNATURE);
        up_zip_put64(buffer + 8, zip64_offset);
        up_zip_put32(buffer + 16, 1);
        if (!up_zip_write(writer, buffer, 20)) {
            fclose(writer->file);
            writer->file = NULL;
            return up_fail(ctx, "zip: write failed");
        }
    }
    memset(buffer, 0, UP_ZIP_EOCD_BYTES);
    up_zip_put32(buffer, UP_ZIP_EOCD_SIGNATURE);
    uint16_t count = writer->entry_count >= 0xffff ? 0xffff : (uint16_t)writer->entry_count;
    up_zip_put16(buffer + 8, count);
    up_zip_put16(buffer + 10, count);
    up_zip_put32(buffer + 12, zip64 ? UP_ZIP_MAX64 : (uint32_t)central_size);
    up_zip_put32(buffer + 16, zip64 ? UP_ZIP_MAX64 : (uint32_t)central_offset);
    bool written = up_zip_write(writer, buffer, UP_ZIP_EOCD_BYTES) && !writer->failed;
    int sync_error = 0;
    if (written && fflush(writer->file) != 0) {
        sync_error = errno;
        written = false;
    }
    if (fclose(writer->file) != 0 && written) {
        sync_error = errno;
        written = false;
    }
    writer->file = NULL;
    up_buf_free(&writer->central);
    if (!written) {
        return up_fail(ctx, "zip: finish failed: %s", strerror(sync_error != 0 ? sync_error : EIO));
    }
    return 1;
}
