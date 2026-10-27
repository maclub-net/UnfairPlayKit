//
//  up_macho.c
//  CUnfairPlay
//
//  Direct port of internal/fairplay/macho.go. Bounds checks are kept in the
//  same order as the Go source so the failure messages and the accept/reject
//  decisions stay identical.
//

#include "up_macho.h"

#include "up_crypto.h"

#define UP_MH_MAGIC32 UINT32_C(0xfeedface)
#define UP_MH_MAGIC64 UINT32_C(0xfeedfacf)
#define UP_MH_CIGAM32 UINT32_C(0xcefaedfe)
#define UP_MH_CIGAM64 UINT32_C(0xcffaedfe)
#define UP_FAT_MAGIC UINT32_C(0xcafebabe)
#define UP_FAT_CIGAM UINT32_C(0xbebafeca)
#define UP_FAT_MAGIC64 UINT32_C(0xcafebabf)
#define UP_FAT_CIGAM64 UINT32_C(0xbfbafeca)
#define UP_CPU_TYPE_ARM UINT32_C(0x0000000c)
#define UP_CPU_TYPE_ARM64 UINT32_C(0x0100000c)
#define UP_CPU_TYPE_ARM64_32 UINT32_C(0x0200000c)
#define UP_LC_CODE_SIGNATURE 0x1d
#define UP_LC_SEGMENT 0x01
#define UP_LC_SEGMENT64 0x19
#define UP_LC_ENCRYPTION_INFO 0x21
#define UP_LC_ENCRYPTION_INFO64 0x2c
#define UP_SECTION_ATTR_PURE_INSTRUCTIONS UINT32_C(0x80000000)
#define UP_SECTION_ATTR_SOME_INSTRUCTIONS UINT32_C(0x00000400)
#define UP_CS_MAGIC_EMBEDDED_SIGNATURE UINT32_C(0xfade0cc0)
#define UP_CS_MAGIC_CODEDIRECTORY UINT32_C(0xfade0c02)

static uint32_t up_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint32_t up_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static uint64_t up_le64(const uint8_t *bytes) {
    return (uint64_t)up_le32(bytes) | ((uint64_t)up_le32(bytes + 4) << 32);
}

static uint64_t up_be64(const uint8_t *bytes) {
    return ((uint64_t)up_be32(bytes) << 32) | (uint64_t)up_be32(bytes + 4);
}

static void up_macho_name(const uint8_t *value, size_t length, char output[17]) {
    size_t count = 0;
    while (count < length && value[count] != 0) {
        count++;
    }
    if (count > 16) {
        count = 16;
    }
    memcpy(output, value, count);
    output[count] = '\0';
}

void up_macho_layout_free(up_macho_layout *layout) {
    if (layout == NULL) {
        return;
    }
    free(layout->ranges);
    layout->ranges = NULL;
    layout->range_count = 0;
}

void up_macho_architecture(uint32_t cpu_type, uint32_t cpu_subtype, char output[32]) {
    switch (cpu_type) {
    case UP_CPU_TYPE_ARM:
        switch (cpu_subtype & 0xff) {
        case 6:
            snprintf(output, 32, "armv6");
            return;
        case 9:
            snprintf(output, 32, "armv7");
            return;
        case 10:
            snprintf(output, 32, "armv7f");
            return;
        case 11:
            snprintf(output, 32, "armv7s");
            return;
        case 12:
            snprintf(output, 32, "armv7k");
            return;
        case 13:
            snprintf(output, 32, "armv8");
            return;
        default:
            snprintf(output, 32, "arm");
            return;
        }
    case UP_CPU_TYPE_ARM64:
        snprintf(output, 32, "%s", (cpu_subtype & 0xff) == 2 ? "arm64e" : "arm64");
        return;
    case UP_CPU_TYPE_ARM64_32:
        snprintf(output, 32, "arm64_32");
        return;
    default:
        snprintf(output, 32, "cpu-%#x", (unsigned)cpu_type);
        return;
    }
}

bool up_is_arm64_instruction_set(uint32_t cpu_type) {
    return cpu_type == UP_CPU_TYPE_ARM64 || cpu_type == UP_CPU_TYPE_ARM64_32;
}

static bool up_is_fat_macho(const uint8_t *blob, size_t length) {
    if (length < 4) {
        return false;
    }
    uint32_t magic = up_be32(blob);
    return magic == UP_FAT_MAGIC || magic == UP_FAT_CIGAM || magic == UP_FAT_MAGIC64 ||
           magic == UP_FAT_CIGAM64;
}

static int up_append_range(up_macho_layout *layout, up_macho_range range) {
    up_macho_range *grown =
        realloc(layout->ranges, (layout->range_count + 1) * sizeof(up_macho_range));
    if (grown == NULL) {
        return 0;
    }
    layout->ranges = grown;
    layout->ranges[layout->range_count++] = range;
    return 1;
}

static int up_parse_thin_macho(up_context *ctx,
                               const uint8_t *blob,
                               size_t blob_length,
                               uint64_t total_size,
                               up_macho_layout *result) {
    memset(result, 0, sizeof(*result));
    if (blob_length < 4) {
        return up_fail(ctx, "Mach-O header is truncated");
    }
    int header_size = 0;
    switch (up_le32(blob)) {
    case UP_MH_MAGIC32:
        header_size = 28;
        break;
    case UP_MH_MAGIC64:
        header_size = 32;
        break;
    default:
        return up_fail(ctx, "expected thin little-endian Mach-O");
    }
    if (blob_length < (size_t)header_size || total_size < (uint64_t)header_size) {
        return up_fail(ctx, "Mach-O header is truncated");
    }
    result->cpu_type = up_le32(blob + 4);
    result->cpu_subtype = up_le32(blob + 8);
    uint64_t command_count = up_le32(blob + 16);
    uint64_t commands_size = up_le32(blob + 20);
    uint64_t commands_end = (uint64_t)header_size + commands_size;
    if (commands_end < (uint64_t)header_size || commands_end > (uint64_t)blob_length ||
        commands_end > total_size) {
        return up_fail(ctx, "Mach-O load commands are truncated");
    }
    if (command_count > commands_size / 8) {
        return up_fail(ctx, "Mach-O load-command count is invalid");
    }
    uint64_t cursor = (uint64_t)header_size;
    bool encryption = false;
    bool signature = false;
    for (uint64_t index = 0; index < command_count; index++) {
        if (cursor + 8 > commands_end) {
            return up_fail(ctx, "Mach-O load command header is truncated");
        }
        uint32_t command = up_le32(blob + cursor);
        uint64_t size = up_le32(blob + cursor + 4);
        if (size < 8 || cursor + size > commands_end) {
            return up_fail(ctx, "Mach-O load command has invalid size");
        }
        if (command == UP_LC_SEGMENT || command == UP_LC_SEGMENT64) {
            uint64_t segment_header_size = 56, section_size = 68, section_count_offset = 48;
            uint64_t section_file_offset = 40, section_byte_size = 36, section_flags_offset = 56;
            if (command == UP_LC_SEGMENT64) {
                segment_header_size = 72;
                section_size = 80;
                section_count_offset = 64;
                section_file_offset = 48;
                section_byte_size = 40;
                section_flags_offset = 64;
            }
            if (size < segment_header_size) {
                return up_fail(ctx, "Mach-O segment command is truncated");
            }
            uint64_t section_count = up_le32(blob + cursor + section_count_offset);
            if (section_count > (size - segment_header_size) / section_size ||
                segment_header_size + section_count * section_size != size) {
                return up_fail(ctx, "Mach-O segment section table is invalid");
            }
            for (uint64_t section_index = 0; section_index < section_count; section_index++) {
                const uint8_t *section =
                    blob + cursor + segment_header_size + section_index * section_size;
                uint32_t flags = up_le32(section + section_flags_offset);
                if ((flags & (UP_SECTION_ATTR_PURE_INSTRUCTIONS |
                              UP_SECTION_ATTR_SOME_INSTRUCTIONS)) == 0) {
                    continue;
                }
                uint64_t offset = up_le32(section + section_file_offset);
                uint64_t section_bytes = command == UP_LC_SEGMENT64
                                             ? up_le64(section + section_byte_size)
                                             : up_le32(section + section_byte_size);
                if (section_bytes == 0) {
                    continue;
                }
                if (offset > total_size || section_bytes > total_size - offset) {
                    up_fail(ctx, "Mach-O instruction section exceeds file");
                    up_macho_layout_free(result);
                    return 0;
                }
                up_macho_range candidate;
                memset(&candidate, 0, sizeof(candidate));
                candidate.offset = offset;
                candidate.size = section_bytes;
                candidate.flags = flags;
                up_macho_name(section, 16, candidate.section);
                up_macho_name(section + 16, 16, candidate.segment);
                for (size_t previous = 0; previous < result->range_count; previous++) {
                    up_macho_range *earlier = &result->ranges[previous];
                    if (candidate.offset < earlier->offset + earlier->size &&
                        earlier->offset < candidate.offset + candidate.size) {
                        up_fail(ctx, "Mach-O instruction sections overlap");
                        up_macho_layout_free(result);
                        return 0;
                    }
                }
                if (!up_append_range(result, candidate)) {
                    up_fail(ctx, "out of memory");
                    up_macho_layout_free(result);
                    return 0;
                }
            }
        } else if (command == UP_LC_ENCRYPTION_INFO || command == UP_LC_ENCRYPTION_INFO64) {
            uint64_t minimum = command == UP_LC_ENCRYPTION_INFO64 ? 24 : 20;
            if (size < minimum || encryption) {
                up_fail(ctx, "Mach-O encryption command is invalid");
                up_macho_layout_free(result);
                return 0;
            }
            result->crypt_offset = up_le32(blob + cursor + 8);
            result->crypt_size = up_le32(blob + cursor + 12);
            result->crypt_id = up_le32(blob + cursor + 16);
            result->crypt_id_offset = (int)(cursor + 16);
            encryption = true;
        } else if (command == UP_LC_CODE_SIGNATURE) {
            if (size < 16 || signature) {
                up_fail(ctx, "Mach-O code-signature command is invalid");
                up_macho_layout_free(result);
                return 0;
            }
            result->signature_offset = up_le32(blob + cursor + 8);
            result->signature_size = up_le32(blob + cursor + 12);
            signature = true;
        }
        cursor += size;
    }
    if (cursor != commands_end) {
        up_fail(ctx, "Mach-O load commands do not fill header");
        up_macho_layout_free(result);
        return 0;
    }
    if (!encryption || result->crypt_id == 0) {
        return 1;
    }
    uint32_t magic = up_le32(blob);
    if (result->crypt_id != 1 ||
        (magic == UP_MH_MAGIC32 && result->cpu_type != UP_CPU_TYPE_ARM &&
         result->cpu_type != UP_CPU_TYPE_ARM64_32) ||
        (magic == UP_MH_MAGIC64 && result->cpu_type != UP_CPU_TYPE_ARM64)) {
        up_fail(ctx, "unsupported encrypted Mach-O architecture or cryptid");
        up_macho_layout_free(result);
        return 0;
    }
    if (!signature) {
        up_fail(ctx, "Mach-O has no code-signature command");
        up_macho_layout_free(result);
        return 0;
    }
    if ((uint64_t)result->crypt_offset + result->crypt_size > total_size ||
        (uint64_t)result->signature_offset + result->signature_size > total_size) {
        up_fail(ctx, "Mach-O range exceeds file");
        up_macho_layout_free(result);
        return 0;
    }
    if (result->crypt_size == 0 || result->crypt_size % UP_PAGE_BYTES != 0 ||
        result->crypt_offset % UP_PAGE_BYTES != 0) {
        up_fail(ctx, "Mach-O encrypted range must be nonempty and 4 KiB aligned");
        up_macho_layout_free(result);
        return 0;
    }
    if ((uint64_t)result->crypt_offset < commands_end ||
        (uint64_t)result->crypt_offset + (uint64_t)result->crypt_size >
            (uint64_t)result->signature_offset) {
        up_fail(ctx, "Mach-O encrypted range overlaps headers or signature");
        up_macho_layout_free(result);
        return 0;
    }
    return 1;
}

int up_parse_macho_slices(up_context *ctx,
                          const uint8_t *blob,
                          size_t blob_length,
                          uint64_t total_size,
                          up_macho_slice **slices,
                          size_t *count) {
    *slices = NULL;
    *count = 0;
    if (blob_length < 4) {
        return up_fail(ctx, "Mach-O header is truncated");
    }
    uint32_t thin_magic = up_le32(blob);
    if (thin_magic == UP_MH_MAGIC32 || thin_magic == UP_MH_MAGIC64) {
        up_macho_slice *result = calloc(1, sizeof(up_macho_slice));
        if (result == NULL) {
            return up_fail(ctx, "out of memory");
        }
        if (!up_parse_thin_macho(ctx, blob, blob_length, total_size, &result->layout)) {
            free(result);
            return 0;
        }
        result->size = total_size;
        result->offset = 0;
        *slices = result;
        *count = 1;
        return 1;
    }
    if (thin_magic == UP_MH_CIGAM32 || thin_magic == UP_MH_CIGAM64) {
        return up_fail(ctx, "big-endian thin Mach-O is unsupported");
    }
    if (!up_is_fat_macho(blob, blob_length)) {
        return up_fail(ctx, "expected Mach-O image");
    }
    if ((uint64_t)blob_length != total_size) {
        return up_fail(ctx, "universal Mach-O must be read completely");
    }
    uint32_t magic = up_be32(blob);
    bool little = magic == UP_FAT_CIGAM || magic == UP_FAT_CIGAM64;
    bool is64 = magic == UP_FAT_MAGIC64 || magic == UP_FAT_CIGAM64;
    uint64_t entry_size = is64 ? 32 : 20;
    if (blob_length < 8) {
        return up_fail(ctx, "universal Mach-O header is truncated");
    }
    uint64_t fat_count = little ? up_le32(blob + 4) : up_be32(blob + 4);
    if (fat_count == 0 || fat_count > 32 || fat_count > ((uint64_t)blob_length - 8) / entry_size) {
        return up_fail(ctx, "universal Mach-O architecture count is invalid");
    }
    uint64_t table_end = 8 + fat_count * entry_size;
    up_macho_slice *result = calloc((size_t)fat_count, sizeof(up_macho_slice));
    if (result == NULL) {
        return up_fail(ctx, "out of memory");
    }
    for (uint64_t index = 0; index < fat_count; index++) {
        const uint8_t *entry = blob + 8 + index * entry_size;
        uint32_t cpu_type = little ? up_le32(entry) : up_be32(entry);
        uint32_t cpu_subtype = little ? up_le32(entry + 4) : up_be32(entry + 4);
        uint64_t offset;
        uint64_t size;
        if (is64) {
            offset = little ? up_le64(entry + 8) : up_be64(entry + 8);
            size = little ? up_le64(entry + 16) : up_be64(entry + 16);
        } else {
            offset = little ? up_le32(entry + 8) : up_be32(entry + 8);
            size = little ? up_le32(entry + 12) : up_be32(entry + 12);
        }
        uint64_t alignment_offset = is64 ? 24 : 16;
        uint32_t align = little ? up_le32(entry + alignment_offset)
                               : up_be32(entry + alignment_offset);
        if (size == 0 || offset < table_end || offset > total_size || size > total_size - offset) {
            up_fail(ctx, "universal Mach-O architecture %llu has invalid bounds",
                    (unsigned long long)index);
            up_macho_slices_free(result, (size_t)index);
            return 0;
        }
        if (align > 63 || (offset & ((UINT64_C(1) << align) - 1)) != 0) {
            up_fail(ctx, "universal Mach-O architecture %llu is misaligned",
                    (unsigned long long)index);
            up_macho_slices_free(result, (size_t)index);
            return 0;
        }
        for (uint64_t previous = 0; previous < index; previous++) {
            if (offset < result[previous].offset + result[previous].size &&
                result[previous].offset < offset + size) {
                up_fail(ctx, "universal Mach-O architectures overlap");
                up_macho_slices_free(result, (size_t)index);
                return 0;
            }
        }
        up_macho_layout layout;
        if (!up_parse_thin_macho(ctx, blob + offset, (size_t)size, size, &layout)) {
            char *detail = strdup(up_last_error(ctx));
            up_macho_slices_free(result, (size_t)index);
            if (detail != NULL) {
                up_fail(ctx, "universal Mach-O architecture %llu: %s",
                        (unsigned long long)index, detail);
                free(detail);
            }
            return 0;
        }
        if (layout.cpu_type != cpu_type || layout.cpu_subtype != cpu_subtype) {
            up_macho_layout_free(&layout);
            up_fail(ctx, "universal Mach-O architecture %llu does not match its slice",
                    (unsigned long long)index);
            up_macho_slices_free(result, (size_t)index);
            return 0;
        }
        result[index].offset = offset;
        result[index].size = size;
        result[index].layout = layout;
    }
    *slices = result;
    *count = (size_t)fat_count;
    return 1;
}

void up_macho_slices_free(up_macho_slice *slices, size_t count) {
    if (slices == NULL) {
        return;
    }
    for (size_t index = 0; index < count; index++) {
        up_macho_layout_free(&slices[index].layout);
    }
    free(slices);
}

bool up_macho_layout_equal(const up_macho_layout *left, const up_macho_layout *right) {
    if (left->cpu_type != right->cpu_type || left->cpu_subtype != right->cpu_subtype ||
        left->crypt_offset != right->crypt_offset || left->crypt_size != right->crypt_size ||
        left->crypt_id != right->crypt_id || left->crypt_id_offset != right->crypt_id_offset ||
        left->signature_offset != right->signature_offset ||
        left->signature_size != right->signature_size ||
        left->range_count != right->range_count) {
        return false;
    }
    for (size_t index = 0; index < left->range_count; index++) {
        const up_macho_range *a = &left->ranges[index];
        const up_macho_range *b = &right->ranges[index];
        if (a->offset != b->offset || a->size != b->size || a->flags != b->flags ||
            strcmp(a->segment, b->segment) != 0 || strcmp(a->section, b->section) != 0) {
            return false;
        }
    }
    return true;
}

static int up_hash_code_page(uint8_t hash_type, const uint8_t *payload, size_t length,
                             uint8_t *output) {
    switch (hash_type) {
    case 1:
        up_sha1(payload, length, output);
        return 20;
    case 2:
    case 3:
        up_sha256(payload, length, output);
        return 32;
    case 4:
        up_sha384(payload, length, output);
        return 48;
    }
    return 0;
}

int up_audit_code_directories(up_context *ctx,
                              const uint8_t *executable,
                              size_t length,
                              const up_macho_layout *layout,
                              up_code_directory_audit **audits,
                              size_t *count) {
    *audits = NULL;
    *count = 0;
    uint64_t signature_end = (uint64_t)layout->signature_offset + layout->signature_size;
    uint64_t crypt_end = (uint64_t)layout->crypt_offset + layout->crypt_size;
    if (signature_end > (uint64_t)length || crypt_end > (uint64_t)length ||
        layout->crypt_size == 0) {
        return up_fail(ctx, "invalid Mach-O audit ranges");
    }
    const uint8_t *sig = executable + layout->signature_offset;
    size_t sig_length = (size_t)(signature_end - layout->signature_offset);
    if (sig_length < 12 || up_be32(sig) != UP_CS_MAGIC_EMBEDDED_SIGNATURE) {
        return up_fail(ctx, "invalid embedded signature");
    }
    uint64_t total = up_be32(sig + 4);
    uint64_t item_count = up_be32(sig + 8);
    if (total > sig_length || 12 + item_count * 8 > total) {
        return up_fail(ctx, "invalid embedded signature geometry");
    }
    up_code_directory_audit *reports = NULL;
    size_t report_count = 0;
    for (uint64_t index = 0; index < item_count; index++) {
        uint64_t offset = up_be32(sig + 16 + index * 8);
        if (offset + 8 > total) {
            free(reports);
            return up_fail(ctx, "signature item exceeds superblob");
        }
        uint32_t magic = up_be32(sig + offset);
        uint64_t item_length = up_be32(sig + offset + 4);
        if (item_length < 8 || offset + item_length > total) {
            free(reports);
            return up_fail(ctx, "signature item has invalid length");
        }
        if (magic != UP_CS_MAGIC_CODEDIRECTORY) {
            continue;
        }
        const uint8_t *dir = sig + offset;
        size_t dir_length = (size_t)item_length;
        if (dir_length < 44) {
            free(reports);
            return up_fail(ctx, "CodeDirectory is truncated");
        }
        uint32_t version = up_be32(dir + 8);
        uint64_t header_size = 44;
        if (version >= 0x20100) {
            header_size = 48;
            if (dir_length < header_size || up_be32(dir + 44) != 0) {
                free(reports);
                return up_fail(ctx, "truncated or unsupported scattered CodeDirectory");
            }
        }
        uint64_t code_limit = up_be32(dir + 32);
        if (version >= 0x20300) {
            header_size = 64;
            if (dir_length < header_size) {
                free(reports);
                return up_fail(ctx, "extended CodeDirectory is truncated");
            }
            if (code_limit == 0) {
                code_limit = up_be64(dir + 56);
            }
        }
        uint64_t hash_offset = up_be32(dir + 16);
        uint64_t code_slots = up_be32(dir + 28);
        int hash_size = dir[36];
        uint8_t hash_type = dir[37];
        uint8_t shift = dir[39];
        int expected_size = 0;
        switch (hash_type) {
        case 1:
            expected_size = 20;
            break;
        case 2:
            expected_size = 32;
            break;
        case 3:
            expected_size = 20;
            break;
        case 4:
            expected_size = 48;
            break;
        }
        if (expected_size == 0 || hash_size != expected_size || shift > 30) {
            free(reports);
            return up_fail(ctx, "CodeDirectory geometry is invalid");
        }
        if (code_limit < crypt_end || code_limit > (uint64_t)length) {
            free(reports);
            return up_fail(ctx, "CodeDirectory does not cover encrypted range");
        }
        uint64_t page_size = UINT64_C(1) << shift;
        if (shift == 0) {
            page_size = code_limit;
        }
        uint64_t first_slot = page_size == 0 ? 0 : (uint64_t)layout->crypt_offset / page_size;
        uint64_t last_slot =
            page_size == 0 ? 0 : (crypt_end + page_size - 1) / page_size;
        uint64_t slots = last_slot - first_slot;
        if (code_slots != (page_size == 0 ? 0 : (code_limit + page_size - 1) / page_size) ||
            last_slot > code_slots || hash_offset < header_size ||
            hash_offset + code_slots * (uint64_t)hash_size > (uint64_t)dir_length) {
            free(reports);
            return up_fail(ctx, "CodeDirectory table is truncated");
        }
        int matched = 0;
        for (uint64_t slot = first_slot; slot < last_slot; slot++) {
            uint64_t start = slot * page_size;
            uint64_t end = start + page_size < code_limit ? start + page_size : code_limit;
            uint8_t actual[48];
            int actual_length = up_hash_code_page(hash_type, executable + start,
                                                  (size_t)(end - start), actual);
            if (actual_length == 0) {
                free(reports);
                return up_fail(ctx, "unsupported CodeDirectory hash type %u", (unsigned)hash_type);
            }
            const uint8_t *expected = dir + hash_offset + slot * (uint64_t)hash_size;
            if (memcmp(actual, expected, (size_t)hash_size) == 0) {
                matched++;
            }
        }
        up_code_directory_audit *grown =
            realloc(reports, (report_count + 1) * sizeof(up_code_directory_audit));
        if (grown == NULL) {
            free(reports);
            return up_fail(ctx, "out of memory");
        }
        reports = grown;
        up_code_directory_audit *report = &reports[report_count++];
        report->hash_type = hash_type;
        report->hash_size = hash_size;
        report->page_size = (int)page_size;
        report->first_slot = (int)first_slot;
        report->slot_count = (int)slots;
        report->matched_slots = matched;
    }
    if (report_count == 0) {
        free(reports);
        return up_fail(ctx, "embedded signature contains no CodeDirectory");
    }
    *audits = reports;
    *count = report_count;
    return 1;
}
