//
//  up_ipa.h
//  CUnfairPlay
//
//  IPA inventory ported from openIPAInventory in decrypt.go: duplicate member
//  rules, SINF/SUPF association, Mach-O and SUPF validation, and the final
//  "no supported encrypted Mach-O images" gate.
//

#ifndef UP_IPA_H
#define UP_IPA_H

#include "up_macho.h"
#include "up_supf.h"
#include "up_zip.h"

/// Open-addressing name index over the ZIP entries. Slot values are entry
/// indices plus one, so zero means empty.
typedef struct {
    size_t *slots;
    size_t capacity;
} up_name_index;

int up_name_index_build(up_context *ctx, const up_zip *archive, up_name_index *out);
void up_name_index_free(up_name_index *index);
/// Entry index, or SIZE_MAX.
size_t up_name_index_find(const up_name_index *index, const up_zip *archive, const char *name);

typedef struct {
    char *member;
    char *supf_member;
    char *sinf_member;
    uint64_t slice_offset;
    uint64_t slice_size;
    up_macho_layout layout;
} up_encrypted_image;

typedef struct {
    char *name;
    up_supf_table table;
} up_supf_cache;

typedef struct {
    char *name;
    uint8_t *bytes;
    size_t length;
} up_cached_member;

typedef struct {
    char *path;
    int64_t bytes;
    char sha256[65];
    char **sinf_members;
    size_t sinf_count;
    up_encrypted_image *images;
    size_t image_count;
    up_supf_cache *tables;
    size_t table_count;
    up_cached_member *cached;
    size_t cached_count;
    up_name_index index;
    up_zip archive;
} up_ipa_inventory;

int up_ipa_inventory_open(up_context *ctx, const char *path, up_ipa_inventory *out);
void up_ipa_inventory_close(up_ipa_inventory *inventory);

/// Returns the archive entry named `name`, or fails.
const up_zip_entry *up_ipa_entry(up_context *ctx,
                                 const up_ipa_inventory *inventory,
                                 const char *name);

/// Reads and caches a SUPF table by member name.
int up_ipa_supf(up_context *ctx, up_ipa_inventory *inventory, const char *name,
                up_supf_table **out);

/// Returns the cached whole-member bytes for `name`, or NULL when absent.
const uint8_t *up_ipa_cached(const up_ipa_inventory *inventory, const char *name, size_t *length);

#endif /* UP_IPA_H */
