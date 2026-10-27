//
//  up_license.h
//  CUnfairPlay
//
//  Logical-key resolution and license material, ported from provider.go and
//  ipa_licenses.go. Error strings follow the Go implementation because the
//  doctor report surfaces them to the host app.
//

#ifndef UP_LICENSE_H
#define UP_LICENSE_H

#include "up_ipa.h"
#include "up_model.h"
#include "up_pagekey.h"

typedef struct {
    uint8_t logical[16];
    uint8_t mask[16];
    up_page_deriver deriver;
    uint32_t model_version;
    char provider_kind[48];
    char model_name[80];
    char model_sha256[65];
    char evaluator_source_sha256[65];
    char request_selector[18];
} up_key_material;

typedef struct {
    char *member;
    char request_sinf_sha256[65];
    up_key_material material;
} up_license;

typedef struct {
    up_license *items;
    size_t count;
} up_license_set;

void up_license_set_free(up_license_set *set);

/// Port of `ResolveLogicalKeyWithModel`: model parse, selector binding,
/// private-key decode, and inner→logical conversion. Sets `profile_mismatch`
/// when the model simply cannot decode this SINF.
int up_resolve_with_model(up_context *ctx,
                          const uint8_t *sinf,
                          size_t sinf_length,
                          const uint8_t *pack,
                          size_t pack_length,
                          up_key_material *out,
                          bool *profile_mismatch);

/// Port of `ResolveLogicalKeyWithModels`: exactly one candidate may decode the
/// SINF. `selected_index` receives the winning registry position.
int up_resolve_with_registry(up_context *ctx,
                             const uint8_t *sinf,
                             size_t sinf_length,
                             const up_model_registry *registry,
                             up_key_material *out,
                             size_t *selected_index);

/// Resolves one license per encrypted image using the model path bound to the
/// context (a directory, or a single `.bin` file).
int up_resolve_ipa_licenses(up_context *ctx,
                            up_ipa_inventory *inventory,
                            const char *model_path,
                            up_license_set *out);

#endif /* UP_LICENSE_H */
