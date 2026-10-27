//
//  up_sinf.h
//  CUnfairPlay
//
//  SINF private-key decoding with an enrollment model, ported from
//  internal/fairplay/current_sinf.go and provider.go.
//

#ifndef UP_SINF_H
#define UP_SINF_H

#include "up_model.h"

/// Port of `currentSINFPrivateKey`. Sets `profile_mismatch` when the failure is
/// a "model cannot decode this SINF" condition, which the registry logic must
/// skip rather than report.
int up_current_sinf_private_key(up_context *ctx,
                                const up_model *model,
                                const uint8_t *sinf,
                                size_t sinf_length,
                                const up_atoms *fields,
                                uint8_t inner_key[16],
                                bool *profile_mismatch);

/// Port of `logicalFromInnerKey`.
void up_logical_from_inner_key(const uint8_t inner_key[16], uint8_t logical[16]);

/// Resolves the logical key for `sinf` with a single model, mirroring
/// `ResolveLogicalKeyWithModel`: selector binding, decode, then inner→logical.
/// `state_origin` is reported back for evidence output.
int up_resolve_logical_key(up_context *ctx,
                           const uint8_t *sinf,
                           size_t sinf_length,
                           const up_model *model,
                           uint8_t logical[16],
                           up_selector *selector,
                           bool *profile_mismatch);

#endif /* UP_SINF_H */
