// Copyright (c) 2025 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/oscms_ecc_curve.h"
#include "oscms_codecs_api/oscms_signature.h"

#include "oscms_asn1c_generated/Signature.h"

int oscms_signature_to_internal(const OscmsSignature *api_signature, void *internal_signature_void)
{
    int rc = 0;

    if (!api_signature || !internal_signature_void)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    Signature_t *internal_signature = (Signature_t *)internal_signature_void;
    (void)memset(internal_signature, 0, sizeof(*internal_signature));

    if (api_signature->type == OSCMS_SIGNATURE_TYPE_UNKNOWN || api_signature->type > OSCMS_SIGNATURE_TYPE_SM2)
    {
        oscms_log(LOG_CRIT, "%s: Unknown signature type: %d", __func__, api_signature->type);
        return -1;
    }
    else
    {
        internal_signature->present = (Signature_PR)api_signature->type;
        if (api_signature->type == OSCMS_SIGNATURE_TYPE_SM2)
        {
        }
        else
        {
            // We rely on the fact that all the in-memory reprsentations are the same and just treat them all as a NIST
            // P256
            rc = oscms_internal_from_ecc_curve_point(
                &api_signature->rsig.curve_point, &internal_signature->choice.ecdsaNistP256Signature.rSig);
            if (rc != 0)
            {
                return -1;
            }
        }
    }

    rc = oscms_octet_string_init_from_octet_buffer(
        &api_signature->s_sig, &internal_signature->choice.ecdsaNistP256Signature.sSig);
    if (rc != 0)
    {
        oscms_log(LOG_CRIT, "%s: Failed to initialize sSig", __func__);
        ASN_STRUCT_RESET(asn_DEF_Signature, internal_signature);
        return -1;
    }

    return 0;
}

int oscms_signature_from_internal(
    const void *internal_signature_void, OscmsSignature *oscms_signature, OscmsSequence *tracker)
{
    if (!internal_signature_void || !oscms_signature)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    const Signature_t *internal_signature = (const Signature_t *)internal_signature_void;

    int rc = 0;

    // We assume that all the internal representations are the same and just treat them all as a NIST P256.
    // We also assume the internal representation is valid, as it should have been constraint checked etc after
    // decoding.
    memset(oscms_signature, 0, sizeof(*oscms_signature));
    oscms_signature->type = (OscmsSignatureType)internal_signature->present;

    if (oscms_signature->type == OSCMS_SIGNATURE_TYPE_SM2)
    {
        // Just has an octet string for the rsig value
        rc = oscms_octet_buffer_init_from_octet_string(
            &internal_signature->choice.sm2Signature.rSig, &oscms_signature->rsig.value, tracker);
    }
    else
    {
        // Evertyhing else is a curve point for r_sig

        // Annoyingly, the ASN.1 for a Signature has the choices for P834 in a different order than everywhere else,  so
        // we can't just use the internal representation as is.
        OscmsEccPointCurveType api_curve_type = 0;
        if (internal_signature->present == Signature_PR_ecdsaBrainpoolP384r1Signature)
        {
            api_curve_type = OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P384;
        }
        else if (internal_signature->present == Signature_PR_ecdsaNistP384Signature)
        {
            api_curve_type = OSCMS_ECC_POINT_CURVE_TYPE_NIST_P384;
        }
        else
        {
            // Everything else corresponds.
            api_curve_type = (OscmsEccPointCurveType)internal_signature->present;
        }

        rc = oscms_ecc_curve_point_from_internal(
            &internal_signature->choice.ecdsaNistP256Signature.rSig,
            api_curve_type,
            &oscms_signature->rsig.curve_point,
            tracker);
    }

    if (rc != 0)
    {
        if (!tracker)
        {
            // No tracker provided so clean up after ourselves
            oscms_empty_signature(oscms_signature);
        }

        oscms_log(LOG_CRIT, "%s: Failed to initialize rsig", __func__);
        return -1;
    }

    rc = oscms_octet_buffer_init_from_octet_string(
        &internal_signature->choice.ecdsaNistP256Signature.sSig, &oscms_signature->s_sig, tracker);
    if (rc != 0)
    {
        if (!tracker)
        {
            // No tracker provided so clean up after ourselves
            oscms_empty_signature(oscms_signature);
        }

        oscms_log(LOG_CRIT, "%s: Failed to initialize sSig", __func__);
        return -1;
    }

    return 0;
}
