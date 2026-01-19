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

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ecc_curve.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "public_encryption_key.h"

int oscms_public_encryption_key_from_internal(
    const PublicEncryptionKey_t *internal, OscmsPublicEncryptionKey *pe_key, OscmsSequence *tracker)
{
    if (!internal || !pe_key)
    {
        oscms_log(LOG_ERR, "%s: Invalid parameters", __func__);
        return -1;
    }

    if (internal->supportedSymmAlg > OSCMS_SYMMETRIC_ALGORITHM_MAX)
    {
        oscms_log(LOG_ERR, "%s: Invalid symmetric algorithm", __func__);
        return -1;
    }

    memset(pe_key, 0, sizeof(OscmsPublicEncryptionKey));
    pe_key->algorithm = (OscmsSymmetricAlgorithmType)internal->supportedSymmAlg;

    const OscmsEccPointCurveType curve_point_type_map[] = {
        OSCMS_ECC_POINT_CURVE_TYPE_NONE,
        OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256,
        OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P256,
        OSCMS_ECC_POINT_CURVE_TYPE_SM2,
    };

    if (internal->publicKey.present >= sizeof(curve_point_type_map) / sizeof(curve_point_type_map[0]))
    {
        oscms_log(LOG_ERR, "%s: Unsupported ECC point curve type in certificate", __func__);
        return -1;
    }

    const EccP256CurvePoint_t *key_internal = &internal->publicKey.choice.eciesNistP256;
    if (oscms_ecc_curve_point_from_internal(
            key_internal, curve_point_type_map[internal->publicKey.present], &pe_key->key, tracker) != 0)
    {
        return -1;
    }

    return 0;
}
