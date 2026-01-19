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

#include "oscms_codecs_api/dot2_data_unsecured.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_aca_response.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

#include "asn1c_utilities.h"
#include "dot2_data_encrypted_utils.h"
#include "dot2_data_signed_utils.h"

SO_EXPORT int oscms_encode_aca_response_private(
    const OscmsDot2DataSignedArgs *encrypted_signed_data, OscmsOctetBuffer *encoded)
{
    // Null checks
    if (!encrypted_signed_data || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    // Build signed data
    Ieee1609Dot2Content_t *content = (Ieee1609Dot2Content_t *)calloc(1, sizeof(Ieee1609Dot2Content_t));
    if (!content)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for Ieee1609Dot2Content_t", __func__);
        return -1;
    }

    content->present = Ieee1609Dot2Content_PR_signedData;

    int rc = generate_signed_data(encrypted_signed_data, &content->choice.signedData);
    if (rc != 0)
    {
        free(content);
        return -1;
    }

    Ieee1609Dot2Data_t spdu = {
        .protocolVersion = 3,
        .content         = content,
        ._asn_ctx        = {0},
    };

    // Build AcaResponse
    AcaResponse_t aca_response = {
        .present = AcaResponse_PR_private,
        .choice =
            {
                .Private = spdu,
            },
        ._asn_ctx = {0},
    };

    // Encode AcaResponse
    rc = check_and_encode(&aca_response, &asn_DEF_AcaResponse, encoded);

    ASN_STRUCT_RESET(asn_DEF_AcaResponse, &aca_response);
    return rc;
}

SO_EXPORT int oscms_encode_aca_response_cubk(
    const OscmsDot2DataEncrypted *dot2_data_encrypted, OscmsOctetBuffer *encoded)
{
    // Null checks
    if (!dot2_data_encrypted || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    // Build encrypted data
    Ieee1609Dot2Content_t *content = (Ieee1609Dot2Content_t *)calloc(1, sizeof(Ieee1609Dot2Content_t));
    if (!content)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for Ieee1609Dot2Content_t", __func__);
        return -1;
    }

    content->present = Ieee1609Dot2Content_PR_encryptedData;

    Ieee1609Dot2Data_t spdu = {
        .protocolVersion = 3,
        .content         = content,
        ._asn_ctx        = {0},
    };

    if (encode_encrypted_data(dot2_data_encrypted, &content->choice.encryptedData) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Data_Encrypted_276P0, &spdu);
        return -1;
    }

    // Build AcaResponse
    AcaResponse_t aca_response = {
        .present = AcaResponse_PR_cubk,
        .choice =
            {
                .cubk = spdu,
            },
        ._asn_ctx = {0},
    };

    // Encode AcaResponse
    int rc = check_and_encode(&aca_response, &asn_DEF_AcaResponse, encoded);

    ASN_STRUCT_RESET(asn_DEF_AcaResponse, &aca_response);
    return rc;
}

SO_EXPORT int oscms_encode_aca_response_plain(const OscmsAcaEeCertResponse *plain, OscmsOctetBuffer *encoded)
{
    // Null checks
    if (!plain || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    // NULL checks happen in encode_ra_ee_cert_info()
    OscmsOctetBuffer encoded_payload = {0};
    if (oscms_encode_aca_ee_cert_response(plain, &encoded_payload) != 0)
    {
        return -1;
    }

    // Build unsecure data
    Ieee1609Dot2Content_t *contentInfo = calloc(1, sizeof(Ieee1609Dot2Content_t));
    if (!contentInfo)
    {
        oscms_log(LOG_CRIT, "%s: calloc failed for Ieee1609Dot2ContentInfo_t", __func__);
        oscms_empty_octet_buffer(&encoded_payload);
        return -1;
    }

    Ieee1609Dot2Data_Unsecured_216P0_t spdu = {
        .protocolVersion = 3,
        .content         = contentInfo,
        ._asn_ctx        = {0},
    };

    contentInfo->present = Ieee1609Dot2Content_PR_unsecuredData;
    if (oscms_octet_string_init_from_octet_buffer(&encoded_payload, &contentInfo->choice.unsecuredData) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Data_Unsecured_216P0, &spdu);
        return -1;
    }

    oscms_empty_octet_buffer(&encoded_payload);

    // Build AcaResponse
    AcaResponse_t aca_response = {
        .present = AcaResponse_PR_plain,
        .choice =
            {
                .plain = spdu,
            },
        ._asn_ctx = {0},
    };

    // Encode AcaResponse
    int rc = check_and_encode(&aca_response, &asn_DEF_AcaResponse, encoded);

    ASN_STRUCT_RESET(asn_DEF_AcaResponse, &aca_response);
    return rc;
}
