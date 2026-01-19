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

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/Ieee1609Dot2Data-Unsecured.h"

SO_EXPORT int oscms_encode_dot2_data_unsecured(const OscmsOctetBuffer *payload, OscmsOctetBuffer *encoded)
{
    if (!payload || !encoded || !payload->data || !payload->length)
    {
        oscms_log(LOG_CRIT, "%s: NULL or invalid parameter provided", __func__);
        return -1;
    }

    Ieee1609Dot2Content_t *contentInfo = calloc(1, sizeof(Ieee1609Dot2Content_t));
    if (!contentInfo)
    {
        oscms_log(LOG_CRIT, "%s: calloc failed for Ieee1609Dot2ContentInfo_t", __func__);
        return -1;
    }

    Ieee1609Dot2Data_Unsecured_216P0_t spdu = {
        .protocolVersion = 3,
        .content         = contentInfo,
        ._asn_ctx        = {0},
    };

    // From this point on,  contentInfo is owned by the SPDU and will be freed when the SPDU is RESET

    contentInfo->present = Ieee1609Dot2Content_PR_unsecuredData;
    if (oscms_octet_string_init_from_octet_buffer(payload, &contentInfo->choice.unsecuredData) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Data_Unsecured_216P0, &spdu);
        return -1;
    }

    if (check_and_encode(&spdu, &asn_DEF_Ieee1609Dot2Data_Unsecured_216P0, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Data_Unsecured_216P0, &spdu);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Data_Unsecured_216P0, &spdu);
    return 0;
}

SO_EXPORT int oscms_decode_dot2_data_unsecured(const OscmsOctetBuffer *encoded, OscmsOctetBuffer *payload)
{
    if (!payload || !encoded || !encoded->data || !encoded->length)
    {
        oscms_log(LOG_CRIT, "%s: NULL or invalid parameter provided", __func__);
        return -1;
    }

    Ieee1609Dot2Data_Unsecured_216P0_t *spdu = 0;

    if (decode_and_check(encoded, &asn_DEF_Ieee1609Dot2Data_Unsecured_216P0, (void **)&spdu) != 0)
    {
        return -1;
    }

    int rc = oscms_octet_buffer_init_from_octet_string(&spdu->content->choice.unsecuredData, payload, 0);
    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data_Unsecured_216P0, spdu);

    return rc;
}
