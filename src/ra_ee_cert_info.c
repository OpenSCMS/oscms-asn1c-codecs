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
#include "oscms_codecs_api/oscms_ra_ee_cert_info.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

SO_EXPORT int oscms_encode_ra_ee_cert_info(const OscmsRaEeCertInfo *cert_info, OscmsOctetBuffer *encoded)
{
    if (!cert_info || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    ScmsPdu_t internal = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_ee_ra,
                .choice.ee_ra =
                    {
                        .present = EeRaInterfacePdu_PR_raEeCertInfo,
                        .choice.raEeCertInfo =
                            {
                                .version        = 2,
                                .generationTime = cert_info->generation_time,
                                .currentI       = cert_info->current_i,
                                .requestHash    = {0},
                                .nextDlTime     = cert_info->next_download_time,
                                .acpcTreeId     = 0,
                                ._asn_ctx       = {0},
                            },
                        ._asn_ctx = {0},
                    },
                ._asn_ctx = {0},
            },
        ._asn_ctx = {0},
    };

    RaEeCertInfo_t *internal_pdu = &internal.content.choice.ee_ra.choice.raEeCertInfo;

    if (oscms_octet_string_init_from_buffer(
            cert_info->request_hash, sizeof(cert_info->request_hash), &internal_pdu->requestHash) != 0)
    {
        // No need to RESET the struct as we haven't managed to allocate any memory
        oscms_log(LOG_ERR, "%s: Failed to allocate memory for request hash", __func__);
        return -1;
    }

    // Do a sanity check of the PDU itself.
    if (check_and_encode(internal_pdu, &asn_DEF_RaEeCertInfo, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal);
        oscms_log(LOG_ERR, "%s: Failed to encode RaEeCertInfo", __func__);
        return -1;
    }

    oscms_empty_octet_buffer(encoded);

    // Now actually encode the ScmsPdu
    if (check_and_encode(&internal, &asn_DEF_ScmsPdu, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal);
        oscms_log(LOG_ERR, "%s: Failed to encode ScmsPdu", __func__);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal);
    return 0;
}

SO_EXPORT int oscms_encode_ra_ee_cert_info_spdu(
    const OscmsRaEeCertInfo *ra_ee_cert_info, OscmsOctetBuffer *encoded_spdu)
{
    // NULL checks happen in encode_ra_ee_cert_info()
    OscmsOctetBuffer encoded_payload = {0};
    if (oscms_encode_ra_ee_cert_info(ra_ee_cert_info, &encoded_payload) != 0)
    {
        return -1;
    }

    if (oscms_encode_dot2_data_unsecured(&encoded_payload, encoded_spdu) != 0)
    {
        oscms_empty_octet_buffer(&encoded_payload);
        oscms_log(LOG_ERR, "%s: Failed to encode RaEeCertInfo SPDU", __func__);

        return -1;
    }

    oscms_empty_octet_buffer(&encoded_payload);
    return 0;
}
