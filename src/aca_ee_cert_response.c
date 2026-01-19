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

//***** Delete the following comments they are just to give a structure */

// System includes (e.g. <stdio.h>)

// API includes

#include "oscms_codecs_api/dot2_data_unsecured.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_aca_ee_cert_response.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

SO_EXPORT int oscms_encode_aca_ee_cert_response(const OscmsAcaEeCertResponse *response, OscmsOctetBuffer *encoded)
{
    if (!response || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    // Per Ieee1609.2.1-2022 7.3.4
    //
    // privateKeyInfo shall be present and contain the private key reconstruction value if
    // certificate.type is implicit.
    //
    if (response->certificate.type == OSCMS_CERTIFICATE_TYPE_IMPLICIT && !response->private_key_info)
    {
        oscms_log(LOG_ERR, "%s: Private key info is empty for an implicit certificate", __func__);
        return -1;
    }

    // Per Ieee1609.2.1-2022 7.3.4,  privateKeyInfo is constrained on size
    //
    //      privateKeyInfo OCTET STRING (SIZE(32))

    if (response->private_key_info && response->private_key_info->length != 32)
    {
        oscms_log(LOG_ERR, "%s: Private key info is too long", __func__);
        return -1;
    }

    oscms_octet_buffer_init(encoded);

    ScmsPdu_t internal_scms_pdu = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_aca_ee,
                .choice.aca_ee =
                    {
                        .present                  = AcaEeInterfacePdu_PR_acaEeCertResponse,
                        .choice.acaEeCertResponse = {0},
                        ._asn_ctx                 = {0},
                    },
                ._asn_ctx = {0},
            },
        ._asn_ctx = {0},
    };

    AcaEeCertResponse_t *internal_pdu = &internal_scms_pdu.content.choice.aca_ee.choice.acaEeCertResponse;

    internal_pdu->version        = 2;
    internal_pdu->generationTime = response->generation_time;

    if (oscms_internal_from_certificate(&response->certificate, &internal_pdu->certificate) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_scms_pdu);
        return -1;
    }

    if (response->private_key_info)
    {
        if (response->private_key_info->length > INT_MAX)
        {
            ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_scms_pdu);
            oscms_log(LOG_ERR, "%s: Private key info is too long", __func__);
            return -1;
        }

        internal_pdu->privateKeyInfo = OCTET_STRING_new_fromBuf(
            &asn_DEF_OCTET_STRING,
            (const char *)response->private_key_info->data,
            (int)response->private_key_info->length);

        if (!internal_pdu->privateKeyInfo)
        {
            oscms_log(LOG_CRIT, "%s: Failed to initialize privateKeyInfo from buffer", __func__);
            ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_scms_pdu);
            return -1;
        }
    }

    // Sanity check of the internal PDU
    OscmsOctetBuffer encoded_internal_pdu = {0};

    if (check_and_encode(internal_pdu, &asn_DEF_AcaEeCertResponse, &encoded_internal_pdu) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_scms_pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode ACA EE certificate response", __func__);
        return -1;
    }
    oscms_empty_octet_buffer(&encoded_internal_pdu);

    if (check_and_encode(&internal_scms_pdu, &asn_DEF_ScmsPdu, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_scms_pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode ACA EE certificate response as an ScmsPdu", __func__);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_scms_pdu);
    return 0;
}

SO_EXPORT int oscms_encode_aca_ee_cert_response_plain_spdu(
    const OscmsAcaEeCertResponse *aca_ee_cert_response, OscmsOctetBuffer *encoded_spdu)
{
    // NULL checks happen in encode_ra_ee_cert_info()
    OscmsOctetBuffer encoded_payload = {0};
    if (oscms_encode_aca_ee_cert_response(aca_ee_cert_response, &encoded_payload) != 0)
    {
        return -1;
    }

    if (oscms_encode_dot2_data_unsecured(&encoded_payload, encoded_spdu) != 0)
    {
        oscms_empty_octet_buffer(&encoded_payload);
        oscms_log(LOG_ERR, "%s: Failed to encode AcaEeCertResponsePlain SPDU", __func__);

        return -1;
    }

    oscms_empty_octet_buffer(&encoded_payload);
    return 0;
}
