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

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_eca_ee_cert_response.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

SO_EXPORT int oscms_encode_eca_ee_cert_response(const OscmsEcaEeCertResponse *response, OscmsOctetBuffer *encoded)
{
    if (!response || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    // Per Ieee1609.2.1-2022 7.3.30
    //
    // Certificate chain must contain the entire ECA certificate chain up to and including
    // the root certificate

    if (!response->eca_cert_chain || response->eca_cert_chain_count == 0)
    {
        oscms_log(LOG_ERR, "%s: ECA certificate chain is empty", __func__);
        return -1;
    }

    // Per Ieee1609.2.1-2022 7.3.30
    //
    // privateKeyInfo shall be present and contain the private key reconstruction value if
    // certificate.type is implicit.
    //
    if (response->certificate.type == OSCMS_CERTIFICATE_TYPE_IMPLICIT && !response->private_key_info)
    {
        oscms_log(LOG_ERR, "%s: Private key info is empty for an implicit certificate", __func__);
        return -1;
    }

    // Per Ieee1609.2.1-2022 7.3.30,  privateKeyInfo is constrained on size
    //
    //      privateKeyInfo OCTET STRING (SIZE(32))

    if (response->private_key_info && response->private_key_info->length != 32)
    {
        oscms_log(LOG_ERR, "%s: Private key info is too long", __func__);
        return -1;
    }

    ScmsPdu_t internal = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_eca_ee,
                .choice.eca_ee =
                    {
                        .present                  = EcaEeInterfacePdu_PR_ecaEeCertResponse,
                        .choice.ecaEeCertResponse = {0},
                        ._asn_ctx                 = {0},
                    },
                ._asn_ctx = {0},
            },
        ._asn_ctx = {0},
    };

    EcaEeCertResponse_t *internal_pdu = &internal.content.choice.eca_ee.choice.ecaEeCertResponse;

    internal_pdu->version        = 2;
    internal_pdu->generationTime = response->generation_time;

    if (oscms_octet_string_init_from_buffer(
            response->request_hash, sizeof(response->request_hash), &internal_pdu->requestHash) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
        return -1;
    }

    if (oscms_internal_from_certificate(&response->certificate, &internal_pdu->certificate) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
        return -1;
    }

    if (allocate_asn1c_sequence_of(
            response->eca_cert_chain_count,
            sizeof(Certificate_t),
            (asn_anonymous_sequence_ *)&internal_pdu->ecaCertChain) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for ECA certificate chain", __func__);
        return -1;
    }

    for (size_t i = 0; i < response->eca_cert_chain_count; i++)
    {
        if (oscms_internal_from_certificate(
                &response->eca_cert_chain[i], internal_pdu->ecaCertChain.list.array[i]) != 0)
        {
            ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
            return -1;
        }
    }

    if (response->private_key_info)
    {
        if (response->private_key_info->length > INT_MAX)
        {
            ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
            oscms_log(LOG_ERR, "%s: Private key info is too long", __func__);
            return -1;
        }

        internal_pdu->privateKeyInfo = OCTET_STRING_new_fromBuf(
            &asn_DEF_OCTET_STRING,
            (const char *)response->private_key_info->data,
            (int)response->private_key_info->length);

        if (!internal_pdu->privateKeyInfo)
        {
            ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
            oscms_log(LOG_CRIT, "%s: Failed to initialize privateKeyInfo from buffer", __func__);
            return -1;
        }
    }

    // Sanity check of the internal PDU
    if (check_and_encode(internal_pdu, &asn_DEF_EcaEeCertResponse, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode ECA EE certificate response", __func__);
        return -1;
    }
    oscms_empty_octet_buffer(encoded);

    if (check_and_encode(&internal, &asn_DEF_ScmsPdu, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal_pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode ECA EE certificate response as an ScmsPdu", __func__);
        return -1;
    }
    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &internal);
    return 0;
}
