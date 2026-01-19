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
#include "oscms_codecs_api/oscms_composite_crl.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/CompositeCrl.h"
#include "oscms_asn1c_generated/CompositeCrlSpdu.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

SO_EXPORT int oscms_encode_composite_crl(const OscmsCompositeCrl *composite_crl, OscmsOctetBuffer *encoded)
{
    if (!composite_crl || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    oscms_octet_buffer_init(encoded);

    if (!composite_crl->secured_crls || composite_crl->secured_crls_count == 0)
    {
        oscms_log(LOG_CRIT, "%s: Empty list of secured CRLs provided", __func__);
        return -1;
    }

    if (!composite_crl->home_ctl.data || composite_crl->home_ctl.length == 0)
    {
        oscms_log(LOG_CRIT, "%s: Empty MultiSignedCtlSpdu provided", __func__);
        return -1;
    }

    ScmsPdu_t pdu = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_cert,
                .choice =
                    {
                        .cert =
                            {
                                .present = CertManagementPdu_PR_compositeCrl,
                                // .choice.compositeCrl initialized later
                                ._asn_ctx = {0},
                            },
                    },
                ._asn_ctx = {0},
            },
        ._asn_ctx = {0},
    };

    CompositeCrl_t *internal = &pdu.content.choice.cert.choice.compositeCrl;
    memset(internal, 0, sizeof(CompositeCrl_t));

    for (size_t i = 0; i < composite_crl->secured_crls_count; i++)
    {
        SecuredCrl_t *decoded_secured_crl = 0;
        if (decode_and_check(&composite_crl->secured_crls[i], &asn_DEF_SecuredCrl, (void **)&decoded_secured_crl) != 0)
        {
            ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &pdu);
            oscms_log(LOG_ERR, "%s: Failed to decode and check secured CRL", __func__);
            return -1;
        }

        int rc = asn1c_add_to_sequence(&internal->crl.list, decoded_secured_crl);

        if (rc < 0)
        {
            ASN_STRUCT_FREE(asn_DEF_SecuredCrl, decoded_secured_crl);
            ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &pdu);
            oscms_log(LOG_ERR, "%s: Failed to add secured CRL", __func__);
            return -1;
        }
    }

    MultiSignedCtlSpdu_t *internal_home_ctl = 0;
    if (decode_and_check(&composite_crl->home_ctl, &asn_DEF_MultiSignedCtlSpdu, (void **)&internal_home_ctl) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &pdu);
        oscms_log(LOG_ERR, "%s: Failed to decode and check homeCtl", __func__);
        return -1;
    }
    (void)memcpy(&pdu.content.choice.cert.choice.compositeCrl.homeCtl, internal_home_ctl, sizeof(MultiSignedCtlSpdu_t));
    free(internal_home_ctl);
    internal_home_ctl = 0;

    if (check_and_encode(&pdu, &asn_DEF_ScmsPdu, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode composite CRL", __func__);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &pdu);
    return 0;
}

SO_EXPORT int oscms_encode_composite_crl_spdu(const OscmsCompositeCrl *composite_crl, OscmsOctetBuffer *encoded)
{
    if (!composite_crl || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    oscms_octet_buffer_init(encoded);

    OscmsOctetBuffer pdu = {0};
    if (oscms_encode_composite_crl(composite_crl, &pdu) != 0)
    {
        return -1;
    }

    int rc = oscms_encode_dot2_data_unsecured(&pdu, encoded);
    oscms_empty_octet_buffer(&pdu);

    if (rc != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to encode composite CRL as 1609Dot2Data-Unsecured", __func__);
    }
    return rc;
}
