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
#include "oscms_codecs_api/oscms_certificate_chain.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/CertificateChain.h"
#include "oscms_asn1c_generated/Ieee1609Dot2Data-Unsecured.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

SO_EXPORT int oscms_certificate_chain_to_internal(const OscmsCertificateChain *certificate_chain, void *internal_void)
{
    if (certificate_chain == NULL || internal_void == NULL)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    CertificateChain_t *internal = (CertificateChain_t *)internal_void;
    memset(internal, 0, sizeof(CertificateChain_t));

    MultiSignedCtlSpdu_t *homeCtl = 0;
    if (decode_and_check(&certificate_chain->home_ctl, &asn_DEF_MultiSignedCtlSpdu, (void **)&homeCtl) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to decode and check homeCtl", __func__);
        return -1;
    }

    (void)memcpy(&internal->homeCtl, homeCtl, sizeof(MultiSignedCtlSpdu_t));
    free(homeCtl); // We;ve copied it, so just release the original

    internal->others.list.array = NULL;
    internal->others.list.count = 0;
    internal->others.list.size  = 0;

    if (certificate_chain->others_count > 0 && certificate_chain->others != NULL)
    {
        // Pre-allocate the iternal sequence array of pointers to avoid regular re-allocs
        internal->others.list.array = calloc(certificate_chain->others_count, sizeof(Certificate_t *));
        if (!internal->others.list.array)
        {
            oscms_log(LOG_ERR, "%s: Failed to allocate memory for Sequence of certificates", __func__);
            ASN_STRUCT_RESET(asn_DEF_CertificateChain, internal);
            return -1;
        }

        internal->others.list.count = 0;
        internal->others.list.size  = certificate_chain->others_count;

        for (size_t i = 0; i < certificate_chain->others_count; i++)
        {
            if (decode_and_check(
                    &certificate_chain->others[i], &asn_DEF_Certificate, (void **)&internal->others.list.array[i]) != 0)
            {
                ASN_STRUCT_RESET(asn_DEF_CertificateChain, internal);
                oscms_log(LOG_ERR, "%s: Failed to decode and check others", __func__);
                return -1;
            }
            internal->others.list.count++;
        }
    }

    return 0;
}

SO_EXPORT int oscms_encode_certificate_chain(const OscmsCertificateChain *certificate_chain, OscmsOctetBuffer *encoded)
{
    if (!certificate_chain || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    oscms_octet_buffer_init_from_buffer(encoded, 0, 0);

    ScmsPdu_t scms_pdu = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_cert,
                .choice =
                    {
                        .cert =
                            {
                                .present = CertManagementPdu_PR_certificateChain,
                                // .choice.certificateChain initialized later
                                ._asn_ctx = {0},
                            },
                    },
                ._asn_ctx = {0},
            },
        ._asn_ctx = {0},
    };

    if (oscms_certificate_chain_to_internal(certificate_chain, &scms_pdu.content.choice.cert.choice.certificateChain) !=
        0)
    {
        oscms_log(LOG_ERR, "%s: Failed to OscmsCertificateChain to internal CertificateChain", __func__);
        return -1;
    }

    if (check_and_encode(&scms_pdu, &asn_DEF_ScmsPdu, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode CertificateChain as an ScmsPdu", __func__);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);
    return 0;
}

SO_EXPORT int oscms_encode_certificate_chain_spdu(
    const OscmsCertificateChain *certificate_chain, OscmsOctetBuffer *encoded)
{
    if (!certificate_chain || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    OscmsOctetBuffer scms_pdu = {0};
    oscms_octet_buffer_init_from_buffer(encoded, 0, 0);

    if (oscms_encode_certificate_chain(certificate_chain, &scms_pdu) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to encode certificate chain as an ScmsPdu", __func__);
        return -1;
    }

    int rc = oscms_encode_dot2_data_unsecured(&scms_pdu, encoded);
    if (rc != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to encode certificate chain as an ScmsPdu", __func__);
    }

    oscms_empty_octet_buffer(&scms_pdu);

    return rc;
}
