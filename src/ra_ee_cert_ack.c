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

#include "oscms_codecs_api/dot2_data_signed.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ra_ee_cert_ack.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/EeRaInterfacePdu.h"
#include "oscms_asn1c_generated/RaEeCertAck.h"
#include "oscms_asn1c_generated/ScmsPdu.h"

static int generate_ee_ra_cert_ack(const OscmsRaEeCertAck *ra_ee_cert_ack, RaEeCertAck_t **ra_ee_cert_ack_asn1)
{
    oscms_log(LOG_DEBUG, "%s: Generating RaEeCertAck", __func__);

    if (!ra_ee_cert_ack || !ra_ee_cert_ack_asn1)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    // Allocate memory for RaEeCertAck_t
    *ra_ee_cert_ack_asn1 = (RaEeCertAck_t *)calloc(1, sizeof(RaEeCertAck_t));
    if (!*ra_ee_cert_ack_asn1)
    {
        oscms_log(LOG_CRIT, "%s: Memory allocation failed for RaEeCertAck_t", __func__);
        return -1;
    }

    // Set version to 2 as per specification
    (*ra_ee_cert_ack_asn1)->version = 2;

    // Set generationTime
    (*ra_ee_cert_ack_asn1)->generationTime = ra_ee_cert_ack->generation_time;

    // Set requestHash
    int rc = oscms_octet_string_init_from_buffer(
        ra_ee_cert_ack->request_hash, sizeof(ra_ee_cert_ack->request_hash), &(*ra_ee_cert_ack_asn1)->requestHash);
    if (rc != 0)
    {
        oscms_log(LOG_CRIT, "%s: Failed to initialize requestHash from buffer", __func__);
        ASN_STRUCT_FREE(asn_DEF_RaEeCertAck, *ra_ee_cert_ack_asn1);
        return -1;
    }

    // Set nextDlTime
    (*ra_ee_cert_ack_asn1)->nextDlTime = ra_ee_cert_ack->next_dl_time;

    // Set firstI
    (*ra_ee_cert_ack_asn1)->firstI = (IValue_t *)calloc(1, sizeof(IValue_t));
    if (!(*ra_ee_cert_ack_asn1)->firstI)
    {
        oscms_log(LOG_CRIT, "%s: Memory allocation failed for firstI", __func__);
        ASN_STRUCT_FREE(asn_DEF_RaEeCertAck, *ra_ee_cert_ack_asn1);
        return -1;
    }

    *(*ra_ee_cert_ack_asn1)->firstI = ra_ee_cert_ack->first_i;

    return 0;
}

SO_EXPORT int oscms_encode_ra_ee_cert_ack(
    const OscmsRaEeCertAck *ra_ee_cert_ack, OscmsOctetBuffer *encoded_ra_ee_cert_ack)
{
    oscms_log(LOG_DEBUG, "%s: Encoding RaEeCertAck", __func__);

    // Null checks
    if (!ra_ee_cert_ack || !encoded_ra_ee_cert_ack)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    // Generate RaEeCertAck
    RaEeCertAck_t *ra_ee_cert_ack_asn1 = NULL;

    int rc = generate_ee_ra_cert_ack(ra_ee_cert_ack, &ra_ee_cert_ack_asn1);
    if (rc != 0)
    {
        oscms_log(LOG_CRIT, "%s: Failed to generate RaEeCertAck ASN.1 structure", __func__);
        return -1;
    }

    // Wrap up RaEeCertAck into EeRaInterfacePdu
    EeRaInterfacePdu_t ee_ra_interface_pdu = {
        .present            = EeRaInterfacePdu_PR_raEeCertAck,
        .choice.raEeCertAck = *ra_ee_cert_ack_asn1,
        ._asn_ctx           = {0},
    };

    // we've copied it, so we can release the original. But DON"T call ASN_STRUCT_FREE as the copy
    // has all the included resources.
    (void)explicit_bzero(ra_ee_cert_ack_asn1, sizeof(*ra_ee_cert_ack_asn1));
    free(ra_ee_cert_ack_asn1);

    // Wrap up EeRaInterfacePdu into ScmsPdu
    ScmsPdu_t scms_pdu = {
        .version              = 2,
        .content.present      = ScmsPdu__content_PR_ee_ra,
        .content.choice.ee_ra = ee_ra_interface_pdu,
        ._asn_ctx             = {0},
    };

    if (check_and_encode(&scms_pdu, &asn_DEF_ScmsPdu, encoded_ra_ee_cert_ack) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);
        return -1;
    }

    // Free allocated structures
    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);

    return 0;
}
