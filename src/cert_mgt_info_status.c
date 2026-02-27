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

// System includes (e.g. <stdio.h>)

#include <stdlib.h>

// API includes
#include "oscms_codecs_api/cert_mgt_info_status.h"
#include "oscms_codecs_api/dot2_data_signed.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"

#include "asn1c_utilities.h"

// Includes from generated files
#include "oscms_asn1c_generated/CertManagementPdu.h"
#include "oscms_asn1c_generated/CertificateManagementInfoStatus.h"
#include "oscms_asn1c_generated/CertificateManagementInformationStatusSpdu.h"
#include "oscms_asn1c_generated/ScmsPdu.h"

static int check_args(const OscmsCertManagementPduArgs *args)
{
    if (args->crl_count > 0 && (!args->crl_series_list || !args->crl_issue_dates || !args->crl_craca_ids))
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided for CRL components", __func__);
        return -1;
    }

    if (args->ctl_count > 0 && (!args->ctl_series_ids || !args->ctl_sequence_numbers || !args->ctl_last_update_times))
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided for CTL components", __func__);
        return -1;
    }

    if (args->ma_count > 0 && (!args->ma_psid_lists || !args->ma_updated_times || !args->ma_psid_list_counts))
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided for MA components", __func__);
        return -1;
    }
    return 0;
}

static int build_crl_list(const OscmsCertManagementPduArgs *args, SequenceOfCrlInfoStatus_t *crl)
{
    memset(crl, 0, sizeof(SequenceOfCrlInfoStatus_t));

    if (allocate_asn1c_sequence_of(args->crl_count, sizeof(CrlInfoStatus_t), (asn_anonymous_sequence_ *)crl) < 0)
    {
        oscms_log(LOG_CRIT, "%s: allocate_asn1c_sequence_of failed", __func__);
        return -1;
    }

    for (size_t i = 0; i < args->crl_count; i++)
    {
        CrlInfoStatus_t *crl_info_status = crl->list.array[i];
        if (!crl_info_status)
        {
            oscms_log(LOG_CRIT, "%s: calloc failed", __func__);
            return -1;
        }

        if (oscms_octet_string_init_from_buffer(
                args->crl_craca_ids[i], sizeof(OscmsHashedId8), &crl_info_status->cracaId) < 0)
        {
            oscms_log(LOG_CRIT, "%s: OCTET_STRING_fromBuf failed", __func__);
            return -1;
        }

        crl_info_status->series    = args->crl_series_list[i];
        crl_info_status->issueDate = args->crl_issue_dates[i];
    }
    return 0;
}

static int build_ctl_list(const OscmsCertManagementPduArgs *args, SequenceOfCtlInfoStatus_t *ctl)
{
    memset(ctl, 0, sizeof(SequenceOfCtlInfoStatus_t));

    if (allocate_asn1c_sequence_of(args->ctl_count, sizeof(CtlInfoStatus_t), (asn_anonymous_sequence_ *)ctl) < 0)
    {
        oscms_log(LOG_CRIT, "%s: allocate_asn1c_sequence_of failed", __func__);
        return -1;
    }

    for (size_t i = 0; i < args->ctl_count; i++)
    {
        CtlInfoStatus_t *ctl_info_status = ctl->list.array[i];

        ctl_info_status->sequenceNumber = args->ctl_sequence_numbers[i];
        ctl_info_status->lastUpdate     = args->ctl_last_update_times[i];

        if (oscms_octet_string_init_from_buffer(
                args->ctl_series_ids[i], sizeof(OscmsCtlSeriesId), &ctl_info_status->ctlSeriesId) < 0)
        {
            oscms_log(LOG_CRIT, "%s: OCTET_STRING_fromBuf failed", __func__);
            return -1;
        }
    }
    return 0;
}

static int build_ma_list(const OscmsCertManagementPduArgs *args, SequenceOfMaInfoStatus_t *ma)
{
    ma->list.count = ma->list.size = 0;
    ma->list.array                 = 0;

    if (allocate_asn1c_sequence_of(args->ma_count, sizeof(MaInfoStatus_t), (asn_anonymous_sequence_ *)ma) != 0)
    {
        oscms_log(LOG_CRIT, "%s: allocate_asn1c_sequence_of failed", __func__);
        return -1;
    }

    for (size_t i = 0; i < args->ma_count; i++)
    {
        MaInfoStatus_t *ma_info_status = ma->list.array[i];

        if (allocate_asn1c_sequence_of(
                args->ma_psid_list_counts[i], sizeof(Psid_t), (asn_anonymous_sequence_ *)&ma_info_status->psids) != 0)
        {
            oscms_log(LOG_CRIT, "%s: allocate_asn1c_sequence_of failed", __func__);
            return -1;
        }

        ma_info_status->updated    = args->ma_updated_times[i];
        const OscmsPsid *psid_list = args->ma_psid_lists[i];
        Psid_t *internal_psid_list = ma_info_status->psids.list.array[i];

        for (size_t j = 0; j < args->ma_psid_list_counts[i]; j++)
        {
            internal_psid_list[j] = psid_list[j];
        }
    }
    return 0;
}

// Public functions

SO_EXPORT int oscms_encode_cert_mngt_pdu(const OscmsCertManagementPduArgs *args, OscmsOctetBuffer *encoded_pdu)
{
    if (!encoded_pdu || !args)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    if (check_args(args) != 0)
    {
        return -1;
    }

    encoded_pdu->data   = 0;
    encoded_pdu->length = 0;

    // Pre-initialize as much as possible to make the structure clearer
    ScmsPdu_t scms_spdu = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_cert,
                .choice =
                    {
                        .cert =
                            {
                                .present = CertManagementPdu_PR_infoStatus,
                                .choice =
                                    {
                                        .infoStatus =
                                            {
                                                .ra    = 0, // Has to be malloc'd
                                                .caCcf = args->ca_ccf_updated_time,
                                                .crl   = {{0}},
                                                .ctl   = {{0}},
                                                .ma    = {{0}},
                                            },
                                    },

                            },
                    },
            },
    };

    CertificateManagementInfoStatus_t *infoStatus = &scms_spdu.content.choice.cert.choice.infoStatus;

    // The ra field in infostatus is optional and therefore has to be set as a pointer,
    // but ASN_STRUCT_RESET() will assume it is pointing to dynamic memory.
    //
    // Therefore we need to malloc memory for it

    Time32_t *ra = calloc(1, sizeof(Time32_t));
    if (!ra)
    {
        oscms_log(LOG_CRIT, "%s: calloc failed for ra", __func__);
        return -1;
    }
    *ra            = args->ra_updated_time;
    infoStatus->ra = ra;

    if (build_crl_list(args, &infoStatus->crl) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_spdu);
        return -1;
    }

    if (build_ctl_list(args, &infoStatus->ctl) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_spdu);
        return -1;
    }

    if (build_ma_list(args, &infoStatus->ma) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_spdu);
        return -1;
    }

    // Validate what we've built for any constraint violations and encode it to binary

    if (check_and_encode(&scms_spdu, &asn_DEF_ScmsPdu, encoded_pdu) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_spdu);
        return -1;
    }

    // We're done now with the actual PDU, so release all its resources.
    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_spdu);
    return 0;
}
