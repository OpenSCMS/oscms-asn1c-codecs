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
#include "oscms_codecs_api/oscms_tbs_ctl_signature.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"
#include "oscms_asn1c_generated/ToBeSignedCtlSignature.h"

SO_EXPORT int oscms_tbs_ctl_signature_to_internal(const OscmsTbsCtlSignature *tbsCtlSig, void *internal_void)
{
    if (!tbsCtlSig || !internal_void)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    ToBeSignedCtlSignature_t *internal = (ToBeSignedCtlSignature_t *)internal_void;
    memset(internal, 0, sizeof(ToBeSignedCtlSignature_t));

    internal->sequenceNumber = tbsCtlSig->sequence_number;
    internal->ctlType        = Ieee1609dot2dot1MsctlType_fullIeeeCtl;

    if (oscms_octet_string_init_from_buffer(
            tbsCtlSig->series_id, sizeof(tbsCtlSig->series_id), &internal->ctlSeriesId) != 0)
    {
        return -1;
    }

    if (oscms_octet_string_init_from_buffer(
            tbsCtlSig->tbs_ctl_hash, sizeof(tbsCtlSig->tbs_ctl_hash), &internal->tbsCtlHash) != 0)
    {
        return -1;
    }

    return 0;
}

SO_EXPORT int oscms_encode_tbs_ctl_signature(const OscmsTbsCtlSignature *tbsCtlSig, OscmsOctetBuffer *encoded)
{
    if (!tbsCtlSig || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    ScmsPdu_t scms_pdu = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_cert,
                .choice =
                    {
                        .cert =
                            {
                                .present = CertManagementPdu_PR_tbsCtlSignature,
                                // .choice.tbsCtlSignature initialized later
                                ._asn_ctx = {0},
                            },
                    },
                ._asn_ctx = {0},
            },
        ._asn_ctx = {0},
    };

    if (oscms_tbs_ctl_signature_to_internal(tbsCtlSig, &scms_pdu.content.choice.cert.choice.tbsCtlSignature) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to convert args to internal TbsCtlSignature", __func__);
        return -1;
    }

    if (check_and_encode(&scms_pdu, &asn_DEF_ScmsPdu, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode TbsCtlSignature as ScmsPdu", __func__);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);
    return 0;
}

SO_EXPORT int oscms_encode_ctl_signature_spdu(const OscmsDot2DataSignedArgs *args, OscmsOctetBuffer *encoded)
{
    if (!args || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    oscms_octet_buffer_init_from_buffer(encoded, 0, 0);

    // Create a copy of the input args so we can enforce some constraints
    // without modifying the original
    OscmsDot2DataSignedArgs local_args = *args;
    local_args.enclosing_type          = OSCMS_DOT2_DATA_SIGNED_TYPE_CTL_SIGNATURE_SPDU;
    local_args.payload_psid            = OSCMS_PSID_SECURITY_MGMT;

    if (oscms_encode_dot2_data_signed(&local_args, encoded) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to encode CtlSignatureSpdu", __func__);
        return -1;
    }

    return 0;
}
