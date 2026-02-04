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
#include "oscms_codecs_api/oscms_multi_signed_ctl.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/CtlSignatureSpdu.h"
#include "oscms_asn1c_generated/MultiSignedCtl.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

// These really should have been in the IEEE ASN.1 sources

typedef A_SEQUENCE_OF(CtlElectorEntry_t) SequenceOfCtlElectors;
typedef A_SEQUENCE_OF(CtlRootCaEntry_t) SequenceOfCtlRootCaEntry;
typedef A_SEQUENCE_OF(struct CtlSignatureSpdu) SequenceOfCtlSignatureSpdu;

// NOTE: These functions take a non-const first argument due to a vagary of
// C in that a const * to a struct containing pointers is not the same as a
// pointer to a struct containing const pointers.
//
// i.e. the "const" qualifier on the struct pointer does not get applied to
// the pointers contained in the struct.
//
static int ctl_electors_to_internal(
    OscmsCtlElectorEntry *electors, size_t elector_count, SequenceOfCtlElectors *internal)
{
    if (!internal)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    (void)memset(internal, 0, sizeof(SequenceOfCtlElectors));

    if (!electors || elector_count == 0)
    {
        return 0;
    }

    internal->array = calloc(elector_count, sizeof(CtlElectorEntry_t *));
    if (!internal->array)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for CtlElectorEntries", __func__);
        return -1;
    }

    internal->size = elector_count;

    for (size_t i = 0; i < elector_count; i++)
    {
        CtlElectorEntry_t *elector = malloc(sizeof(CtlElectorEntry_t));
        if (!elector)
        {
            return -1;
        }

        if (oscms_octet_string_init_from_buffer((const uint8_t *)&electors[i], sizeof(*electors), elector) != 0)
        {
            free(elector);
            return -1;
        }

        int rc = asn1c_add_to_sequence(internal, elector);
        if (rc != 0)
        {
            free(elector);
            return -1;
        }
    }

    return 0;
}

static int ctl_root_cas_to_internal(
    OscmsRootCaEntry *root_cas, size_t root_ca_count, SequenceOfCtlRootCaEntry *internal)
{
    if (!internal)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    internal->count = internal->size = 0;
    internal->array                  = NULL;

    if (!root_cas || root_ca_count == 0)
    {
        return 0;
    }

    internal->array = calloc(root_ca_count, sizeof(CtlRootCaEntry_t *));
    if (!internal->array)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for CtlRootCaEntries", __func__);
        return -1;
    }

    internal->size = root_ca_count;

    for (size_t i = 0; i < root_ca_count; i++)
    {
        CtlRootCaEntry_t *root_ca = calloc(1, sizeof(CtlRootCaEntry_t));
        if (!root_ca)
        {
            return -1;
        }

        if (oscms_octet_string_init_from_buffer((const uint8_t *)&root_cas[i], sizeof(*root_cas), root_ca) != 0)
        {
            free(root_ca);
            return -1;
        }

        int rc = asn1c_add_to_sequence(internal, root_ca);
        if (rc != 0)
        {
            free(root_ca);
            return -1;
        }
    }

    return 0;
}

static int full_ieee_ctl_to_internal(const OscmsFullIeeeTbsCtl *full_ieee_ctl, FullIeeeTbsCtl_t *internal)
{
    if (!internal || !full_ieee_ctl)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }
    memset(internal, 0, sizeof(FullIeeeTbsCtl_t));
    internal->type           = Ieee1609dot2dot1MsctlType_fullIeeeCtl;
    internal->sequenceNumber = full_ieee_ctl->sequence_number;
    internal->effectiveDate  = full_ieee_ctl->effective_date;

    if (oscms_octet_string_init_from_buffer(
            full_ieee_ctl->series_id, sizeof(full_ieee_ctl->series_id), &internal->ctlSeriesId) != 0)
    {
        return -1;
    }

    if (ctl_electors_to_internal(
            full_ieee_ctl->elector_approve,
            full_ieee_ctl->num_elector_approve,
            (SequenceOfCtlElectors *)&internal->electorApprove.list) != 0)
    {
        return -1;
    }

    if (ctl_electors_to_internal(
            full_ieee_ctl->elector_remove,
            full_ieee_ctl->num_elector_remove,
            (SequenceOfCtlElectors *)&internal->electorRemove.list) != 0)
    {
        return -1;
    }

    if (ctl_root_cas_to_internal(
            full_ieee_ctl->root_ca_approve,
            full_ieee_ctl->num_root_ca_approve,
            (SequenceOfCtlRootCaEntry *)&internal->rootCaApprove.list) != 0)
    {
        return -1;
    }

    if (ctl_root_cas_to_internal(
            full_ieee_ctl->root_ca_remove,
            full_ieee_ctl->num_root_ca_remove,
            (SequenceOfCtlRootCaEntry *)&internal->rootCaRemove.list) != 0)
    {
        return -1;
    }

    if (full_ieee_ctl->quorum_present)
    {
        internal->quorum = malloc(sizeof(*internal->quorum));
        if (!internal->quorum)
        {
            return -1;
        }
        *internal->quorum = full_ieee_ctl->quorum;
    }

    return 0;
}

static int unsigned_to_internal(
    const OscmsOctetBuffer *certificates, size_t cert_count, SequenceOfCertificate_t *internal)
{
    if (!internal)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    internal->list.count = internal->list.size = 0;
    internal->list.array                       = NULL;

    if (!certificates || cert_count == 0)
    {
        return 0;
    }

    // pre-allocate the array of pointers that is the core of the SEQUENCE structure.
    internal->list.array = calloc(cert_count, sizeof(Certificate_t *));
    internal->list.size  = cert_count;
    internal->list.count = 0;

    if (!internal->list.array)
    {
        oscms_log(LOG_ERR, "%s: Failed to allocate memory for Sequence of certificates", __func__);
        return -1;
    }

    for (size_t i = 0; i < cert_count; i++)
    {
        Certificate_t *cert = 0;
        if (decode_and_check(&certificates[i], &asn_DEF_Certificate, (void **)&cert) != 0)
        {
            asn_sequence_empty(&internal->list);
            oscms_log(LOG_ERR, "%s: Failed to decode certificate %zu of %zu", __func__, i, cert_count);
            return -1;
        }

        int rc = asn1c_add_to_sequence(&internal->list, cert);
        if (rc != 0)
        {
            ASN_STRUCT_FREE(asn_DEF_Certificate, cert);
            asn_sequence_empty(&internal->list);
            oscms_log(LOG_ERR, "%s: Failed to add certificate %zu of %zu", __func__, i, cert_count);
            return -1;
        }
    }
    return 0;
}

static int signatures_to_internal(
    const OscmsOctetBuffer *signatures, size_t signature_count, SequenceOfCtlSignatureSpdu *internal)
{
    if (!internal)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    (void)memset(internal, 0, sizeof(SequenceOfCtlSignatureSpdu));

    if (!signatures || signature_count == 0)
    {
        return 0;
    }

    // pre-allocate the array of pointers that is the core of the SEQUENCE structure.
    allocate_asn1c_sequence_of(signature_count, sizeof(CtlSignatureSpdu_t), (asn_anonymous_sequence_ *)internal);

    if (!internal->array)
    {
        oscms_log(LOG_ERR, "%s: Failed to allocate memory for Sequence of CtlSignatureSpdus", __func__);
        return -1;
    }

    for (size_t i = 0; i < signature_count; i++)
    {
        CtlSignatureSpdu_t *spdu = 0;
        if (decode_and_check(&signatures[i], &asn_DEF_CtlSignatureSpdu, (void **)&spdu) != 0)
        {
            asn_sequence_empty(internal);
            oscms_log(LOG_ERR, "%s: Failed to decode CtlSignatureSpdu %zu of %zu", __func__, i, signature_count);
            return -1;
        }
        (void)memcpy(internal->array[i], spdu, sizeof(CtlSignatureSpdu_t));
        (void)explicit_bzero(spdu, sizeof(*spdu));
        free(spdu);
    }

    return 0;
}

SO_EXPORT int oscms_multi_signed_ctl_to_internal(const OscmsMultiSignedCtl *multi_signed_ctl, void *internal_void)
{
    if (!multi_signed_ctl || !internal_void)
    {
        return -1;
    }

    MultiSignedCtl_t *internal = (MultiSignedCtl_t *)internal_void;
    memset(internal, 0, sizeof(MultiSignedCtl_t));

    internal->type = Ieee1609dot2dot1MsctlType_fullIeeeCtl;

    internal->tbsCtl.present = MultiSignedCtl__tbsCtl_PR_FullIeeeTbsCtl;

    if (full_ieee_ctl_to_internal(&multi_signed_ctl->full_ieee_tbs_ctl, &internal->tbsCtl.choice.FullIeeeTbsCtl) != 0)
    {
        return -1;
    }
    // From this point on need to use ASN_STRUCT_RESSET on any error to free memory

    internal->Unsigned.present = MultiSignedCtl__unsigned_PR_SequenceOfCertificate;
    if (unsigned_to_internal(
            multi_signed_ctl->certs, multi_signed_ctl->cert_count, &internal->Unsigned.choice.SequenceOfCertificate) !=
        0)
    {
        ASN_STRUCT_RESET(asn_DEF_MultiSignedCtl, internal);
        memset(internal, 0, sizeof(MultiSignedCtl_t));
        return -1;
    }

    if (signatures_to_internal(
            multi_signed_ctl->ctl_signatures,
            multi_signed_ctl->signature_count,
            (SequenceOfCtlSignatureSpdu *)&internal->signatures.list) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_MultiSignedCtl, internal);
        memset(internal, 0, sizeof(MultiSignedCtl_t));
        return -1;
    }

    return 0;
}

SO_EXPORT int oscms_encode_multi_signed_ctl(const OscmsMultiSignedCtl *multi_signed_ctl, OscmsOctetBuffer *encoded)
{
    if (!multi_signed_ctl || !encoded)
    {
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
                                .present = CertManagementPdu_PR_multiSignedCtl,
                                // .choice.multiSignedCtl initialized later
                                ._asn_ctx = {0},
                            },
                    },
                ._asn_ctx = {0},
            },
        ._asn_ctx = {0},
    };

    if (oscms_multi_signed_ctl_to_internal(multi_signed_ctl, &scms_pdu.content.choice.cert.choice.multiSignedCtl) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to convert MultiSignedCtl to internal representation", __func__);
        return -1;
    }

    if (check_and_encode(&scms_pdu, &asn_DEF_ScmsPdu, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);
        oscms_log(LOG_ERR, "%s: Failed to encode MultiSignedCtl as ScmsPdu", __func__);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_ScmsPdu, &scms_pdu);
    return 0;
}

SO_EXPORT int oscms_encode_multi_signed_ctl_spdu(const OscmsMultiSignedCtl *multi_signed_ctl, OscmsOctetBuffer *encoded)
{
    if (!multi_signed_ctl || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    oscms_octet_buffer_init_from_buffer(encoded, 0, 0);

    OscmsOctetBuffer pdu = {0};
    if (oscms_encode_multi_signed_ctl(multi_signed_ctl, &pdu) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to encode MultiSignedCtl as an ScmsPdu", __func__);
        return -1;
    }

    if (oscms_encode_dot2_data_unsecured(&pdu, encoded) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to encode MultiSignedCtl SPDU as a Dot2Data-Unsecured", __func__);
        oscms_empty_octet_buffer(&pdu);
        return -1;
    }

    oscms_empty_octet_buffer(&pdu);
    return 0;
}

SO_EXPORT int oscms_encode_full_ieee_ctl(const OscmsFullIeeeTbsCtl *full_ieee_ctl, OscmsOctetBuffer *encoded)
{
    if (!full_ieee_ctl || !encoded)
    {
        return -1;
    }

    // Initializing output
    oscms_octet_buffer_init(encoded);

    FullIeeeTbsCtl_t internal = {0};
    if (full_ieee_ctl_to_internal(full_ieee_ctl, &internal) != 0)
    {
        return -1;
    }
    if (check_and_encode(&internal, &asn_DEF_FullIeeeTbsCtl, encoded) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_FullIeeeTbsCtl, &internal);
        oscms_log(LOG_ERR, "%s: Failed to encode FullIeeeTbsCtl", __func__);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_FullIeeeTbsCtl, &internal);
    return 0;
}