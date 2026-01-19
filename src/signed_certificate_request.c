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

#include <string.h>

#include "asn1c_utilities.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_certificate.h"
#include "oscms_codecs_api/oscms_ee_eca_cert_request.h"
#include "oscms_codecs_api/oscms_ee_ra_cert_request.h"
#include "oscms_codecs_api/oscms_utilities.h"
#include "oscms_codecs_api/signed_certificate_request.h"

#include "oscms_asn1c_generated/ScmsPdu.h"
#include "oscms_asn1c_generated/SignedCertificateRequest.h"

static int signer_identifier_from_internal(
    const SignerIdentifier_t *internal, OscmsSignerIdentifier *request, OscmsSequence *tracker)
{
    (void)memset(request, 0, sizeof(*request));
    request->type = (OscmsSignerIdentifierType)internal->present;
    if (request->type == OSCMS_SIGNER_IDENTIFIER_TYPE_DIGEST)
    {
        (void)memcpy(request->identifier.digest, internal->choice.digest.buf, sizeof(request->identifier.digest));
        return 0;
    }

    if (internal->choice.certificate.list.count <= 0)
    {
        return 0;
    }

    request->identifier.certificates.certificates =
        oscms_tracked_calloc(internal->choice.certificate.list.count, sizeof(OscmsCertificate), tracker);
    if (!request->identifier.certificates.certificates)
    {
        return -1;
    }

    request->identifier.certificates.certificates_count = internal->choice.certificate.list.count;

    for (size_t i = 0; i < request->identifier.certificates.certificates_count; i++)
    {
        if (oscms_certificate_from_internal(
                internal->choice.certificate.list.array[i], &request->identifier.certificates.certificates[i]) != 0)
        {
            return -1;
        }
    }

    return 0;
}

static int oscms_signed_certificate_request_from_internal(
    const SignedCertificateRequest_t *internal, OscmsSignedCertificateRequest *request)
{
    (void)memset(request, 0, sizeof(*request));
    if (internal->hashAlgorithmId > OSCMS_HASH_ALGORITHM_MAX)
    {
        oscms_log(LOG_ERR, "%s: Invalid hash algorithm", __func__);
        oscms_empty_signed_certificate_request(request);
        return -1;
    }
    request->hashAlgorithm = internal->hashAlgorithmId;

    if (signer_identifier_from_internal(&internal->signer, &request->signer, &request->allocations) != 0)
    {
        oscms_empty_signed_certificate_request(request);
        return -1;
    }

    if (oscms_signature_from_internal(&internal->signature, &request->signature, &request->allocations) != 0)
    {
        oscms_empty_signed_certificate_request(request);
        return -1;
    }

    switch (internal->tbsRequest.content.present)
    {
        case ScmsPdu__content_PR_aca_ra:
            oscms_log(LOG_ERR, "%s: We do not support ACA_RA PDUs", __func__);
            oscms_empty_signed_certificate_request(request);
            return -1;

        case ScmsPdu__content_PR_ee_ra:
            if (internal->tbsRequest.content.choice.ee_ra.present != EeRaInterfacePdu_PR_eeRaCertRequest &&
                internal->tbsRequest.content.choice.ee_ra.present !=
                    EeRaInterfacePdu_PR_eeRaSuccessorEnrollmentCertRequest)
            {
                oscms_log(LOG_ERR, "%s: Invalid EE_RA PDU for decoding", __func__);
                oscms_empty_signed_certificate_request(request);
                return -1;
            }

            if (internal->tbsRequest.content.choice.ee_ra.present == EeRaInterfacePdu_PR_eeRaCertRequest)
            {
                request->tbs_request.type = OSCMS_SCOPED_CERTIFICATE_REQUEST_TYPE_EE_RA;

                if (oscms_ee_ra_cert_request_from_internal(
                        &internal->tbsRequest.content.choice.ee_ra.choice.eeRaCertRequest,
                        &request->tbs_request.pdu.ee_ra) != 0)
                {
                    oscms_empty_signed_certificate_request(request);
                    return -1;
                }
                break; // We're done here
            }

            request->tbs_request.type = OSCMS_SCOPED_CERTIFICATE_REQUEST_TYPE_EE_RA_SUCCESSOR;

            if (check_and_encode(
                    &internal->tbsRequest.content.choice.ee_ra.choice.eeRaSuccessorEnrollmentCertRequest,
                    &asn_DEF_EeEcaCertRequestSpdu,
                    &request->tbs_request.pdu.ee_ra_successor) != 0)
            {
                oscms_empty_signed_certificate_request(request);
                oscms_log(LOG_ERR, "%s: Failed to re-encode EeEcaCertRequestSpdu", __func__);
                return -1;
            }

            if (oscms_track_other(request->tbs_request.pdu.ee_ra_successor.data, &request->allocations) != 0)
            {
                oscms_empty_octet_buffer(&request->tbs_request.pdu.ee_ra_successor);
                oscms_empty_signed_certificate_request(request);
                return -1;
            }
            break;

        case ScmsPdu__content_PR_eca_ee:
            if (internal->tbsRequest.content.choice.eca_ee.present != EcaEeInterfacePdu_PR_eeEcaCertRequest)
            {
                oscms_log(LOG_ERR, "%s: Invalid ECA_EE PDU for decoding", __func__);
                oscms_empty_signed_certificate_request(request);
                return -1;
            }

            request->tbs_request.type = OSCMS_SCOPED_CERTIFICATE_REQUEST_TYPE_ECA_EE;
            if (oscms_ee_eca_cert_request_from_internal(
                    &internal->tbsRequest.content.choice.eca_ee.choice.eeEcaCertRequest,
                    &request->tbs_request.pdu.eca_ee) != 0)
            {
                oscms_empty_signed_certificate_request(request);
                return -1;
            }
            break;

        default:
            oscms_empty_signed_certificate_request(request);
            oscms_log(LOG_ERR, "%s: Unknown or unsupported signed certificate request PDU", __func__);
            return -1;
    }

    return 0;
}

SO_EXPORT int oscms_decode_signed_certificate_request(
    const OscmsOctetBuffer *encoded, OscmsSignedCertificateRequest *request, OscmsOctetBuffer *encoded_tbs_request)
{
    if (!encoded || !request)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    SignedCertificateRequest_t *internal = NULL;
    if (decode_and_check(encoded, &asn_DEF_SignedCertificateRequest, (void **)&internal) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to decode SignedCertificateRequest", __func__);
        return -1;
    }

    if (encoded_tbs_request)
    {
        if (check_and_encode(&internal->tbsRequest, &asn_DEF_ScopedCertificateRequest, encoded_tbs_request) != 0)
        {
            ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, internal);
            oscms_log(LOG_ERR, "%s: Failed to encode TbsCertificateRequest", __func__);
            return -1;
        }
    }

    int rc = oscms_signed_certificate_request_from_internal(internal, request);

    if (rc != 0 && encoded_tbs_request)
    {
        oscms_empty_octet_buffer(encoded_tbs_request);
    }

    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, internal);
    return rc;
}
