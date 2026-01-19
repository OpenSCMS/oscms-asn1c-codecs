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

#include <stdlib.h>

#include "oscms_codecs_api/base_types.h"
#include "oscms_codecs_api/dot2_data_signed.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_certificate.h"

#include "oscms_asn1c_generated/AcaRaCertResponse.h"
#include "oscms_asn1c_generated/AcaRaCertResponseSpdu.h"
#include "oscms_asn1c_generated/CertificateManagementInformationStatusSpdu.h"
#include "oscms_asn1c_generated/CtlSignatureSpdu.h"
#include "oscms_asn1c_generated/EcaEeCertResponseSpdu.h"
#include "oscms_asn1c_generated/EeEcaCertRequestSpdu.h"
#include "oscms_asn1c_generated/EeRaDownloadRequestSpdu.h"
#include "oscms_asn1c_generated/Ieee1609Dot2Content.h"
#include "oscms_asn1c_generated/Ieee1609Dot2Data-Signed.h"
#include "oscms_asn1c_generated/Ieee1609Dot2Data-SignedEncrypted.h"
#include "oscms_asn1c_generated/RaEeCertAckSpdu.h"
#include "oscms_asn1c_generated/RaEeCertInfoSpdu.h"
#include "oscms_asn1c_generated/RaEeEnrollmentCertAckSpdu.h"

#include "asn1c_utilities.h"
#include "dot2_data_signed_utils.h"
#include "tbs_data.h"

// Map the enclosing type to the ASN.1 type descriptor
static asn_TYPE_descriptor_t *enclosing_type_to_descriptor[] = {
    &asn_DEF_Ieee1609Dot2Data_Signed_228P0,              // OSCMS_DOT2_DATA_SIGNED_TYPE_UNKNOWN
    &asn_DEF_CertificateManagementInformationStatusSpdu, // OSCMS_DOT2_DATA_SIGNED_TYPE_CERTIFICATE_MANAGEMENT_INFO_STATUS_SPDU
    &asn_DEF_CtlSignatureSpdu,                           // OSCMS_DOT2_DATA_SIGNED_TYPE_CTL_SIGNATURE_SPDU
    &asn_DEF_EcaEeCertResponseSpdu,                      // OSCMS_DOT2_DATA_SIGNED_TYPE_ECA_EE_CERT_RESPONSE_SPDU
    &asn_DEF_EeEcaCertRequestSpdu,                       // OSCMS_DOT2_DATA_SIGNED_TYPE_EE_ECA_CERT_REQUEST_SPDU
    &asn_DEF_RaEeCertAckSpdu,                            // OSCMS_DOT2_DATA_SIGNED_TYPE_RA_EE_CERT_ACK_SPDU
    &asn_DEF_RaEeEnrollmentCertAckSpdu,                  // OSCMS_DOT2_DATA_SIGNED_TYPE_RA_EE_ENROLLMENT_CERT_ACK_SPDU
    &asn_DEF_Ieee1609Dot2Data_SignedEncrypted_358P0, // OSCMS_DOT2_DATA_SIGNED_TYPE_DOT_DATA_SIGNED_ENCRYTPED_SPDU
    &asn_DEF_AcaRaCertResponseSpdu,                  // OSCMS_DOT2_DATA_SIGNED_TYPE_ACA_RA_CERT_RESPONSE_SPDU
    &asn_DEF_EeRaDownloadRequestSpdu,                // OSCMS_DOT2_DATA_SIGNED_TYPE_RA_EE_DOWNLOAD_REQUEST_SPDU
    &asn_DEF_RaEeCertInfoSpdu                        // OSCMS_DOT2_DATA_SIGNED_TYPE_RA_EE_CERT_INFO_SPDU
};

/**
 * Check arguments for valid values and null pointers
 *
 * @param[in] args A pointer to the input arguments
 *
 * @return 0 on success, and -1 on failure
 */
static int check_args(const OscmsDot2DataSignedArgs *args)
{
    if (args->enclosing_type > sizeof(enclosing_type_to_descriptor) / sizeof(asn_TYPE_descriptor_t *))
    {
        oscms_log(LOG_CRIT, "%s: Invalid enclosing type", __func__);
        return -1;
    }

    // Signer certificate buffer must be present and non-empty
    if (!args->signer_certificate.data || args->signer_certificate.length == 0)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided for signer certificate", __func__);
        return -1;
    }

    // Payload data buffer must be present and non-empty
    if (args->payload.length == 0 || !args->payload.data)
    {
        oscms_log(LOG_CRIT, "%s: NULL data provided for payload", __func__);
        return -1;
    }

    return 0;
}

/**
 * Complete the SignerIdentifier_t structure
 *
 * The SignerIdentifier_t structure contains the public key and private key
 *
 * @param[in] args A pointer to the input arguments
 * @param[in] signer A pointer to the SignerIdentifier_t structure
 *
 * @return 0 on success, -1 on error
 */
static int generate_signer(const OscmsDot2DataSignedArgs *args, SignerIdentifier_t *signer)
{
    (void)memset(signer, 0, sizeof(*signer));

    signer->present                = SignerIdentifier_PR_certificate;
    SequenceOfCertificate_t *certs = &signer->choice.certificate;

    // Decode the provided certificate so we can use it to complete the Signer field
    Certificate_t *decoded_cert = 0;

    if (decode_and_check(&args->signer_certificate, &asn_DEF_Certificate, (void **)&decoded_cert) != 0)
    {
        return -1;
    }

    // We simply add the decoded certificate to the list.
    // It will be freed when encoding is complete.
    int rc = asn1c_add_to_sequence(certs, decoded_cert);
    if (rc < 0)
    {
        ASN_STRUCT_FREE(asn_DEF_Certificate, decoded_cert);
        oscms_log(LOG_CRIT, "%s: asn1c_add_to_sequence failed", __func__);
        return -1;
    }
    return 0;
}

/**
 * Generate the SignedData_t structure
 *
 * The SignedData_t structure contains the hash algorithm, the ToBeSignedData_t structure,
 * and the SignerIdentifier_t structure and signature.
 *
 * @param[in] args A pointer to the input arguments
 * @param[out] signed_data A pointer to a pointer to the SignedData_t structure to be filled in
 *
 * @note The caller is responsible for freeing the SignedData_t structure and its contents
 *
 * @return 0 on success, -1 on failure
 */
int generate_signed_data(const OscmsDot2DataSignedArgs *args, SignedData_t **signed_data)
{
    if (!args || !signed_data)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    *signed_data = (SignedData_t *)calloc(1, sizeof(SignedData_t));
    if (!*signed_data)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for SignedData_t", __func__);
        return -1;
    }

    ToBeSignedData_t *tbs_data = {0};

    int rc = generate_tbs_data(&args->payload, args->payload_psid, &tbs_data);
    if (rc != 0)
    {
        free(*signed_data);
        *signed_data = NULL;
        return -1;
    }

    (*signed_data)->hashId  = HashAlgorithm_sha256;
    (*signed_data)->tbsData = tbs_data;

    // From here on , we let the codecs library release all resources on error.

    rc = generate_signer(args, &(*signed_data)->signer);
    if (rc < 0)
    {
        ASN_STRUCT_FREE(asn_DEF_SignedData, (*signed_data));
        *signed_data = NULL;
        return -1;
    }

    rc = oscms_signature_to_internal(&args->signature, &(*signed_data)->signature);
    if (rc < 0)
    {
        ASN_STRUCT_FREE(asn_DEF_SignedData, (*signed_data));
        *signed_data = NULL;
        return -1;
    }

    return 0;
}

// Public functions

SO_EXPORT int oscms_encode_dot2_data_signed(const OscmsDot2DataSignedArgs *args, OscmsOctetBuffer *buffer)
{
    if (!args || !buffer)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    if (check_args(args) < 0)
    {
        return -1;
    }

    const asn_TYPE_descriptor_t *enclosing_pdu_type = enclosing_type_to_descriptor[args->enclosing_type];

    // take care of malloc up front
    Ieee1609Dot2Content_t *content = (Ieee1609Dot2Content_t *)calloc(1, sizeof(Ieee1609Dot2Content_t));
    if (!content)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for Ieee1609Dot2Content_t", __func__);
        return -1;
    }

    SignedData_t *signed_data = {0};

    int rc = generate_signed_data(args, &signed_data);
    if (rc != 0)
    {
        free(content);
        return -1; // The function takes care of all other resource cleanup and logging
    }

    // From this point on we need to recursively release the SPDU and all its children
    // on an error, so ensure the it's in the correct state.

    content->present           = Ieee1609Dot2Content_PR_signedData;
    content->choice.signedData = signed_data;

    Ieee1609Dot2Data_t spdu = {
        .protocolVersion = 3,
        .content         = content,
        ._asn_ctx        = {0},
    };

    if (check_and_encode(&spdu, enclosing_pdu_type, buffer) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Data, &spdu);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_Ieee1609Dot2Data, &spdu);
    return 0;
}

SO_EXPORT int oscms_decode_dot2_data_signed(
    const OscmsOctetBuffer *buffer, OscmsDot2DataSignedType enclosing_type, OscmsSignedData *signed_data)
{
    if (!buffer || !signed_data || !buffer->data || !buffer->length)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    if (enclosing_type >= sizeof(enclosing_type_to_descriptor) / sizeof(asn_TYPE_descriptor_t *))
    {
        oscms_log(LOG_CRIT, "%s: Invalid enclosing type", __func__);
        return -1;
    }

    const asn_TYPE_descriptor_t *enclosing_pdu_type = enclosing_type_to_descriptor[enclosing_type];
    Ieee1609Dot2Data_t *spdu                        = 0;

    if (decode_and_check(buffer, enclosing_pdu_type, (void **)&spdu) != 0)
    {
        return -1;
    }
    // From this point on we need to recursively release the SPDU and all its children
    // on an error, so ensure the it's in the correct state.

    if (spdu->content->present != Ieee1609Dot2Content_PR_signedData)
    {
        oscms_log(LOG_ERR, "%s: Expected Ieee1609Dot2Content_PR_signedData, got %d", __func__, spdu->content->present);
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
        return -1;
    }

    SignedData_t *internal_signed_data = spdu->content->choice.signedData;
    if (!internal_signed_data)
    {
        oscms_log(LOG_ERR, "%s: Expected SignedData_t, got NULL", __func__);
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
        return -1;
    }

    // Finally begin to populate the output
    memset(signed_data, 0, sizeof(*signed_data));

    int rc = oscms_octet_buffer_init_from_octet_string(
        &internal_signed_data->tbsData->payload->data->content->choice.unsecuredData, &signed_data->payload, 0);
    if (rc != 0)
    {
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
        return -1;
    }

    signed_data->payload_psid = internal_signed_data->tbsData->headerInfo.psid;

    rc = oscms_signature_from_internal(&internal_signed_data->signature, &signed_data->signature, 0);
    if (rc != 0)
    {
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
        return -1;
    }

    // Extract the signer's certificate
    if (internal_signed_data->signer.present != SignerIdentifier_PR_certificate)
    {
        oscms_log(
            LOG_ERR,
            "%s: Expected SignerIdentifier_PR_certificate, got %d",
            __func__,
            internal_signed_data->signer.present);
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
        return -1;
    }

    if (internal_signed_data->signer.choice.certificate.list.count != 1)
    {
        oscms_log(
            LOG_ERR,
            "%s: Expected 1 certificate for the signer, got %d",
            __func__,
            internal_signed_data->signer.choice.certificate.list.count);
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
        return -1;
    }

    rc = oscms_certificate_from_internal(
        internal_signed_data->signer.choice.certificate.list.array[0], &signed_data->signer_certificate);
    if (rc != 0)
    {
        ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
        return -1;
    }

    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
    return 0;
}
