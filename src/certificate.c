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
#include "oscms_codecs_api/oscms_certificate.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "oscms_asn1c_generated/Certificate.h"

#include "asn1c_utilities.h"

int oscms_certificate_from_internal(const void *internal_certificate_void, OscmsCertificate *decoded_certificate)
{
    if (!internal_certificate_void || !decoded_certificate)
    {
        return -1;
    }

    const Certificate_t *internal_certificate = (const Certificate_t *)internal_certificate_void;

    // Initialize the decoded certificate to an empty state
    memset(decoded_certificate, 0, sizeof(*decoded_certificate));
    oscms_tbs_certificate_init(&decoded_certificate->tbs_certificate);

    if (internal_certificate->type > OSCMS_CERTIFICATE_TYPE_MAX)
    {
        oscms_log(LOG_CRIT, "%s: Unknown or unsupported certificate type", __func__);
        return -1;
    }

    decoded_certificate->type                   = (OscmsCertificateType)internal_certificate->type;
    decoded_certificate->issuer_identifier_type = (OscmsIssuerIdentifierType)internal_certificate->issuer.present;

    if (decoded_certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SELF)
    {
        if (internal_certificate->issuer.choice.self > OSCMS_HASH_ALGORITHM_MAX)
        {
            oscms_log(LOG_CRIT, "%s: Unknown or unsupported hash algorithm", __func__);
            return -1;
        }

        decoded_certificate->issuer_identifier.hash_algorithm =
            (OscmsHashAlgorithm)internal_certificate->issuer.choice.self;
    }
    else
    {
        const HashedId8_t *decoded_hash = 0;
        switch (internal_certificate->issuer.present)
        {
            case IssuerIdentifier_PR_sha256AndDigest:
                decoded_hash = &internal_certificate->issuer.choice.sha256AndDigest;
                break;

            case IssuerIdentifier_PR_sha384AndDigest:
                decoded_hash = &internal_certificate->issuer.choice.sha384AndDigest;
                break;

            case IssuerIdentifier_PR_sm3AndDigest:
                decoded_hash = &internal_certificate->issuer.choice.sm3AndDigest;
                break;

            default:
                oscms_log(LOG_CRIT, "%s: Unknown or unsupported issuer identifier type", __func__);
                return -1;
        }
        if (decoded_hash->size != sizeof(OscmsHashedId8))
        {
            oscms_log(LOG_CRIT, "%s: Wrong hash size", __func__);
            return -1;
        }
        memcpy(decoded_certificate->issuer_identifier.hash, decoded_hash->buf, decoded_hash->size);
    }

    // Unpack the embedded ToBeSignedCertificate
    int rc =
        oscms_tbs_certificate_from_internal(&internal_certificate->toBeSigned, &decoded_certificate->tbs_certificate);

    if (rc != 0)
    {
        oscms_empty_certificate(decoded_certificate);
        return -1;
    }

    // Unpack the signature

    if (internal_certificate->signature)
    {
        decoded_certificate->signature =
            oscms_tracked_malloc(sizeof(OscmsSignature), &decoded_certificate->allocations);
        if (!decoded_certificate->signature)
        {
            oscms_empty_certificate(decoded_certificate);
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for signature", __func__);
            return -1;
        }

        if (oscms_signature_from_internal(
                internal_certificate->signature, decoded_certificate->signature, &decoded_certificate->allocations) !=
            0)
        {
            oscms_empty_certificate(decoded_certificate);
            oscms_log(LOG_ERR, "%s: Failed to unpack signature", __func__);
            return -1;
        }
    }

    return 0;
}

int oscms_internal_from_certificate(const OscmsCertificate *certificate, void *internal_void)
{
    if (!certificate || !internal_void)
    {
        return -1;
    }

    Certificate_t *internal = (Certificate_t *)internal_void;
    (void)memset(internal, 0, sizeof(*internal));

    internal->version = 3;

    // Check the highest level constraints, based on certificate type
    if (certificate->type == OSCMS_CERTIFICATE_TYPE_EXPLICIT)
    {
        // See Ieee 1609.2-2022 specification 6.4.6
        //
        // An explicit certificate must have a signature, and the VKI must contain a verification key.
        //
        if (!certificate->signature)
        {
            oscms_log(LOG_ERR, "%s: Explicit certificate missing signature", __func__);
            return -1;
        }
        if (certificate->tbs_certificate.verify_key_indicator.type != OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_KEY)
        {
            oscms_log(LOG_ERR, "%s: Explicit certificate missing verification key", __func__);
            return -1;
        }
        internal->type = CertificateType_explicit;
    }
    else if (certificate->type == OSCMS_CERTIFICATE_TYPE_IMPLICIT)
    {
        // See Ieee 1609.2-2022 specification 6.4.5
        //
        // An implicit certificate must not have a signature, and the VKI must contain a reconstruction value.
        //
        if (certificate->signature)
        {
            oscms_log(LOG_ERR, "%s: Implicit certificate should not have a signature", __func__);
            return -1;
        }
        if (certificate->tbs_certificate.verify_key_indicator.type !=
            OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_RECONSTRUCTION)
        {
            oscms_log(LOG_ERR, "%s: implicit certificate missing reconstruction value", __func__);
            return -1;
        }
        internal->type = CertificateType_implicit;
    }
    else
    {
        oscms_log(LOG_ERR, "%s: Unknown or unsupported certificate type %d", __func__, certificate->type);
        return -1;
    }

    // Issuer Identifier
    if (certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SELF)
    {
        internal->issuer.present     = IssuerIdentifier_PR_self;
        internal->issuer.choice.self = certificate->issuer_identifier.hash_algorithm;
    }
    else if (
        certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SHA256_AND_DIGEST ||
        certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SHA384_AND_DIGEST ||
        certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SM3_AND_DIGEST)
    {
        internal->issuer.present = (IssuerIdentifier_PR)certificate->issuer_identifier_type;
        // All of these are just a HashedId8, but allow for layout differences in the union
        HashedId8_t *buf = 0;
        if (certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SHA256_AND_DIGEST)
        {
            buf = &internal->issuer.choice.sha256AndDigest;
        }
        else if (certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SHA384_AND_DIGEST)
        {
            buf = &internal->issuer.choice.sha384AndDigest;
        }
        else if (certificate->issuer_identifier_type == OSCMS_ISSUER_IDENTIFIER_SM3_AND_DIGEST)
        {
            buf = &internal->issuer.choice.sm3AndDigest;
        }

        if (oscms_octet_string_init_from_buffer(
                certificate->issuer_identifier.hash, sizeof(certificate->issuer_identifier.hash), buf) != 0)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for issuer hash", __func__);
            goto cleanup;
        }
    }
    else
    {
        oscms_log(LOG_ERR, "%s: Unknown issuer identifier type %d", __func__, certificate->issuer_identifier_type);
        goto cleanup;
    }

    // ToBeSignedCertificate
    if (oscms_internal_from_tbs_certificate(&certificate->tbs_certificate, &internal->toBeSigned) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to pack ToBeSignedCertificate", __func__);
        goto cleanup;
    }

    // Signature
    if (certificate->signature)
    {
        internal->signature = malloc(sizeof(Signature_t));
        if (!internal->signature)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for signature", __func__);
            goto cleanup;
        }
        if (oscms_signature_to_internal(certificate->signature, internal->signature) != 0)
        {
            oscms_log(LOG_ERR, "%s: Failed to pack signature", __func__);
            goto cleanup;
        }
    }
    else
    {
        internal->signature = 0;
    }

    return 0;

cleanup:
    ASN_STRUCT_RESET(asn_DEF_Certificate, internal);
    (void)memset(internal, 0, sizeof(*internal));
    return -1;
}

/**
 * Decode the provided COER-encoded certificate
 *
 * @param[in] encoded_certificate A pointer to the input COER-encoded Certificate_t
 * @param[out] decoded_certificate A pointer to the output OscmsCertificate
 *
 * @return 0 on success, and the provided `decoded_certificate` will contain the decoded certificate
 */
SO_EXPORT int oscms_decode_certificate(
    const OscmsOctetBuffer *encoded_certificate, OscmsCertificate *decoded_certificate)
{
    if (!encoded_certificate || !decoded_certificate || !encoded_certificate->data || !encoded_certificate->length)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    // Decode the provided certificate so we can use it to complete the Signer field
    Certificate_t *internal_certificate = 0;
    if (decode_and_check(encoded_certificate, &asn_DEF_Certificate, (void **)&internal_certificate) != 0)
    {
        return -1;
    }

    int rc = oscms_certificate_from_internal(internal_certificate, decoded_certificate);
    ASN_STRUCT_FREE(asn_DEF_Certificate, internal_certificate);

    if (rc != 0)
    {
        oscms_empty_certificate(decoded_certificate);
    }

    return rc;
}

SO_EXPORT int oscms_encode_certificate(const OscmsCertificate *certificate, OscmsOctetBuffer *encoded_certificate)
{
    if (!certificate || !encoded_certificate)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    Certificate_t internal = {0};
    oscms_octet_buffer_init(encoded_certificate);

    if (oscms_internal_from_certificate(certificate, &internal) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_Certificate, &internal);
        return -1;
    }

    // Finally, check constraints and encode
    if (check_and_encode(&internal, &asn_DEF_Certificate, encoded_certificate) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_Certificate, &internal);
        oscms_empty_octet_buffer(encoded_certificate);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_Certificate, &internal);
    return 0;
}

SO_EXPORT int oscms_encode_tbs_certificate(const OscmsCertificate *certificate, OscmsOctetBuffer *encoded_certificate)
{
    if (!certificate || !encoded_certificate)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    ToBeSignedCertificate_t internal = {0};

    // ToBeSignedCertificate
    if (oscms_internal_from_tbs_certificate(&certificate->tbs_certificate, &internal) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to pack ToBeSignedCertificate", __func__);
        return -1;
    }

    if (check_and_encode(&internal, &asn_DEF_ToBeSignedCertificate, encoded_certificate) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_ToBeSignedCertificate, &internal);
        return -1;
    }

    ASN_STRUCT_RESET(asn_DEF_ToBeSignedCertificate, &internal);
    return 0;
}
