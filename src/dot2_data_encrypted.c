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

#include "oscms_codecs_api/dot2_data_encrypted.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ecc_curve.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "oscms_asn1c_generated/EeEcaCertRequest.h"
#include "oscms_asn1c_generated/EeRaCertRequestSpdu.h"
#include "oscms_asn1c_generated/EeRaSuccessorEnrollmentCertRequestSpdu.h"
#include "oscms_asn1c_generated/Ieee1609Dot2Data-Encrypted.h"

#include "asn1c_utilities.h"
#include "dot2_data_encrypted_utils.h"

// Maps the enclosing type to the corresponding ASN1C type defintion for encoding and decoding
static asn_TYPE_descriptor_t *enclosing_type_to_descriptor[] = {
    &asn_DEF_Ieee1609Dot2Data_Encrypted_276P0,
    &asn_DEF_EeRaCertRequestSpdu,
    &asn_DEF_EeRaCertRequestSpdu,
    &asn_DEF_EeRaSuccessorEnrollmentCertRequestSpdu,
    &asn_DEF_Ieee1609Dot2Data_Encrypted_276P0,
};

static int decode_ciphertext(
    const SymmetricCiphertext_t *ciphertext_internal, OscmsSymmetricCiphertext *decoded, OscmsSequence *tracker)
{
    if (!ciphertext_internal || !decoded)
    {
        return -1;
    }
    decoded->type = (OscmsSymmCiphertextType)ciphertext_internal->present;
    if (oscms_octet_buffer_init_from_octet_string(
            &ciphertext_internal->choice.aes128ccm.ccmCiphertext, &decoded->cipher_text, tracker) != 0)
    {
        return -1;
    }

    if (oscms_octet_buffer_init_from_octet_string(
            &ciphertext_internal->choice.aes128ccm.nonce, &decoded->nonce, tracker) != 0)
    {
        return -1;
    }

    return 0;
}

static int decode_symmetric_recipient(
    const SymmRecipientInfo_t *recipient_internal, OscmsRecipientInfo *decoded, OscmsSequence *tracker)
{
    (void)memcpy(decoded->value.symmetric.recipient_id, recipient_internal->recipientId.buf, sizeof(OscmsHashedId8));

    return decode_ciphertext(&recipient_internal->encKey, &decoded->value.symmetric.encryption_key, tracker);
}

static int decode_public_recipient(
    const PKRecipientInfo_t *recipient_internal, OscmsRecipientInfo *decoded, OscmsSequence *tracker)
{
    (void)memcpy(decoded->value.public_key.recipient_id, recipient_internal->recipientId.buf, sizeof(OscmsHashedId8));
    OscmsEncryptedDataEncryptionKey *key = &decoded->value.public_key.encryption_key;
    key->type                            = (OscmsEdekType)recipient_internal->encKey.present;

    // EciesP256EncryptedKey and EcesP256EncryptedKey are identical so we can just use the EciesP256EncryptedKey and
    // eciseNistP256 member but we need to get the curvepoint type right
    //
    // This maps the EDEK type to the curvepoint type
    const OscmsEccPointCurveType curve_point_type_map[] = {
        OSCMS_ECC_POINT_CURVE_TYPE_NONE,
        OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256,
        OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P256,
        OSCMS_ECC_POINT_CURVE_TYPE_SM2,
    };

    if (key->type >= sizeof(curve_point_type_map) / sizeof(curve_point_type_map[0]) || key->type < 0)
    {
        oscms_log(LOG_ERR, "%s: Unsupported ECC point curve type in certificate", __func__);
        return -1;
    }

    const EciesP256EncryptedKey_t *key_internal = &recipient_internal->encKey.choice.eciesNistP256;
    if (oscms_ecc_curve_point_from_internal(
            &key_internal->v, curve_point_type_map[key->type], &key->public_key, tracker) != 0)
    {
        return -1;
    }

    if (oscms_octet_buffer_init_from_octet_string(&key_internal->c, &key->symmetric_key, tracker) != 0)
    {
        return -1;
    }
    if (oscms_octet_buffer_init_from_octet_string(&key_internal->t, &key->tag, tracker) != 0)
    {
        return -1;
    }

    return 0;
}
static int decode_recipients(const SequenceOfRecipientInfo_t *recipients_internal, OscmsDot2DataEncrypted *decoded)
{
    if (!recipients_internal || !decoded)
    {
        return -1;
    }

    if (recipients_internal->list.count <= 0)
    {
        oscms_log(LOG_ERR, "%s: Recipients list is empty or negative; %d", __func__, recipients_internal->list.count);
        return -1;
    }

    if (SIZE_MAX / sizeof(OscmsRecipientInfo) < (size_t)recipients_internal->list.count)
    {
        oscms_log(LOG_ERR, "%s: Recipients list is too large", __func__);
        return -1;
    }

    decoded->recipient_count = recipients_internal->list.count;
    decoded->recipients =
        oscms_tracked_calloc(decoded->recipient_count, sizeof(OscmsRecipientInfo), &decoded->allocations);

    if (!decoded->recipients)
    {
        return -1;
    }

    for (size_t i = 0; i < decoded->recipient_count; i++)
    {
        OscmsRecipientInfo *recipient             = &decoded->recipients[i];
        const RecipientInfo_t *recipient_internal = recipients_internal->list.array[i];

        if (!recipient_internal)
        {
            oscms_log(LOG_ERR, "%s: Recipient %zu is NULL", __func__, i);
            return -1;
        }
        recipient->type = (OscmsRecipientInfoType)recipient_internal->present;

        switch (recipient->type)
        {
            case OSCMS_RECIPIENT_INFO_TYPE_PSK:
                (void)memcpy(
                    &recipient->value.psk, &recipient_internal->choice.pskRecipInfo.buf, sizeof(OscmsHashedId8));
                break;

            case OSCMS_RECIPIENT_INFO_TYPE_SYMMETRIC:
                if (decode_symmetric_recipient(
                        &recipient_internal->choice.symmRecipInfo, recipient, &decoded->allocations) != 0)
                {
                    return -1;
                }
                break;
            default: // Others (constraint chck guarantees the type is valid)
                if (decode_public_recipient(
                        &recipient_internal->choice.certRecipInfo, recipient, &decoded->allocations) != 0)
                {
                    return -1;
                }
        }
    }
    return 0;
}

SO_EXPORT int oscms_decode_dot2_data_encrypted(
    const OscmsOctetBuffer *encoded,
    OscmsDot2DataEncryptedType enclosing_type,
    OscmsDot2DataEncrypted *dot2_data_encrypted)
{
    if (!dot2_data_encrypted || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    if (enclosing_type >= sizeof(enclosing_type_to_descriptor) / sizeof(asn_TYPE_descriptor_t *))
    {
        oscms_log(LOG_CRIT, "%s: Invalid enclosing type", __func__);
        return -1;
    }

    (void)memset(dot2_data_encrypted, 0, sizeof(OscmsDot2DataEncrypted));
    dot2_data_encrypted->enclosing_type = enclosing_type;

    const asn_TYPE_descriptor_t *enclosing_pdu_type = enclosing_type_to_descriptor[enclosing_type];
    Ieee1609Dot2Data_t *spdu                        = 0;

    if (decode_and_check(encoded, enclosing_pdu_type, (void **)&spdu) != 0)
    {
        return -1;
    }

    if (decode_recipients(&spdu->content->choice.encryptedData.recipients, dot2_data_encrypted) != 0)
    {
        goto error_cleanup;
    }

    if (decode_ciphertext(
            &spdu->content->choice.encryptedData.ciphertext,
            &dot2_data_encrypted->ciphertext,
            &dot2_data_encrypted->allocations) != 0)
    {
        goto error_cleanup;
    }

    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
    return 0;

error_cleanup:
    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data, spdu);
    oscms_empty_dot2_data_encrypted(dot2_data_encrypted);
    return -1;
}
////////////////////////////////////////////////////////////////////////////////////
//                               Encoding routines                                //
////////////////////////////////////////////////////////////////////////////////////

static int encode_symmetrical_ciphertext(const OscmsSymmetricCiphertext *ciphertext, SymmetricCiphertext_t *internal)
{
    internal->present = (SymmetricCiphertext_PR)ciphertext->type;

    OCTET_STRING_t *ciphertext_internal = 0;
    OCTET_STRING_t *nonce_internal      = 0;

    if (ciphertext->type == OSCMS_SYMMETRIC_CIPHERTEXT_AES128)
    {
        ciphertext_internal = &internal->choice.aes128ccm.ccmCiphertext;
        nonce_internal      = &internal->choice.aes128ccm.nonce;
    }
    else if (ciphertext->type == OSCMS_SYMMETRIC_CIPHERTEXT_SM4_CCM)
    {
        ciphertext_internal = &internal->choice.sm4Ccm.ccmCiphertext;
        nonce_internal      = &internal->choice.sm4Ccm.nonce;
    }
    else
    {
        oscms_log(LOG_ERR, "%s: Invalid ciphertext type", __func__);
        return -1;
    }

    if (oscms_octet_string_init_from_octet_buffer(&ciphertext->cipher_text, ciphertext_internal) != 0)
    {
        return -1;
    }

    return oscms_octet_string_init_from_octet_buffer(&ciphertext->nonce, nonce_internal);
}

static int encode_public_recipient(const OscmsRecipientInfo *recipient, PKRecipientInfo_t *internal)
{
    if (oscms_octet_string_init_from_buffer(
            recipient->value.public_key.recipient_id, sizeof(OscmsHashedId8), &internal->recipientId) != 0)
    {
        return -1;
    }

    const OscmsEncryptedDataEncryptionKey *ede_key = &recipient->value.public_key.encryption_key;

    internal->encKey.present              = (EncryptedDataEncryptionKey_PR)ede_key->type;
    EciesP256EncryptedKey_t *key_internal = &internal->encKey.choice.eciesNistP256;
    if (oscms_internal_from_ecc_curve_point(&ede_key->public_key, &key_internal->v) != 0)
    {
        return -1;
    }
    if (oscms_octet_string_init_from_octet_buffer(&ede_key->symmetric_key, &key_internal->c) != 0)
    {
        return -1;
    }
    if (oscms_octet_string_init_from_octet_buffer(&ede_key->tag, &key_internal->t) != 0)
    {
        return -1;
    }

    return 0;
}

static int encode_recipient_info(
    const OscmsRecipientInfo *recipients, size_t recipient_count, SequenceOfRecipientInfo_t *internal)
{
    if (!recipients || recipient_count == 0 || recipient_count > INT_MAX)
    {
        oscms_log(LOG_ERR, "%s: Recipients list is empty or too large: %zu", __func__, recipient_count);
        return -1;
    }

    int rc = 0;

    internal->list.array = 0;
    internal->list.count = internal->list.size = 0;

    for (size_t i = 0; i < recipient_count; i++)
    {
        RecipientInfo_t *recipient_internal = calloc(1, sizeof(RecipientInfo_t));
        if (!recipient_internal)
        {
            return -1;
        }
        const OscmsRecipientInfo *recipient = &recipients[i];

        switch (recipient->type)
        {
            case OSCMS_RECIPIENT_INFO_TYPE_PSK:

                rc = oscms_octet_string_init_from_buffer(
                    recipient->value.psk, sizeof(recipient->value.psk), &recipient_internal->choice.pskRecipInfo);
                if (rc != 0)
                {
                    free(recipient_internal);
                    return -1;
                }
                break;

            case OSCMS_RECIPIENT_INFO_TYPE_SYMMETRIC:
                rc = oscms_octet_string_init_from_buffer(
                    recipient->value.symmetric.recipient_id,
                    sizeof(recipient->value.symmetric.recipient_id),
                    &recipient_internal->choice.symmRecipInfo.recipientId);
                if (rc != 0)
                {
                    free(recipient_internal);
                    return -1;
                }

                if (encode_symmetrical_ciphertext(
                        &recipient->value.symmetric.encryption_key, &recipient_internal->choice.symmRecipInfo.encKey) !=
                    0)
                {
                    (void)explicit_bzero(recipient_internal, sizeof(*recipient_internal));
                    free(recipient_internal);
                    return -1;
                }
                break;

            case OSCMS_RECIPIENT_INFO_TYPE_CERTIFICATE:
            case OSCMS_RECIPIENT_INFO_TYPE_SIGNED:
            case OSCMS_RECIPIENT_INFO_TYPE_REK:
                if (encode_public_recipient(recipient, &recipient_internal->choice.certRecipInfo) != 0)
                {
                    free(recipient_internal);
                    return -1;
                }
                break;

            default:
                oscms_log(LOG_ERR, "%s: Invalid recipient type", __func__);
                free(recipient_internal);
                return -1;
        }
        recipient_internal->present = (RecipientInfo_PR)recipient->type;

        rc = asn1c_add_to_sequence(internal, recipient_internal);
        if (rc != 0)
        {
            (void)explicit_bzero(recipient_internal, sizeof(*recipient_internal));
            free(recipient_internal);
            oscms_log(LOG_ERR, "%s: Failed to add recipient", __func__);
            return -1;
        }
    }
    return 0;
}

int encode_encrypted_data(const OscmsDot2DataEncrypted *dot2_data_encrypted, EncryptedData_t *internal)
{
    if (!dot2_data_encrypted || !internal)
    {
        return -1;
    }

    if (encode_recipient_info(
            dot2_data_encrypted->recipients, dot2_data_encrypted->recipient_count, &internal->recipients) != 0)
    {
        return -1;
    }

    return encode_symmetrical_ciphertext(&dot2_data_encrypted->ciphertext, &internal->ciphertext);
}

SO_EXPORT int oscms_encode_dot2_data_encrypted(
    const OscmsDot2DataEncrypted *dot2_data_encrypted, OscmsOctetBuffer *encoded_spdu)
{
    if (!dot2_data_encrypted || !encoded_spdu)
    {
        return -1;
    }

    if (dot2_data_encrypted->enclosing_type > sizeof(enclosing_type_to_descriptor) / sizeof(asn_TYPE_descriptor_t *))
    {
        oscms_log(LOG_CRIT, "%s: Invalid enclosing type", __func__);
        return -1;
    }

    asn_TYPE_descriptor_t *enclosing_pdu_type = enclosing_type_to_descriptor[dot2_data_encrypted->enclosing_type];
    encoded_spdu->length                      = 0;
    encoded_spdu->data                        = NULL;

    // take care of malloc up front
    Ieee1609Dot2Content_t *content = (Ieee1609Dot2Content_t *)calloc(1, sizeof(Ieee1609Dot2Content_t));
    if (!content)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for Ieee1609Dot2Content_t", __func__);
        return -1;
    }

    // From this point on we need to recursively release the SPDU and all its children
    // on an error, so ensure the it's in the correct state.

    content->present = Ieee1609Dot2Content_PR_encryptedData;

    Ieee1609Dot2Data_t spdu = {
        .protocolVersion = 3,
        .content         = content,
        ._asn_ctx        = {0},
    };

    if (encode_encrypted_data(dot2_data_encrypted, &content->choice.encryptedData) != 0)
    {
        ASN_STRUCT_RESET(*enclosing_pdu_type, &spdu);
        return -1;
    }

    if (check_and_encode(&spdu, enclosing_pdu_type, encoded_spdu) != 0)
    {
        ASN_STRUCT_RESET(*enclosing_pdu_type, &spdu);
        return -1;
    }

    ASN_STRUCT_RESET(*enclosing_pdu_type, &spdu);
    return 0;
}
