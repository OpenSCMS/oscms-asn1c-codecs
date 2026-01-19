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

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "test_utils.hpp"

#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_tbs_certificate.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/Certificate.h"

TEST(TbsUnpack, NullArgs)
{
    OscmsTbsCertificate tbs;
    ToBeSignedCertificate tbs_cert;

    EXPECT_NE(0, oscms_tbs_certificate_from_internal(nullptr, nullptr));
    EXPECT_NE(0, oscms_tbs_certificate_from_internal(nullptr, &tbs));
    EXPECT_NE(0, oscms_tbs_certificate_from_internal(&tbs_cert, nullptr));
}

TEST(TbsUnpack, Success)
{
    std::vector<uint8_t> buffer;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", buffer), 0);

    Certificate_t *internal_cert = 0;
    asn_dec_rval_t rval =
        asn_decode(0, ATS_CANONICAL_OER, &asn_DEF_Certificate, (void **)&internal_cert, buffer.data(), buffer.size());
    ASSERT_EQ(rval.code, RC_OK);

    // asn_fprint(stderr, &asn_DEF_Certificate, internal_cert);
    asn_fprint(stderr, &asn_DEF_ToBeSignedCertificate, &internal_cert->toBeSigned);

    OscmsTbsCertificate tbs;
    int rc = oscms_tbs_certificate_from_internal(&internal_cert->toBeSigned, &tbs);
    EXPECT_EQ(rc, 0);

    oscms_empty_tbs_certificate(&tbs);
    ASN_STRUCT_FREE(asn_DEF_Certificate, internal_cert);
}

static int compare_octet_strings(const char *name, OCTET_STRING_t *theirs, OCTET_STRING_t *ours)
{
    if (theirs->size != ours->size)
    {
        fprintf(stderr, "size of %s differs: %zu != %zu \n", name, theirs->size, ours->size);
        return -1;
    }
    for (int i = 0; i < theirs->size; i++)
    {
        if (theirs->buf[i] != ours->buf[i])
        {
            fprintf(stderr, "%s buf differs at %d: %02x != %02x \n", name, i, theirs->buf[i], ours->buf[i]);
            return -1;
        }
    }
    return 0;
}
static int compare_internals(PublicEncryptionKey_t *theirs, PublicEncryptionKey_t *ours)
{
    int rc = 0;
    if (ours->supportedSymmAlg != theirs->supportedSymmAlg)
    {
        fprintf(stderr, "supportedSymmAlg differs: %ld != %ld \n", ours->supportedSymmAlg, theirs->supportedSymmAlg);
        return -1;
    }

    if (ours->publicKey.present != theirs->publicKey.present)
    {
        fprintf(stderr, "publicKey.present differs: %d != %d \n", ours->publicKey.present, theirs->publicKey.present);
        return -1;
    }

    EccP256CurvePoint_t *their_curve = &theirs->publicKey.choice.eciesNistP256;
    EccP256CurvePoint_t *our_curve   = &ours->publicKey.choice.eciesNistP256;

    if (their_curve->present != our_curve->present)
    {
        fprintf(stderr, "Curve Point present differs: %d != %d \n", their_curve->present, our_curve->present);
        return -1;
    }

    switch (their_curve->present)
    {
        case EccP256CurvePoint_PR_x_only:
            return compare_octet_strings("x_only", &their_curve->choice.x_only, &our_curve->choice.x_only);

        case EccP256CurvePoint_PR_fill:
            break;

        case EccP256CurvePoint_PR_compressed_y_0:
            return compare_octet_strings("y_0", &their_curve->choice.compressed_y_0, &our_curve->choice.compressed_y_0);

        case EccP256CurvePoint_PR_compressed_y_1:
            return compare_octet_strings("y_1", &their_curve->choice.compressed_y_1, &our_curve->choice.compressed_y_1);

        case EccP256CurvePoint_PR_uncompressedP256:
            if (compare_octet_strings(
                    "uncompressed.x", &their_curve->choice.uncompressedP256.x, &our_curve->choice.uncompressedP256.x) !=
                0)
                return -1;

            return compare_octet_strings(
                "uncompressed.y", &their_curve->choice.uncompressedP256.y, &our_curve->choice.uncompressedP256.y);
        default:
            fprintf(stderr, "Invalid Curve Point type %d \n", their_curve->present);
            return -1;
    }
    return 0;
}
// Round trip test
TEST(TbsPack, Success)
{
    std::vector<uint8_t> buffer;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", buffer), 0);

    Certificate_t *internal_cert = 0;
    asn_dec_rval_t rval =
        asn_decode(0, ATS_CANONICAL_OER, &asn_DEF_Certificate, (void **)&internal_cert, buffer.data(), buffer.size());
    ASSERT_EQ(rval.code, RC_OK);

    // asn_fprint(stderr, &asn_DEF_Certificate, internal_cert);
    // asn_fprint(stderr, &asn_DEF_ToBeSignedCertificate, &internal_cert->toBeSigned);

    OscmsTbsCertificate tbs;
    int rc = oscms_tbs_certificate_from_internal(&internal_cert->toBeSigned, &tbs);
    EXPECT_EQ(rc, 0);

    ToBeSignedCertificate_t internal_tbs;
    rc = oscms_internal_from_tbs_certificate(&tbs, &internal_tbs);
    EXPECT_EQ(rc, 0);

    EXPECT_EQ(compare_internals(internal_cert->toBeSigned.encryptionKey, internal_tbs.encryptionKey), 0);
    fprintf(stderr, "Internals compared OK\n");

    // asn_fprint(stderr, &asn_DEF_ToBeSignedCertificate, &internal_tbs);

    TrackedOctetBuffer internal_cert_tbs_encoded;
    ASSERT_EQ(
        check_and_encode(&internal_cert->toBeSigned, &asn_DEF_ToBeSignedCertificate, internal_cert_tbs_encoded), 0);

    TrackedOctetBuffer our_tbs_encoded;
    ASSERT_EQ(check_and_encode(&internal_tbs, &asn_DEF_ToBeSignedCertificate, our_tbs_encoded), 0);
    EXPECT_TRUE(oscms_octet_buffer_compare(internal_cert_tbs_encoded, our_tbs_encoded));

    oscms_empty_tbs_certificate(&tbs);
    ASN_STRUCT_FREE(asn_DEF_Certificate, internal_cert);
    ASN_STRUCT_RESET(asn_DEF_ToBeSignedCertificate, &internal_tbs);
}
