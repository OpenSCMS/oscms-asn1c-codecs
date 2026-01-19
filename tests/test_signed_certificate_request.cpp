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

#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/signed_certificate_request.h"

#include "asn1c_utilities.h"

#include "test_utils.hpp"

#include "oscms_asn1c_generated/Ieee1609Dot2Data-SignedCertRequest.h"
#include "oscms_asn1c_generated/SignedCertificateRequest.h"

typedef Ieee1609Dot2Data_SignedCertRequest_290P0_t Ieee1609Dot2Data_SignedCertRequest_t;
#define asn_DEF_Ieee1609Dot2Data_SignedCertRequest asn_DEF_Ieee1609Dot2Data_SignedCertRequest_290P0
;
// std::vector<uint8_t> raw_data;
// ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);
// EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);

TEST(SignedCertificateRequest, DumpDataFile)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/DecryptedEeRaCertRequestSpdu.dat", raw_data), 0);

    TrackedOctetBuffer payload;
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(payload, raw_data.data(), raw_data.size()), 0);

    Ieee1609Dot2Data_SignedCertRequest_t *asn1c_decoded = {};
    ASSERT_EQ(decode_and_check(payload, &asn_DEF_Ieee1609Dot2Data_SignedCertRequest, (void **)&asn1c_decoded), 0);
    ASSERT_NE(asn1c_decoded, nullptr);

    asn_fprint(stderr, &asn_DEF_Ieee1609Dot2Data_SignedCertRequest, asn1c_decoded);

    SignedCertificateRequest_t *asn1_signed_cert_request = {};
    TrackedOctetBuffer payload2;

    oscms_octet_buffer_init_from_octet_string(&asn1c_decoded->content->choice.signedCertificateRequest, payload2, 0);

    ASSERT_EQ(decode_and_check(payload2, &asn_DEF_SignedCertificateRequest, (void **)&asn1_signed_cert_request), 0);

    asn_fprint(stderr, &asn_DEF_SignedCertificateRequest, asn1_signed_cert_request);
    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, asn1_signed_cert_request);
    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data_SignedCertRequest, asn1c_decoded);
}

TEST(SignedCertificateRequest, DecodeSuccess)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/DecryptedEeRaCertRequestSpdu.dat", raw_data), 0);

    OscmsOctetBuffer payload;
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(&payload, raw_data.data(), raw_data.size()), 0);

    Ieee1609Dot2Data_SignedCertRequest_t *asn1c_decoded = {};
    ASSERT_EQ(decode_and_check(&payload, &asn_DEF_Ieee1609Dot2Data_SignedCertRequest, (void **)&asn1c_decoded), 0);
    ASSERT_NE(asn1c_decoded, nullptr);

    SignedCertificateRequest_t *asn1_signed_cert_request = {};
    OscmsOctetBuffer payload2                            = {};
    ASSERT_EQ(
        0,
        oscms_octet_buffer_init_from_octet_string(
            &asn1c_decoded->content->choice.signedCertificateRequest, &payload2, 0));

    ASSERT_EQ(decode_and_check(&payload2, &asn_DEF_SignedCertificateRequest, (void **)&asn1_signed_cert_request), 0);

    OscmsSignedCertificateRequest signed_certificate_request = {};
    OscmsOctetBuffer payload3                                = {};
    EXPECT_EQ(oscms_decode_signed_certificate_request(&payload2, &signed_certificate_request, &payload3), 0);
    EXPECT_EQ(signed_certificate_request.tbs_request.type, OSCMS_SCOPED_CERTIFICATE_REQUEST_TYPE_EE_RA);

    fprintf(stderr, "DecodeSuccess releasing memory\n");
    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, asn1_signed_cert_request);
    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Data_SignedCertRequest, asn1c_decoded);
    oscms_empty_signed_certificate_request(&signed_certificate_request);
    oscms_empty_octet_buffer(&payload);
    oscms_empty_octet_buffer(&payload2);
    oscms_empty_octet_buffer(&payload3);
}
