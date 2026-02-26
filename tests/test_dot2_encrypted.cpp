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

#include "oscms_codecs_api/dot2_data_encrypted.h"
#include "oscms_codecs_api/octet_buffer.h"

#include "oscms_asn1c_generated/EeRaCertRequestSpdu.h"

#include "asn1c_utilities.h"

#include "test_utils.hpp"

TEST(Dot2DataEncryptedDecode, BadArgs)
{
    OscmsOctetBuffer payload = {
        .length = 5,
        .data   = (OscmsOctet *)"hello",
    };
    OscmsDot2DataEncrypted dot2_data_encrypted = {};

    EXPECT_EQ(oscms_decode_dot2_data_encrypted(NULL, OSCMS_DOT2_DATA_ENCRYPTED_TYPE_EE_RA_CERT_REQUEST_SPDU, 0), -1);
    EXPECT_EQ(
        oscms_decode_dot2_data_encrypted(&payload, OSCMS_DOT2_DATA_ENCRYPTED_TYPE_EE_RA_CERT_REQUEST_SPDU, 0), -1);
    EXPECT_EQ(
        oscms_decode_dot2_data_encrypted(
            0, OSCMS_DOT2_DATA_ENCRYPTED_TYPE_EE_RA_CERT_REQUEST_SPDU, &dot2_data_encrypted),
        -1);
    EXPECT_EQ(oscms_decode_dot2_data_encrypted(&payload, (OscmsDot2DataEncryptedType)1024, &dot2_data_encrypted), -1);
}

TEST(Dot2DataEncryptedDecode, InvalidData)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);

    TrackedOctetBuffer payload;
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(payload, raw_data.data(), raw_data.size()), 0);

    OscmsDot2DataEncrypted dot2_data_encrypted = {};
    EXPECT_EQ(
        oscms_decode_dot2_data_encrypted(
            payload, OSCMS_DOT2_DATA_ENCRYPTED_TYPE_EE_RA_CERT_REQUEST_SPDU, &dot2_data_encrypted),
        -1);
    oscms_empty_dot2_data_encrypted(&dot2_data_encrypted);
}

TEST(Dot2DataEncryptedDecode, Success)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/EeRaCertRequest.dat", raw_data), 0);

    TrackedOctetBuffer payload;
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(payload, raw_data.data(), raw_data.size()), 0);

    OscmsDot2DataEncrypted dot2_data_encrypted = {};
    EXPECT_EQ(
        oscms_decode_dot2_data_encrypted(
            payload, OSCMS_DOT2_DATA_ENCRYPTED_TYPE_EE_RA_CERT_REQUEST_SPDU, &dot2_data_encrypted),
        0);
    oscms_empty_dot2_data_encrypted(&dot2_data_encrypted);
}

TEST(Dot2DataEncryptedEncode, Success)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/EeRaCertRequest.dat", raw_data), 0);

    TrackedOctetBuffer payload;
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(payload, raw_data.data(), raw_data.size()), 0);

    EeRaCertRequestSpdu_t *ee_ra_cert_request_spdu = 0;

    asn_dec_rval_t rval = asn_decode(
        0,
        ATS_CANONICAL_OER,
        &asn_DEF_EeRaCertRequestSpdu,
        (void **)&ee_ra_cert_request_spdu,
        raw_data.data(),
        raw_data.size());
    ASSERT_EQ(rval.code, 0);
    // asn_fprint(stderr, &asn_DEF_EeRaCertRequestSpdu, ee_ra_cert_request_spdu);

    OscmsDot2DataEncrypted dot2_data_encrypted = {};
    ASSERT_EQ(
        oscms_decode_dot2_data_encrypted(
            payload, OSCMS_DOT2_DATA_ENCRYPTED_TYPE_EE_RA_CERT_REQUEST_SPDU, &dot2_data_encrypted),
        0);

    TrackedOctetBuffer encoded = {};
    EXPECT_EQ(oscms_encode_dot2_data_encrypted(&dot2_data_encrypted, encoded), 0);

    EXPECT_EQ(encoded.length(), raw_data.size());

    EeRaCertRequestSpdu_t *ee_ra_cert_request_spdu_decoded = 0;
    ASSERT_EQ(decode_and_check(encoded, &asn_DEF_EeRaCertRequestSpdu, (void **)&ee_ra_cert_request_spdu_decoded), 0);

    // hexdump("Encoded data", encoded.data(), encoded.length());
    // hexdump("Raw data", raw_data.data(), raw_data.size());
    for (size_t i = 0; i < encoded.length(); i++)
    {
        if (encoded.data()[i] != raw_data.data()[i])
        {
            fprintf(
                stderr,
                "Encoded data differs at offset %zu: %02x, Raw data: %02x\n",
                i,
                encoded.data()[i],
                raw_data.data()[i]);
        }
    }
    EXPECT_EQ(memcmp(encoded.data(), raw_data.data(), encoded.length()), 0);
    oscms_empty_dot2_data_encrypted(&dot2_data_encrypted);
    ASN_STRUCT_FREE(asn_DEF_EeRaCertRequestSpdu, ee_ra_cert_request_spdu_decoded);
    ASN_STRUCT_FREE(asn_DEF_EeRaCertRequestSpdu, ee_ra_cert_request_spdu);
}
