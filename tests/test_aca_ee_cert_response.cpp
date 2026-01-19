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
#include "oscms_codecs_api/oscms_aca_ee_cert_response.h"

#include "test_utils.hpp"

// std::vector<uint8_t> raw_data;
// ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);
// EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);

class AcaEeCertResponseTest : public ::testing::Test
{
  protected:
    OscmsAcaEeCertResponse test_response = {};
    OscmsCertificate test_cert           = {};

    void SetUp()
    {
        // Any certificate will do for testing
        std::vector<uint8_t> cert_data;
        ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", cert_data), 0);
        OscmsOctetBuffer test_cert_encoded = {.length = cert_data.size(), .data = cert_data.data()};
        ASSERT_EQ(oscms_decode_certificate(&test_cert_encoded, &test_cert), 0);

        test_response.generation_time = 0x12345678;
        memcpy(&test_response.certificate, &test_cert, sizeof(OscmsCertificate));
        test_response.private_key_info = oscms_octet_buffer_new_from_string("0123456789ABCDEF0123456789ABCDEF");
    }

    void TearDown()
    {
        oscms_empty_certificate(&test_cert);
        oscms_free_octet_buffer(test_response.private_key_info);
    }
};

TEST_F(AcaEeCertResponseTest, NullArgs)
{
    OscmsOctetBuffer encoded = {
        .length = 5,
        .data   = (uint8_t *)"hello",
    };
    OscmsAcaEeCertResponse cert_response = {};

    EXPECT_EQ(oscms_encode_aca_ee_cert_response(nullptr, &encoded), -1);
    EXPECT_EQ(oscms_encode_aca_ee_cert_response(&cert_response, nullptr), -1);
    EXPECT_EQ(oscms_encode_aca_ee_cert_response(nullptr, nullptr), -1);
}

TEST_F(AcaEeCertResponseTest, MissingPrivateKey)
{
    OscmsOctetBuffer encoded       = {};
    OscmsOctetBuffer *private_key  = test_response.private_key_info;
    test_response.private_key_info = nullptr;
    test_response.certificate.type = OSCMS_CERTIFICATE_TYPE_IMPLICIT;
    EXPECT_EQ(oscms_encode_aca_ee_cert_response(&test_response, &encoded), -1);
    test_response.private_key_info = private_key;
    oscms_empty_octet_buffer(&encoded);
}

TEST_F(AcaEeCertResponseTest, PrivateKeyTooLong)
{
    OscmsOctetBuffer encoded               = {};
    test_response.private_key_info->length = 123;
    EXPECT_EQ(oscms_encode_aca_ee_cert_response(&test_response, &encoded), -1);
    oscms_empty_octet_buffer(&encoded);
}

TEST_F(AcaEeCertResponseTest, EncodePduSuccess)
{
    OscmsOctetBuffer encoded = {};
    EXPECT_EQ(oscms_encode_aca_ee_cert_response(&test_response, &encoded), 0);
    oscms_empty_octet_buffer(&encoded);
}

TEST_F(AcaEeCertResponseTest, EncodeSpduSuccess)
{
    OscmsOctetBuffer encoded = {};
    EXPECT_EQ(oscms_encode_aca_ee_cert_response_plain_spdu(&test_response, &encoded), 0);
    oscms_empty_octet_buffer(&encoded);
}
