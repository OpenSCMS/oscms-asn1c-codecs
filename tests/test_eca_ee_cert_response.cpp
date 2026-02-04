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
#include "oscms_codecs_api/oscms_eca_ee_cert_response.h"

#include "test_utils.hpp"

// std::vector<uint8_t> raw_data;
// ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);
// EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);

class EcaEeCertResponseTest : public ::testing::Test
{
  protected:
    OscmsEcaEeCertResponse test_response = {};
    OscmsCertificate test_cert           = {};

    void SetUp()
    {
        // Any certificate will do for testing
        std::vector<uint8_t> cert_data;
        ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", cert_data), 0);
        OscmsOctetBuffer test_cert_encoded = {.length = cert_data.size(), .data = cert_data.data()};
        ASSERT_EQ(oscms_decode_certificate(&test_cert_encoded, &test_cert), 0);

        test_response.generation_time = 0x12345678;
        memcpy(test_response.request_hash, "12345678", 8);
        memcpy(&test_response.certificate, &test_cert, sizeof(OscmsCertificate));
        test_response.eca_cert_chain       = &test_cert;
        test_response.eca_cert_chain_count = 1;
        test_response.private_key_info     = oscms_octet_buffer_new_from_string("0123456789ABCDEF0123456789ABCDEF");
    }

    void TearDown()
    {
        oscms_empty_certificate(&test_cert);
        oscms_free_octet_buffer(test_response.private_key_info);
    }
};

TEST_F(EcaEeCertResponseTest, NullArgs)
{
    OscmsOctetBuffer encoded = {
        .length = 5,
        .data   = (uint8_t *)"hello",
    };
    OscmsEcaEeCertResponse cert_response = {};

    EXPECT_EQ(oscms_encode_eca_ee_cert_response(nullptr, &encoded), -1);
    EXPECT_EQ(oscms_encode_eca_ee_cert_response(&cert_response, nullptr), -1);
    EXPECT_EQ(oscms_encode_eca_ee_cert_response(nullptr, nullptr), -1);
}

TEST_F(EcaEeCertResponseTest, InvalidEcaCertChain)
{
    TrackedOctetBuffer encoded1, encoded2;
    size_t save_count = test_response.eca_cert_chain_count;

    // Pointer but zero count
    test_response.eca_cert_chain_count = 0;
    EXPECT_EQ(oscms_encode_eca_ee_cert_response(&test_response, encoded1), -1);
    test_response.eca_cert_chain_count = save_count;

    // Count but null pointer
    test_response.eca_cert_chain = nullptr;
    EXPECT_EQ(oscms_encode_eca_ee_cert_response(&test_response, encoded2), -1);
}

TEST_F(EcaEeCertResponseTest, MissingPrivateKey)
{
    TrackedOctetBuffer encoded;
    oscms_free_octet_buffer(test_response.private_key_info);
    test_response.private_key_info = nullptr;
    test_response.certificate.type = OSCMS_CERTIFICATE_TYPE_IMPLICIT;
    EXPECT_EQ(oscms_encode_eca_ee_cert_response(&test_response, encoded), -1);
}

TEST_F(EcaEeCertResponseTest, PrivateKeyTooLong)
{
    TrackedOctetBuffer encoded;
    size_t original_allocation_size        = test_response.private_key_info->length;
    test_response.private_key_info->length = 123;
    EXPECT_EQ(oscms_encode_eca_ee_cert_response(&test_response, encoded), -1);
    test_response.private_key_info->length = original_allocation_size;
}

TEST_F(EcaEeCertResponseTest, Success)
{
    TrackedOctetBuffer encoded;
    EXPECT_EQ(oscms_encode_eca_ee_cert_response(&test_response, encoded), 0);
}
