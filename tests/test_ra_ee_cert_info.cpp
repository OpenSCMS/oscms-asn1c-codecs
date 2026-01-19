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
#include "oscms_codecs_api/oscms_ra_ee_cert_info.h"

#include "test_utils.hpp"

// std::vector<uint8_t> raw_data;
// ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);
// EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);

class RaEeCertInfotest : public ::testing::Test
{
  protected:
    OscmsRaEeCertInfo test_response = {};

    void SetUp()
    {
        test_response.generation_time = 0x12345678;
        memcpy(test_response.request_hash, "12345678", 8);
        test_response.current_i          = 0x1234;
        test_response.next_download_time = 0x12345678;
    }
};

TEST_F(RaEeCertInfotest, NullArgs)
{
    OscmsOctetBuffer encoded = {
        .length = 5,
        .data   = (uint8_t *)"hello",
    };

    EXPECT_EQ(oscms_encode_ra_ee_cert_info(nullptr, &encoded), -1);
    EXPECT_EQ(oscms_encode_ra_ee_cert_info(&test_response, nullptr), -1);
    EXPECT_EQ(oscms_encode_ra_ee_cert_info(nullptr, nullptr), -1);
}

TEST_F(RaEeCertInfotest, Success)
{
    OscmsOctetBuffer encoded = {};
    EXPECT_EQ(oscms_encode_ra_ee_cert_info(&test_response, &encoded), 0);
    oscms_empty_octet_buffer(&encoded);
}

TEST_F(RaEeCertInfotest, EncodeSpduSuccess)
{
    OscmsOctetBuffer encoded = {};
    EXPECT_EQ(oscms_encode_ra_ee_cert_info_spdu(&test_response, &encoded), 0);
    oscms_empty_octet_buffer(&encoded);
}
