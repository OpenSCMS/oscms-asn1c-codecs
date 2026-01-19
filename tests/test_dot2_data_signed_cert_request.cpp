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

#include "oscms_codecs_api/dot2_data_signed_cert_request.h"
#include "oscms_codecs_api/octet_buffer.h"

#include "test_utils.hpp"

TEST(Dot2DataSignedCertRequestDecode, NullArgs)
{
    OscmsOctetBuffer payload =
                         {
                             .length = 5,
                             .data   = (uint8_t *)"hello",
                         },
                     encoded = {};

    EXPECT_EQ(oscms_decode_dot2_data_signed_cert_request(nullptr, nullptr), -1);
    EXPECT_EQ(oscms_decode_dot2_data_signed_cert_request(&payload, nullptr), -1);
    EXPECT_EQ(oscms_decode_dot2_data_signed_cert_request(nullptr, &encoded), -1);

    payload.length = 0;
    EXPECT_EQ(oscms_decode_dot2_data_signed_cert_request(&payload, &encoded), -1);

    payload.length = 1;
    payload.data   = nullptr;
    EXPECT_EQ(oscms_decode_dot2_data_signed_cert_request(&payload, &encoded), -1);
}

TEST(Dot2DataSignedCertRequestEncode, NullArgs)
{
    OscmsOctetBuffer encoded =
                         {
                             .length = 5,
                             .data   = (uint8_t *)"hello",
                         },
                     decoded = {};

    EXPECT_EQ(oscms_encode_dot2_data_signed_cert_request(nullptr, nullptr), -1);
    EXPECT_EQ(oscms_encode_dot2_data_signed_cert_request(&encoded, nullptr), -1);
    EXPECT_EQ(oscms_encode_dot2_data_signed_cert_request(nullptr, &decoded), -1);

    encoded.length = 0;
    EXPECT_EQ(oscms_decode_dot2_data_signed_cert_request(&encoded, &decoded), -1);

    encoded.length = 1;
    encoded.data   = nullptr;
    EXPECT_EQ(oscms_decode_dot2_data_signed_cert_request(&encoded, &decoded), -1);
}

TEST(Dot2DataSignedCertRequest, Roundtrip)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);

    const OscmsOctetBuffer payload = {
        .length = raw_data.size(),
        .data   = raw_data.data(),
    };

    OscmsOctetBuffer encoded = {};
    OscmsOctetBuffer decoded = {};

    EXPECT_EQ(0, oscms_encode_dot2_data_signed_cert_request(&payload, &encoded));
    ASSERT_NE(encoded.length, 0);
    ASSERT_NE(encoded.data, nullptr);

    EXPECT_EQ(0, oscms_decode_dot2_data_signed_cert_request(&encoded, &decoded));
    ASSERT_NE(decoded.length, 0);
    ASSERT_NE(decoded.data, nullptr);

    EXPECT_TRUE(oscms_octet_buffer_compare(&payload, &decoded));

    oscms_empty_octet_buffer(&encoded);
    oscms_empty_octet_buffer(&decoded);
}
