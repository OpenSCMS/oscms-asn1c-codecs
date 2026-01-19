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

#include "oscms_codecs_api/dot2_data_unsecured.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_download_request.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/EeRaDownloadRequestPlainSpdu.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

#include "test_utils.hpp"

// std::vector<uint8_t> raw_data;
// ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);
// EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);

class OscmsEeRaDownloadRequestTest : public testing::Test
{
  protected:
    ScmsPdu_t scmspdu = {
        .version = 2,
        .content =
            {
                .present = ScmsPdu__content_PR_ee_ra,
                .choice =
                    {
                        .ee_ra =
                            {
                                .present = EeRaInterfacePdu_PR_eeRaDownloadRequest,
                                .choice =
                                    {
                                        .eeRaDownloadRequest =
                                            {
                                                .generationTime = 0x12345678,
                                                .filename =
                                                    {
                                                        .buf  = (uint8_t *)"filename",
                                                        .size = 8,
                                                    },
                                            },
                                    },

                            },

                    },

            },
        ._asn_ctx = {0},
    };

    OscmsOctetBuffer encoded_scmspdu = {};
    OscmsOctetBuffer encoded_spdu    = {};

    void SetUp() override
    {
        ASSERT_EQ(check_and_encode(&scmspdu, &asn_DEF_ScmsPdu, &encoded_scmspdu), 0);

        Ieee1609Dot2Content_t content = {
            .present = Ieee1609Dot2Content_PR_unsecuredData,
            .choice =
                {
                    .unsecuredData =
                        {
                            .buf  = encoded_scmspdu.data,
                            .size = encoded_scmspdu.length,
                        },
                },
            ._asn_ctx = {0},
        };

        EeRaDownloadRequestPlainSpdu_t spdu = {
            .protocolVersion = 3,
            .content         = &content,
            ._asn_ctx        = {},
        };

        ASSERT_EQ(check_and_encode(&spdu, &asn_DEF_EeRaDownloadRequestPlainSpdu, &encoded_spdu), 0);
    };

    void TearDown() override
    {
        oscms_empty_octet_buffer(&encoded_scmspdu);
        oscms_empty_octet_buffer(&encoded_spdu);
    }
};

TEST_F(OscmsEeRaDownloadRequestTest, NullArgs)
{
    OscmsEeRaDownloadRequest decoded = {};
    EXPECT_EQ(oscms_decode_ee_ra_download_request(nullptr, nullptr), -1);
    EXPECT_EQ(oscms_decode_ee_ra_download_request(nullptr, &decoded), -1);
    EXPECT_EQ(oscms_decode_ee_ra_download_request(&encoded_scmspdu, nullptr), -1);

    EXPECT_EQ(oscms_decode_ee_ra_download_request_plain_spdu(nullptr, nullptr), -1);
    EXPECT_EQ(oscms_decode_ee_ra_download_request_plain_spdu(nullptr, &decoded), -1);
    EXPECT_EQ(oscms_decode_ee_ra_download_request_plain_spdu(&encoded_scmspdu, nullptr), -1);
}

TEST_F(OscmsEeRaDownloadRequestTest, DecodeScmsPdu)
{
    OscmsEeRaDownloadRequest decoded = {};
    ASSERT_EQ(oscms_decode_ee_ra_download_request(&encoded_scmspdu, &decoded), 0);

    EXPECT_EQ(decoded.generation_time, 0x12345678);
    EXPECT_EQ(decoded.filename.length, 8);
    EXPECT_EQ(memcmp(decoded.filename.data, "filename", 8), 0);
    oscms_empty_ee_ra_download_request(&decoded);
}

TEST_F(OscmsEeRaDownloadRequestTest, DecodeSpdu)
{
    OscmsEeRaDownloadRequest decoded = {};
    ASSERT_EQ(oscms_decode_ee_ra_download_request_plain_spdu(&encoded_spdu, &decoded), 0); // Decode the SPDU

    EXPECT_EQ(decoded.generation_time, 0x12345678);
    EXPECT_EQ(decoded.filename.length, 8);
    EXPECT_EQ(memcmp(decoded.filename.data, "filename", 8), 0);
    oscms_empty_ee_ra_download_request(&decoded);
}
