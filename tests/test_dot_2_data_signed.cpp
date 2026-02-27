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

#include "oscms_codecs_api/dot2_data_signed.h"
#include "oscms_codecs_api/octet_buffer.h"

#include "test_utils.hpp"

// Encoding is tested as part of the CertificateManagementInfoStatusSpdu testing

TEST(Dot2DataSigned, BadArgs)
{
    OscmsSignedData dot2_data_signed = {};
    OscmsOctetBuffer payload         = {};
    EXPECT_EQ(
        oscms_decode_dot2_data_signed(
            NULL, OSCMS_DOT2_DATA_SIGNED_TYPE_CERTIFICATE_MANAGEMENT_INFO_STATUS_SPDU, &dot2_data_signed),
        -1);
    EXPECT_EQ(
        oscms_decode_dot2_data_signed(
            &payload, OSCMS_DOT2_DATA_SIGNED_TYPE_CERTIFICATE_MANAGEMENT_INFO_STATUS_SPDU, NULL),
        -1);
    EXPECT_EQ(
        oscms_decode_dot2_data_signed(
            NULL, OSCMS_DOT2_DATA_SIGNED_TYPE_CERTIFICATE_MANAGEMENT_INFO_STATUS_SPDU, &dot2_data_signed),
        -1);

    // check invalid enclosing type
    payload.data   = (OscmsOctet *)"test data";
    payload.length = 10;
    EXPECT_EQ(oscms_decode_dot2_data_signed(&payload, (OscmsDot2DataSignedType)1234, &dot2_data_signed), -1);
}
TEST(Dot2DataSigned, DecodeSuccess)
{
    // The CertificateManagementInfoStatusSpdu is, in fact, simply an Ieee1609Dot2Data_Signed with specific fields
    // present so we can decode this as test data

    std::vector<uint8_t> buffer;
    ASSERT_EQ(read_binary_test_file("data/CertificateManagementInfoStatusSpdu.dat", buffer), 0);

    OscmsOctetBuffer payload = {};

    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(&payload, buffer.data(), buffer.size()), 0);

    OscmsSignedData dot2_data_signed = {};
    EXPECT_EQ(
        oscms_decode_dot2_data_signed(
            &payload, OSCMS_DOT2_DATA_SIGNED_TYPE_CERTIFICATE_MANAGEMENT_INFO_STATUS_SPDU, &dot2_data_signed),
        0);
    EXPECT_EQ(dot2_data_signed.payload_psid, OSCMS_PSID_SECURITY_MGMT);
    oscms_empty_octet_buffer(&payload);
    oscms_empty_signed_data(&dot2_data_signed);
}
