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

#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ra_ee_cert_ack.h"

#include "asn1c_utilities.h"

#include "test_utils.hpp"

#include <ScmsPdu.h>

TEST(EncodeRaEeCertAck, NullParams)
{
    OscmsRaEeCertAck ra_ee_cert_ack = {0};

    TrackedOctetBuffer out_buf;

    int rc = oscms_encode_ra_ee_cert_ack(nullptr, nullptr);
    EXPECT_EQ(rc, -1);

    rc = oscms_encode_ra_ee_cert_ack(&ra_ee_cert_ack, nullptr);
    EXPECT_EQ(rc, -1);

    rc = oscms_encode_ra_ee_cert_ack(nullptr, out_buf);
    EXPECT_EQ(rc, -1);
}

TEST(EncodeRaEeCertAck, EncodeSuccess)
{
    OscmsRaEeCertAck ra_ee_cert_ack = {
        .generation_time = 1622548800, // Example timestamp
        .request_hash    = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        .next_dl_time    = 1622635200, // Example timestamp
        .first_i         = 42,
    };

    TrackedOctetBuffer encode_out;

    int rc = oscms_encode_ra_ee_cert_ack(&ra_ee_cert_ack, encode_out);
    EXPECT_EQ(rc, 0);
    EXPECT_NE(encode_out.length(), 0);
    EXPECT_NE(encode_out.data(), nullptr);
    // hexdump("Encoded RaEeCertAck", encode_out.data(), encode_out.length());

    // Decode
    ScmsPdu *internal_ra_ee_cert_ack = 0;
    ASSERT_EQ(decode_and_check(encode_out, &asn_DEF_ScmsPdu, (void **)&internal_ra_ee_cert_ack), 0);
    ASN_STRUCT_FREE(asn_DEF_ScmsPdu, internal_ra_ee_cert_ack);
}
