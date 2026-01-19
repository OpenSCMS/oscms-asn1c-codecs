// Copyright(c) 2025 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0(the "License"); you may not
// use this file except in compliance with the License.You may obtain a copy of
// the License at
//
// http : //www.apache.org / licenses / LICENSE - 2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.See the
// License for the specific language governing permissions and limitations under
// the License.
//
// SPDX - License - Identifier : Apache - 2.0

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_tbs_data.h"

#include "test_utils.hpp"

#include <ToBeSignedData.h>

TEST(EncodeTbsData, NullParams)
{
    OscmsOctetBuffer *tbs_data_payload = oscms_octet_buffer_new();
    EXPECT_NE(tbs_data_payload, nullptr);

    OscmsOctetBuffer *out_buf = oscms_octet_buffer_new();
    EXPECT_NE(out_buf, nullptr);

    int rc = oscms_encode_tbs_data(nullptr, 0x23, nullptr);
    EXPECT_EQ(rc, -1);

    rc = oscms_encode_tbs_data(tbs_data_payload, 0x23, nullptr);
    EXPECT_EQ(rc, -1);

    rc = oscms_encode_tbs_data(nullptr, 0x23, out_buf);
    EXPECT_EQ(rc, -1);

    oscms_free_octet_buffer(tbs_data_payload);
    oscms_free_octet_buffer(out_buf);
}

static int known_tbs_data_payload(OscmsOctetBuffer *payload)
{
    std::vector<uint8_t> buffer;
    if (read_binary_test_file("data/CertManagementPdu.dat", buffer) != 0)
    {
        return -1;
    }

    return oscms_octet_buffer_init_from_buffer(payload, buffer.data(), buffer.size());
}

TEST(EncodeTbsData, EncodeSuccess)
{
    TrackedOctetBuffer payload;
    ASSERT_EQ(known_tbs_data_payload(payload), 0);

    TrackedOctetBuffer encode_out;
    int rc = oscms_encode_tbs_data(payload, OSCMS_PSID_SECURITY_MGMT, encode_out);
    EXPECT_EQ(rc, 0);
    EXPECT_NE(encode_out.length(), 0);
    EXPECT_NE(encode_out.data(), nullptr);
    // hexdump("Encoded TBS DATA", encode_out->data, encode_out->length);

    // Decode
    ToBeSignedData_t *internal_to_be_signed_data = 0;
    asn_dec_rval_t rv                            = asn_decode(
        0,
        ATS_CANONICAL_OER,
        &asn_DEF_ToBeSignedData,
        (void **)&internal_to_be_signed_data,
        encode_out.data(),
        encode_out.length());

    ASSERT_EQ(rv.code, RC_OK);
    EXPECT_EQ(rv.consumed, encode_out.length());

    // Check constraints
    char error_buf[256];
    size_t error_length = sizeof(error_buf);
    EXPECT_EQ(asn_check_constraints(&asn_DEF_ToBeSignedData, internal_to_be_signed_data, error_buf, &error_length), 0);

    ASN_STRUCT_FREE(asn_DEF_ToBeSignedData, internal_to_be_signed_data);
}
