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
#include "oscms_codecs_api/oscms_signature.h"

#include "oscms_asn1c_generated/Certificate.h"
#include "oscms_asn1c_generated/Signature.h"

#include "asn1c_utilities.h"

#include "test_utils.hpp"

// std::vector<uint8_t> raw_data;
// ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);
// EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);

TEST(OscmsSignatureTest, NullSafe)
{
    oscms_empty_signature(nullptr);
    oscms_free_signature(nullptr);
}

TEST(OscmsSignatureTest, EmptyCertificate)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);

    OscmsOctetBuffer certificate = {};
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(&certificate, raw_data.data(), raw_data.size()), 0);

    Certificate_t *cert = 0;
    ASSERT_EQ(decode_and_check(&certificate, &asn_DEF_Certificate, (void **)&cert), 0);
    oscms_empty_octet_buffer(&certificate);

    OscmsSignature signature = {};
    ASSERT_EQ(oscms_signature_from_internal(cert->signature, &signature, 0), 0);

    ASN_STRUCT_FREE(asn_DEF_Certificate, cert);

    oscms_empty_signature(&signature);

    // EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);
}

TEST(OscmsSignatureTest, TrackMemory)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);

    OscmsOctetBuffer certificate = {};
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(&certificate, raw_data.data(), raw_data.size()), 0);

    Certificate_t *cert = 0;
    ASSERT_EQ(decode_and_check(&certificate, &asn_DEF_Certificate, (void **)&cert), 0);
    oscms_empty_octet_buffer(&certificate);

    OscmsSignature signature = {};
    OscmsSequence tracker    = {};
    ASSERT_EQ(oscms_signature_from_internal(cert->signature, &signature, &tracker), 0);

    ASN_STRUCT_FREE(asn_DEF_Certificate, cert);

    oscms_empty_sequence(&tracker);
    // EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);
}
