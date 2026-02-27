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

#include <iostream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "test_utils.hpp"

#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_certificate.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/Certificate.h"
#include "oscms_asn1c_generated/ExplicitCertificate.h"

TEST(CertificateDecode, NullArgs)
{
    OscmsCertificate cert          = {};
    OscmsOctetBuffer internal_cert = {};

    EXPECT_NE(0, oscms_decode_certificate(nullptr, nullptr));
    EXPECT_NE(0, oscms_decode_certificate(&internal_cert, nullptr));
    EXPECT_NE(0, oscms_decode_certificate(nullptr, &cert));
}

TEST(CertificateDecode, Success)
{
    OscmsCertificate cert          = {};
    OscmsOctetBuffer internal_cert = {};

    std::vector<uint8_t> buffer;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", buffer), 0);

    oscms_octet_buffer_init_from_buffer(&internal_cert, buffer.data(), buffer.size());
    int rc = oscms_decode_certificate(&internal_cert, &cert);
    EXPECT_EQ(rc, 0);

    oscms_empty_octet_buffer(&internal_cert);
    oscms_empty_certificate(&cert);
}

static int decode_binary_certificate(const uint8_t *buffer, size_t buffer_size, Certificate_t **certificate)
{
    *certificate             = 0;
    OscmsOctetBuffer encoded = {.length = buffer_size, .data = (uint8_t *)buffer};
    return decode_and_check(&encoded, &asn_DEF_Certificate, (void **)certificate);
}

TEST(Certificate, Roundtrip)
{
    int rc;

    std::vector<uint8_t> buffer;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", buffer), 0);

    Certificate_t *asn_decoded_cert = 0;
    ASSERT_EQ(0, decode_binary_certificate(buffer.data(), buffer.size(), &asn_decoded_cert));

    // std::cerr << "Certificate Decoded by CODECS" << std::endl;
    // asn_fprint(stderr, &asn_DEF_Certificate, asn_decoded_cert);

    OscmsCertificate api_decoded_cert = {};
    OscmsOctetBuffer cert_buffer      = {};

    oscms_octet_buffer_init_from_buffer(&cert_buffer, buffer.data(), buffer.size());
    rc = oscms_decode_certificate(&cert_buffer, &api_decoded_cert);
    ASSERT_EQ(rc, 0);
    oscms_empty_octet_buffer(&cert_buffer);

    rc = oscms_encode_certificate(&api_decoded_cert, &cert_buffer);
    ASSERT_EQ(rc, 0);

    EXPECT_EQ(buffer.size(), cert_buffer.length);
    EXPECT_EQ(memcmp(buffer.data(), cert_buffer.data, buffer.size()), 0);

    // As a final sanity check, make sure the raw codecs can decode our encoded version
    Certificate_t *our_decoded_cert = 0;
    ASSERT_EQ(0, decode_binary_certificate(cert_buffer.data, cert_buffer.length, &our_decoded_cert));

    // std::cerr << "##################################################" << std::endl
    //           << "Certificate Decoded by API" << std::endl;
    // asn_fprint(stderr, &asn_DEF_Certificate, our_decoded_cert);

    ASN_STRUCT_FREE(asn_DEF_Certificate, our_decoded_cert);
    ASN_STRUCT_FREE(asn_DEF_Certificate, asn_decoded_cert);

    oscms_empty_octet_buffer(&cert_buffer);

    oscms_empty_certificate(&api_decoded_cert);
}
