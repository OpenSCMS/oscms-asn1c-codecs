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
#include "oscms_codecs_api/oscms_tbs_ctl_signature.h"

#include "asn1c_utilities.h"

#include "test_utils.hpp"

#include "oscms_asn1c_generated/CtlSignatureSpdu.h"
#include "oscms_asn1c_generated/ScmsPdu.h"
#include "oscms_asn1c_generated/ToBeSignedCtlSignature.h"

TEST(TbsCtlSignature, NullArgs)
{
    OscmsDot2DataSignedArgs args = {};
    OscmsOctetBuffer buffer      = {};
    OscmsTbsCtlSignature tbs     = {};

    EXPECT_NE(oscms_tbs_ctl_signature_to_internal(nullptr, &buffer), 0);
    EXPECT_NE(oscms_tbs_ctl_signature_to_internal(&tbs, nullptr), 0);

    EXPECT_NE(oscms_encode_tbs_ctl_signature(nullptr, nullptr), 0);
    EXPECT_NE(oscms_encode_tbs_ctl_signature(&tbs, nullptr), 0);
    EXPECT_NE(oscms_encode_tbs_ctl_signature(nullptr, &buffer), 0);

    EXPECT_NE(oscms_encode_ctl_signature_spdu(nullptr, nullptr), 0);
    EXPECT_NE(oscms_encode_ctl_signature_spdu(&args, nullptr), 0);
    EXPECT_NE(oscms_encode_ctl_signature_spdu(nullptr, &buffer), 0);
}

TEST(TbsCtlSignature, ToInternalSuccess)
{
    OscmsTbsCtlSignature tbs = {
        .series_id       = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        .sequence_number = 0xA05A,
        .tbs_ctl_hash =
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            },
    };
    ToBeSignedCtlSignature_t buffer;

    EXPECT_EQ(oscms_tbs_ctl_signature_to_internal(&tbs, &buffer), 0);

    EXPECT_EQ(asn_check_constraints(&asn_DEF_ToBeSignedCtlSignature, &buffer, nullptr, nullptr), 0);

    // asn_fprint(stderr, &asn_DEF_ToBeSignedCtlSignature, &buffer);
    ASN_STRUCT_RESET(asn_DEF_ToBeSignedCtlSignature, &buffer);
}

TEST(TbsCtlSignature, ToScmsPduSuccess)
{
    OscmsTbsCtlSignature tbs = {
        .series_id       = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        .sequence_number = 0xA05A,
        .tbs_ctl_hash =
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            },
    };
    TrackedOctetBuffer encoded;
    ASSERT_EQ(oscms_encode_tbs_ctl_signature(&tbs, encoded), 0);

    ScmsPdu_t *decoded = nullptr;
    ASSERT_EQ(decode_and_check(encoded, &asn_DEF_ScmsPdu, (void **)&decoded), 0);

    asn_fprint(stderr, &asn_DEF_ScmsPdu, decoded);

    ASN_STRUCT_FREE(asn_DEF_ScmsPdu, decoded);
}

TEST(TbsCtlSignature, ToSpduSuccess)
{
    OscmsTbsCtlSignature tbs = {
        .series_id       = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        .sequence_number = 0xA05A,
        .tbs_ctl_hash =
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            },
    };

    OscmsDot2DataSignedArgs args = {};
    TrackedOctetBuffer encoded;

    std::vector<uint8_t> raw_cert;
    ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_cert), 0);
    ASSERT_EQ(oscms_octet_buffer_init_from_buffer(&args.signer_certificate, raw_cert.data(), raw_cert.size()), 0);

    ASSERT_EQ(oscms_encode_tbs_ctl_signature(&tbs, &args.payload), 0);

    static uint8_t signature_rsig[] = {
        0x44, 0xCE, 0x1F, 0x38, 0x56, 0xDB, 0xEA, 0x7B, 0x09, 0xE3, 0x40, 0xF5, 0x60, 0xBD, 0x0C, 0x0E,
        0x23, 0xAF, 0x21, 0x74, 0x3E, 0xB4, 0x1D, 0x7B, 0x7F, 0xFF, 0x76, 0xFF, 0x97, 0x08, 0xCC, 0xC5,
    };
    static uint8_t signature_ssig[] = {
        0x26, 0x25, 0x08, 0x5D, 0x99, 0xE1, 0x29, 0xF7, 0x54, 0x0F, 0x8B, 0x5E, 0x27, 0x50, 0x18, 0x77,
        0xC1, 0x60, 0xC5, 0xFB, 0xFA, 0x6F, 0x4F, 0xC9, 0xFD, 0x3B, 0x26, 0xFC, 0x70, 0xC0, 0x4A, 0xE5,
    };
    args.signature.type                        = OSCMS_SIGNATURE_TYPE_NIST_P256;
    args.signature.rsig.curve_point.curve_type = OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256;
    args.signature.rsig.curve_point.point_type = OSCMS_ECC_POINT_TYPE_X_ONLY;
    args.signature.rsig.curve_point.x.data     = signature_rsig;
    args.signature.rsig.curve_point.x.length   = sizeof(signature_rsig);
    args.signature.s_sig.data                  = signature_ssig;
    args.signature.s_sig.length                = sizeof(signature_ssig);

    ASSERT_EQ(oscms_encode_ctl_signature_spdu(&args, encoded), 0);

    CtlSignatureSpdu_t *decoded = {};
    ASSERT_EQ(decode_and_check(encoded, &asn_DEF_CtlSignatureSpdu, (void **)&decoded), 0);

    ASN_STRUCT_FREE(asn_DEF_CtlSignatureSpdu, decoded);
    oscms_empty_octet_buffer(&args.signer_certificate);
    oscms_empty_octet_buffer(&args.payload);
}
