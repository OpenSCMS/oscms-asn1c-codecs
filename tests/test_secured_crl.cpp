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
#include "oscms_codecs_api/oscms_secured_crl.h"

#include "test_utils.hpp"

#include "oscms_asn1c_generated/CrlContents.h"
#include "oscms_asn1c_generated/CtlSignatureSpdu.h"
#include "oscms_asn1c_generated/Ieee1609Dot2Data-Unsecured.h"
#include "oscms_asn1c_generated/MultiSignedCtl.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"
#include "oscms_asn1c_generated/ScmsPdu.h"
#include "oscms_asn1c_generated/SecuredCrl.h"
#include "oscms_asn1c_generated/ToBeSignedCtlSignature.h"

#include "asn1c_utilities.h"

class SecuredCrlTest : public ::testing::Test
{
  protected:
    OscmsOctetBuffer encoded_crl_contents = {};
    OscmsCrlContents known_crl_contents   = {};
    bool decomposed                       = false;

    // Loads a composite CRL from a file and decomposes it into its component parts
    // to create a known CrlContents for testing purposes.
    void DecomposeCompositeCrl()
    {
        std::vector<uint8_t> raw_data;
        ASSERT_EQ(read_binary_test_file("data/composite-crl-scms-pdu.dat", raw_data), 0);
        OscmsOctetBuffer raw_data_buffer = {
            .length = raw_data.size(),
            .data   = raw_data.data(),
        };

        ScmsPdu_t *scms_pdu = nullptr;
        ASSERT_EQ(decode_and_check(&raw_data_buffer, &asn_DEF_ScmsPdu, (void **)&scms_pdu), 0);
        ASSERT_NE(scms_pdu, nullptr);

        CompositeCrl_t *composite_crl         = &scms_pdu->content.choice.cert.choice.compositeCrl;
        SecuredCrl_t *secured_crl_0           = (SecuredCrl_t *)composite_crl->crl.list.array[0];
        CrlContents_t *crl_contents           = 0;
        OscmsOctetBuffer encoded_crl_contents = {0};
        ASSERT_EQ(
            0,
            oscms_octet_buffer_init_from_octet_string(
                &secured_crl_0->content->choice.signedData->tbsData->payload->data->content->choice.unsecuredData,
                &encoded_crl_contents,
                0));

        ASSERT_EQ(0, decode_and_check(&encoded_crl_contents, &asn_DEF_CrlContents, (void **)&crl_contents));

        oscms_empty_octet_buffer(&encoded_crl_contents);
        ASN_STRUCT_FREE(asn_DEF_ScmsPdu, scms_pdu);
        ASN_STRUCT_FREE(asn_DEF_CrlContents, crl_contents);
        decomposed = true;
    }

    void ReleaseDecomposed()
    {
        if (!decomposed)
            return;

        oscms_empty_octet_buffer(&encoded_crl_contents);

        decomposed = false;
    }

    // void SetUp() override
    // {
    // }

    void TearDown() override
    {
        ReleaseDecomposed();
    }
};

TEST_F(SecuredCrlTest, DecomposeCompositeCrl)
{
    DecomposeCompositeCrl();
}

TEST_F(SecuredCrlTest, ReleaseDecomposed)
{
    DecomposeCompositeCrl();
    ReleaseDecomposed();
    ReleaseDecomposed();
}

TEST_F(SecuredCrlTest, EncodeCrlContentsSuccess)
{
    OscmsCrlContents known_crl_contents = {
        .crl_series            = 1,
        .crl_craca             = {1, 2, 3, 4, 5, 6, 7, 8},
        .issue_date            = 0x1234,
        .next_crl              = 0x8765,
        .priority_info_present = true,
        .priority_info         = 1,
        .type_specific =
            {
                .type = OSCMS_TSCC_FULL_LINKED,
                .contents =
                    {
                        .full_linked_crl =
                            {
                                .i_rev                    = 563,
                                .index_within_i           = 0,
                                .individual               = 0,
                                .individual_count         = 0,
                                .groups                   = 0,
                                .groups_count             = 0,
                                .groups_single_seed       = 0,
                                .groups_single_seed_count = 0,
                            },
                    },
            },
    };
    OscmsOctetBuffer encoded = {};
    ASSERT_EQ(0, oscms_encode_crl_contents(&known_crl_contents, &encoded));
    ASSERT_NE(encoded.length, 0);
    ASSERT_NE(encoded.data, nullptr);

    CrlContents_t *decoded = {};
    ASSERT_EQ(0, decode_and_check(&encoded, &asn_DEF_CrlContents, (void **)&decoded));
    ASN_STRUCT_FREE(asn_DEF_CrlContents, decoded);
    oscms_empty_octet_buffer(&encoded);
}
