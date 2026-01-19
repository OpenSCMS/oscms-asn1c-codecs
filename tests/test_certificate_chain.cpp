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
#include "oscms_codecs_api/oscms_certificate_chain.h"

#include "test_utils.hpp"

#include "oscms_asn1c_generated/CertificateChain.h"
#include "oscms_asn1c_generated/CertificateChainSpdu.h"
#include "oscms_asn1c_generated/MultiSignedCtl.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

#include "asn1c_utilities.h"

class CertificateChainTest : public ::testing::Test
{
  protected:
    OscmsOctetBuffer known_encoded_spdu           = {};
    OscmsCertificateChain known_certificate_chain = {};
    bool decomposed                               = false;

    // Loads a CertificateChainSpdu from a file and decomposes it into its component parts
    // to create a known OscmsCertificateChain for testing purposes.
    void DecomposeCertificateChain()
    {
        ReleaseDecomposed(); // In case we get called twice in the same test

        std::vector<uint8_t> raw_data;
        ASSERT_EQ(read_binary_test_file("data/OscmsCertificateChainFileSpdu.dat", raw_data), 0);
        oscms_octet_buffer_init_from_buffer(&known_encoded_spdu, raw_data.data(), raw_data.size());

        // Decode the SPDU
        CertificateChainSpdu_t *outer_spdu = nullptr;
        ASSERT_EQ(decode_and_check(&known_encoded_spdu, &asn_DEF_CertificateChainSpdu, (void **)&outer_spdu), 0);
        ASSERT_NE(outer_spdu, nullptr);

        // Decode the unsecued payload as an SCMS PDU
        OscmsOctetBuffer raw_scmspdu = {
            .length = outer_spdu->content->choice.unsecuredData.size,
            .data   = outer_spdu->content->choice.unsecuredData.buf};

        ScmsPdu_t *inner_scms_pdu = nullptr;
        ASSERT_EQ(decode_and_check(&raw_scmspdu, &asn_DEF_ScmsPdu, (void **)&inner_scms_pdu), 0);
        ASSERT_NE(inner_scms_pdu, nullptr);

        // Convenience pointer to the embedded CertificateChain
        CertificateChain_t *internal = &inner_scms_pdu->content.choice.cert.choice.certificateChain;
        memset(&known_certificate_chain, 0, sizeof(known_certificate_chain));

        // Re-encode the partially decoeded MultiSignedCtlSpdu
        ASSERT_EQ(
            0, check_and_encode(&internal->homeCtl, &asn_DEF_MultiSignedCtlSpdu, &known_certificate_chain.home_ctl));

        if (internal->others.list.count > 0)
        {
            known_certificate_chain.others_count = internal->others.list.count;
            known_certificate_chain.others =
                (OscmsOctetBuffer *)calloc(known_certificate_chain.others_count, sizeof(OscmsOctetBuffer));
            ASSERT_NE(known_certificate_chain.others, nullptr);

            for (size_t i = 0; i < internal->others.list.count; i++)
            {
                ASSERT_EQ(
                    0,
                    check_and_encode(
                        internal->others.list.array[i], &asn_DEF_Certificate, &known_certificate_chain.others[i]));
            }
        }

        ASN_STRUCT_FREE(asn_DEF_ScmsPdu, inner_scms_pdu);
        ASN_STRUCT_FREE(asn_DEF_CertificateChainSpdu, outer_spdu);

        decomposed = true;
    }

    void ReleaseDecomposed()
    {
        if (!decomposed)
            return;

        oscms_empty_octet_buffer(&known_encoded_spdu);
        oscms_empty_octet_buffer(&known_certificate_chain.home_ctl);

        if (known_certificate_chain.others_count > 0)
        {
            for (int i = 0; i < known_certificate_chain.others_count; i++)
            {
                oscms_empty_octet_buffer(&known_certificate_chain.others[i]);
            }
            free(known_certificate_chain.others);
        }

        memset(&known_certificate_chain, 0, sizeof(known_certificate_chain));
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

TEST_F(CertificateChainTest, DecomposeCertificateChain)
{
    DecomposeCertificateChain();
}

TEST_F(CertificateChainTest, ReleaseDecomposed)
{
    DecomposeCertificateChain();
    ReleaseDecomposed();
    ReleaseDecomposed();
}

TEST_F(CertificateChainTest, EncodeSpduSuccess)
{
    OscmsOctetBuffer encoded = {};
    DecomposeCertificateChain();
    ASSERT_EQ(oscms_encode_certificate_chain_spdu(&known_certificate_chain, &encoded), 0);
    ASSERT_NE(encoded.length, 0);
    ASSERT_NE(encoded.data, nullptr);

    ASSERT_TRUE(oscms_octet_buffer_compare(&encoded, &known_encoded_spdu));

    Certificate *decoded = {};
    ASSERT_EQ(decode_and_check(&encoded, &asn_DEF_CertificateChainSpdu, (void **)&decoded), 0);
    ASN_STRUCT_FREE(asn_DEF_CertificateChainSpdu, decoded);

    oscms_empty_octet_buffer(&encoded);
}
