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
#include "oscms_codecs_api/oscms_composite_crl.h"

#include "asn1c_utilities.h"
#include "test_utils.hpp"

#include "oscms_asn1c_generated/CompositeCrlSpdu.h"
#include "oscms_asn1c_generated/MultiSignedCtlSpdu.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"
#include "oscms_asn1c_generated/SecuredCrl.h"

// std::vector<uint8_t> raw_data;
// ASSERT_EQ(read_binary_test_file("data/RaCertificate.dat", raw_data), 0);
// EXPECT_EQ(memcmp(encoded.data, raw_data.data(), encoded.length), 0);

TEST(CompositeCrlTest, EncodeSpduSuccess)
{
    std::vector<uint8_t> raw_data;
    ASSERT_EQ(read_binary_test_file("data/composite-crl-file.dat", raw_data), 0);
    OscmsOctetBuffer raw_data_buffer = {
        .length = raw_data.size(),
        .data   = raw_data.data(),
    };

    CompositeCrlSpdu_t *spdu = nullptr;
    ASSERT_EQ(decode_and_check(&raw_data_buffer, &asn_DEF_CompositeCrlSpdu, (void **)&spdu), 0);
    ASSERT_NE(spdu, nullptr);

    ScmsPdu_t *scms_pdu = 0;

    TrackedOctetBuffer encoded_scms_pdu = {};

    ASSERT_EQ(0, oscms_octet_buffer_init_from_octet_string(&spdu->content->choice.unsecuredData, encoded_scms_pdu, 0));

    ASSERT_EQ(0, decode_and_check(encoded_scms_pdu, &asn_DEF_ScmsPdu, (void **)&scms_pdu));

    CompositeCrl_t *composite_crl = &scms_pdu->content.choice.cert.choice.compositeCrl;

    OscmsCompositeCrl api_composite_crl  = {0};
    api_composite_crl.secured_crls_count = composite_crl->crl.list.count;

    if (api_composite_crl.secured_crls_count > 0)
    {
        api_composite_crl.secured_crls =
            (OscmsOctetBuffer *)calloc(composite_crl->crl.list.count, sizeof(OscmsOctetBuffer));
        ASSERT_NE(api_composite_crl.secured_crls, nullptr);

        for (size_t i = 0; i < composite_crl->crl.list.count; i++)
        {
            SecuredCrl_t *secured_crl = (SecuredCrl_t *)composite_crl->crl.list.array[i];
            ASSERT_EQ(check_and_encode(secured_crl, &asn_DEF_SecuredCrl, &api_composite_crl.secured_crls[i]), 0);
        }
    }

    ASSERT_EQ(check_and_encode(&composite_crl->homeCtl, &asn_DEF_MultiSignedCtlSpdu, &api_composite_crl.home_ctl), 0);

    TrackedOctetBuffer encoded;
    ASSERT_EQ(oscms_encode_composite_crl_spdu(&api_composite_crl, encoded), 0);
    ASSERT_NE(encoded.length(), 0);
    ASSERT_NE(encoded.data(), nullptr);

    ASSERT_TRUE(oscms_octet_buffer_compare(encoded, &raw_data_buffer));

    oscms_empty_octet_buffer(&api_composite_crl.home_ctl);
    for (size_t i = 0; i < api_composite_crl.secured_crls_count; i++)
    {
        oscms_empty_octet_buffer(&api_composite_crl.secured_crls[i]);
    }
    free(api_composite_crl.secured_crls);
    ASN_STRUCT_FREE(asn_DEF_ScmsPdu, scms_pdu);
    ASN_STRUCT_FREE(asn_DEF_CompositeCrlSpdu, spdu);
}
