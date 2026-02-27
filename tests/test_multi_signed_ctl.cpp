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
#include "oscms_codecs_api/oscms_multi_signed_ctl.h"

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

class MultiSignedCtlTest : public ::testing::Test
{
  protected:
    OscmsOctetBuffer encoded_multi_signed_ctl_spdu = {};
    OscmsMultiSignedCtl known_multi_signed_ctl     = {};
    bool decomposed                                = false;

    // Loads a composite CRL from a file and decomposes it into its component parts
    // to create a known OscmsMultiSignedCtl for testing purposes.
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

        CompositeCrl_t *composite_crl = &scms_pdu->content.choice.cert.choice.compositeCrl;

        // Generate an encoded MultiSignedCtlSpdu for later use in comparisons.
        ASSERT_EQ(
            check_and_encode(&composite_crl->homeCtl, &asn_DEF_MultiSignedCtlSpdu, &encoded_multi_signed_ctl_spdu), 0);

        OscmsOctetBuffer multi_signed_ctl_buffer = {
            .length = composite_crl->homeCtl.content->choice.unsecuredData.size,
            .data   = composite_crl->homeCtl.content->choice.unsecuredData.buf,
        };

        ScmsPdu_t *inner_scms_pdu = 0;
        ASSERT_EQ(decode_and_check(&multi_signed_ctl_buffer, &asn_DEF_ScmsPdu, (void **)&inner_scms_pdu), 0);
        ASSERT_NE(inner_scms_pdu, nullptr);

        MultiSignedCtl_t *decoded_multi_signed_ctl = &inner_scms_pdu->content.choice.cert.choice.multiSignedCtl;
        FullIeeeTbsCtl_t *full_ieee_tbs_ctl        = &decoded_multi_signed_ctl->tbsCtl.choice.FullIeeeTbsCtl;
        known_multi_signed_ctl.full_ieee_tbs_ctl.sequence_number = full_ieee_tbs_ctl->sequenceNumber;
        memcpy(
            &known_multi_signed_ctl.full_ieee_tbs_ctl.series_id,
            full_ieee_tbs_ctl->ctlSeriesId.buf,
            sizeof(OscmsCtlSeriesId));
        known_multi_signed_ctl.full_ieee_tbs_ctl.effective_date = full_ieee_tbs_ctl->effectiveDate;

        if (full_ieee_tbs_ctl->quorum)
        {
            known_multi_signed_ctl.full_ieee_tbs_ctl.quorum_present = true;
            known_multi_signed_ctl.full_ieee_tbs_ctl.quorum         = *full_ieee_tbs_ctl->quorum;
        }

        if (full_ieee_tbs_ctl->electorApprove.list.count > 0)
        {
            size_t count                                                 = full_ieee_tbs_ctl->electorApprove.list.count;
            known_multi_signed_ctl.full_ieee_tbs_ctl.num_elector_approve = count;
            known_multi_signed_ctl.full_ieee_tbs_ctl.elector_approve =
                (OscmsCtlElectorEntry *)calloc(count, sizeof(OscmsCtlElectorEntry));
            ASSERT_NE(known_multi_signed_ctl.full_ieee_tbs_ctl.elector_approve, nullptr);

            for (int i = 0; i < count; i++)
            {
                memcpy(
                    &known_multi_signed_ctl.full_ieee_tbs_ctl.elector_approve[i],
                    full_ieee_tbs_ctl->electorApprove.list.array[i]->buf,
                    full_ieee_tbs_ctl->electorApprove.list.array[i]->size);
            }
        }
        else
        {
            known_multi_signed_ctl.full_ieee_tbs_ctl.elector_approve     = 0;
            known_multi_signed_ctl.full_ieee_tbs_ctl.num_elector_approve = 0;
        }

        if (full_ieee_tbs_ctl->electorRemove.list.count > 0)
        {
            size_t count = full_ieee_tbs_ctl->electorRemove.list.count;

            known_multi_signed_ctl.full_ieee_tbs_ctl.num_elector_remove = count;
            known_multi_signed_ctl.full_ieee_tbs_ctl.elector_remove =
                (OscmsCtlElectorEntry *)calloc(count, sizeof(OscmsCtlElectorEntry));
            ASSERT_NE(known_multi_signed_ctl.full_ieee_tbs_ctl.elector_remove, nullptr);

            for (int i = 0; i < count; i++)
            {
                memcpy(
                    &known_multi_signed_ctl.full_ieee_tbs_ctl.elector_remove[i],
                    full_ieee_tbs_ctl->electorRemove.list.array[i]->buf,
                    full_ieee_tbs_ctl->electorRemove.list.array[i]->size);
            }
        }
        else
        {
            known_multi_signed_ctl.full_ieee_tbs_ctl.elector_remove     = 0;
            known_multi_signed_ctl.full_ieee_tbs_ctl.num_elector_remove = 0;
        }

        if (full_ieee_tbs_ctl->rootCaApprove.list.count > 0)
        {
            size_t count = full_ieee_tbs_ctl->rootCaApprove.list.count;

            known_multi_signed_ctl.full_ieee_tbs_ctl.num_root_ca_approve = count;
            known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_approve =
                (OscmsRootCaEntry *)calloc(count, sizeof(OscmsRootCaEntry));
            ASSERT_NE(known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_approve, nullptr);

            for (int i = 0; i < count; i++)
            {
                memcpy(
                    &known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_approve[i],
                    full_ieee_tbs_ctl->rootCaApprove.list.array[i]->buf,
                    full_ieee_tbs_ctl->rootCaApprove.list.array[i]->size);
            }
        }
        else
        {
            known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_approve     = 0;
            known_multi_signed_ctl.full_ieee_tbs_ctl.num_root_ca_approve = 0;
        }

        if (full_ieee_tbs_ctl->rootCaRemove.list.count > 0)
        {
            size_t count = full_ieee_tbs_ctl->rootCaRemove.list.count;

            known_multi_signed_ctl.full_ieee_tbs_ctl.num_root_ca_remove = count;
            known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_remove =
                (OscmsRootCaEntry *)calloc(count, sizeof(OscmsRootCaEntry));
            ASSERT_NE(known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_remove, nullptr);

            for (int i = 0; i < count; i++)
            {
                memcpy(
                    &known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_remove[i],
                    full_ieee_tbs_ctl->rootCaRemove.list.array[i]->buf,
                    full_ieee_tbs_ctl->rootCaRemove.list.array[i]->size);
            }
        }
        else
        {
            known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_remove     = 0;
            known_multi_signed_ctl.full_ieee_tbs_ctl.num_root_ca_remove = 0;
        }

        // Re-encode all the certificates in the `unsigned` sequence
        if (decoded_multi_signed_ctl->Unsigned.choice.SequenceOfCertificate.list.count > 0)
        {
            size_t count                 = decoded_multi_signed_ctl->Unsigned.choice.SequenceOfCertificate.list.count;
            Certificate **internal_certs = decoded_multi_signed_ctl->Unsigned.choice.SequenceOfCertificate.list.array;

            known_multi_signed_ctl.cert_count = count;
            known_multi_signed_ctl.certs      = (OscmsOctetBuffer *)calloc(count, sizeof(OscmsOctetBuffer));
            ASSERT_NE(known_multi_signed_ctl.certs, nullptr);
            for (int i = 0; i < count; i++)
            {
                ASSERT_EQ(
                    0, check_and_encode(internal_certs[i], &asn_DEF_Certificate, &known_multi_signed_ctl.certs[i]));
            }
        }
        else
        {
            known_multi_signed_ctl.certs      = 0;
            known_multi_signed_ctl.cert_count = 0;
        }

        if (decoded_multi_signed_ctl->signatures.list.count > 0)
        {
            size_t count = decoded_multi_signed_ctl->signatures.list.count;

            known_multi_signed_ctl.signature_count = count;
            known_multi_signed_ctl.ctl_signatures  = (OscmsOctetBuffer *)calloc(count, sizeof(OscmsOctetBuffer));
            ASSERT_NE(known_multi_signed_ctl.ctl_signatures, nullptr);

            for (int i = 0; i < count; i++)
            {
                ASSERT_EQ(
                    0,
                    check_and_encode(
                        decoded_multi_signed_ctl->signatures.list.array[i],
                        &asn_DEF_CtlSignatureSpdu,
                        &known_multi_signed_ctl.ctl_signatures[i]));
            }
        }
        else
        {
            known_multi_signed_ctl.ctl_signatures  = 0;
            known_multi_signed_ctl.signature_count = 0;
        }

        ASN_STRUCT_FREE(asn_DEF_ScmsPdu, scms_pdu);
        ASN_STRUCT_FREE(asn_DEF_ScmsPdu, inner_scms_pdu);
        decomposed = true;
    }

    void ReleaseDecomposed()
    {
        if (!decomposed)
            return;

        oscms_empty_octet_buffer(&encoded_multi_signed_ctl_spdu);

        if (known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_approve != 0)
            free(known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_approve),
                known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_approve = 0;

        if (known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_remove != 0)
            free(known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_remove),
                known_multi_signed_ctl.full_ieee_tbs_ctl.root_ca_remove = 0;

        if (known_multi_signed_ctl.full_ieee_tbs_ctl.elector_approve != 0)
            free(known_multi_signed_ctl.full_ieee_tbs_ctl.elector_approve),
                known_multi_signed_ctl.full_ieee_tbs_ctl.elector_approve = 0;

        if (known_multi_signed_ctl.full_ieee_tbs_ctl.elector_remove != 0)
            free(known_multi_signed_ctl.full_ieee_tbs_ctl.elector_remove),
                known_multi_signed_ctl.full_ieee_tbs_ctl.elector_remove = 0;

        if (known_multi_signed_ctl.certs != 0)
        {
            for (int i = 0; i < known_multi_signed_ctl.cert_count; i++)
            {
                oscms_empty_octet_buffer(&known_multi_signed_ctl.certs[i]);
            }
            free(known_multi_signed_ctl.certs), known_multi_signed_ctl.certs = 0;
        }

        if (known_multi_signed_ctl.ctl_signatures != 0)
        {
            for (int i = 0; i < known_multi_signed_ctl.signature_count; i++)
            {
                oscms_empty_octet_buffer(&known_multi_signed_ctl.ctl_signatures[i]);
            }
            free(known_multi_signed_ctl.ctl_signatures), known_multi_signed_ctl.ctl_signatures = 0;
        }

        memset(&known_multi_signed_ctl, 0, sizeof(known_multi_signed_ctl));
        decomposed = false;
    }

    // void SetUp() override
    // {
    // }

    void TearDown() override
    {
        ReleaseDecomposed();
        oscms_empty_octet_buffer(&encoded_multi_signed_ctl_spdu);
    }
};

TEST_F(MultiSignedCtlTest, DecomposeCompositeCrl)
{
    DecomposeCompositeCrl();
}

TEST_F(MultiSignedCtlTest, ReleaseDecomposed)
{
    DecomposeCompositeCrl();
    ReleaseDecomposed();
    ReleaseDecomposed();
}

TEST_F(MultiSignedCtlTest, EncodeSpduSuccess)
{
    TrackedOctetBuffer encoded;
    DecomposeCompositeCrl();
    ASSERT_EQ(oscms_encode_multi_signed_ctl_spdu(&known_multi_signed_ctl, encoded), 0);
    ASSERT_NE(encoded.length(), 0);
    ASSERT_NE(encoded.data(), nullptr);

    ASSERT_TRUE(oscms_octet_buffer_compare(encoded, &encoded_multi_signed_ctl_spdu));

    MultiSignedCtlSpdu_t *decoded = {};
    ASSERT_EQ(decode_and_check(encoded, &asn_DEF_MultiSignedCtlSpdu, (void **)&decoded), 0);
    ASN_STRUCT_FREE(asn_DEF_MultiSignedCtlSpdu, decoded);
}
