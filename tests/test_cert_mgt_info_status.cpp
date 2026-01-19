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

#include "oscms_codecs_api/cert_mgt_info_status.h"

#include "asn1c_utilities.h"

#include "test_utils.hpp"

#include <ScmsPdu.h>

TEST(EncodeCertManagementPdu, NullParams)
{
    OscmsCertManagementPduArgs args = {0};
    OscmsOctetBuffer spdu           = {0};

    int rc = oscms_encode_cert_mngt_pdu(nullptr, nullptr);
    EXPECT_EQ(rc, -1);

    rc = oscms_encode_cert_mngt_pdu(&args, nullptr);
    EXPECT_EQ(rc, -1);

    rc = oscms_encode_cert_mngt_pdu(nullptr, &spdu);
    EXPECT_EQ(rc, -1);
}

TEST(EncodeCertManagementPdu, NullCrlArgValues)
{
    OscmsCertManagementPduArgs args = {0};
    OscmsOctetBuffer spdu           = {};

    args.crl_count       = 1;
    args.crl_series_list = nullptr;
    args.crl_issue_dates = nullptr;
    args.crl_craca_ids   = nullptr;
    int rc               = oscms_encode_cert_mngt_pdu(&args, &spdu);
    EXPECT_EQ(rc, -1);
}

TEST(EncodeCertManagementPdu, NullCtlArgValues)
{
    OscmsCertManagementPduArgs args = {0};
    OscmsOctetBuffer spdu           = {};

    args.ctl_count             = 1;
    args.ctl_series_ids        = nullptr;
    args.ctl_last_update_times = nullptr;
    args.ctl_sequence_numbers  = nullptr;
    int rc                     = oscms_encode_cert_mngt_pdu(&args, &spdu);
    EXPECT_EQ(rc, -1);
}

TEST(EncodeCertManagementPdu, NullMaArgValues)
{
    OscmsCertManagementPduArgs args = {0};
    OscmsOctetBuffer spdu           = {};

    args.ma_count            = 1;
    args.ma_psid_lists       = nullptr;
    args.ma_updated_times    = nullptr;
    args.ma_psid_list_counts = nullptr;
    int rc                   = oscms_encode_cert_mngt_pdu(&args, &spdu);
    EXPECT_EQ(rc, -1);
}

static void known_cert_management_pdu(OscmsCertManagementPduArgs *args)
{
    static OscmsTime32 crl_issue_dates[]   = {1757440535};
    static OscmsCrlSeries crl_series_ids[] = {1};

    args->ma_count            = 0;
    args->ma_psid_lists       = nullptr;
    args->ma_psid_list_counts = nullptr;
    args->ma_psid_list_counts = nullptr;
    args->ma_updated_times    = nullptr;
    args->ma_updated_times    = nullptr;

    static OscmsCtlSequenceNumber ctl_sequence_numbers[1] = {0};
    static OscmsTime32 ctl_last_update_times[1]           = {1757442522};
    static OscmsCtlSeriesId series255                     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};
    static uint8_t *ctl_series_ids[1]                     = {series255};
    static OscmsHashedId8 craca_id                        = {0x15, 0xE2, 0x98, 0xFE, 0x7B, 0x1D, 0x91, 0x99};
    static uint8_t *craca_ids[1]                          = {craca_id};

    args->ctl_count             = 1;
    args->ctl_series_ids        = ctl_series_ids;
    args->ctl_last_update_times = ctl_last_update_times;
    args->ctl_sequence_numbers  = ctl_sequence_numbers;

    args->crl_count       = 1;
    args->crl_series_list = crl_series_ids;
    args->crl_issue_dates = crl_issue_dates;
    args->crl_craca_ids   = craca_ids;

    args->ca_ccf_updated_time = 1757442522;
    args->ra_updated_time     = 1757440534;
}

TEST(EncodeCertManagementPdu, EncodeSuccess)
{
    OscmsOctetBuffer spdu                = {};
    OscmsCertManagementPduArgs known_pdu = {};
    known_cert_management_pdu(&known_pdu);
    int rc = oscms_encode_cert_mngt_pdu(&known_pdu, &spdu);
    EXPECT_EQ(rc, 0);
    EXPECT_NE(spdu.length, 0);
    EXPECT_NE(spdu.data, nullptr);
    // hexdump("Encoded CertManagement PDU", spdu.data, spdu.length);

    std::vector<uint8_t> buffer;
    ASSERT_EQ(read_binary_test_file("data/CertManagementPdu.dat", buffer), 0);

    char *file_data  = (char *)buffer.data();
    size_t file_size = buffer.size();

    EXPECT_EQ(memcmp(spdu.data, file_data, spdu.length), 0);
    EXPECT_EQ(spdu.length, file_size);

    // Decode
    OscmsOctetBuffer decoded_spdu = {.length = file_size, .data = (uint8_t *)file_data};

    ScmsPdu *internal_cmis = 0;
    EXPECT_EQ(decode_and_check(&decoded_spdu, &asn_DEF_ScmsPdu, (void **)&internal_cmis), 0);
    ASN_STRUCT_FREE(asn_DEF_ScmsPdu, internal_cmis);
    free(spdu.data);
}
