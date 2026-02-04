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

// System includes (e.g. <stdio.h>)

#include <stdlib.h>

// API includes
#include "oscms_codecs_api/base_types.h"
#include "oscms_codecs_api/logging.h"

// Project internal includes

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/Ieee1609Dot2Content.h"
#include "oscms_asn1c_generated/Ieee1609Dot2Data-Signed.h"

// local types and constants

/**
 * Generate the SignedData payload, containing the unsecured data
 *
 * The bottom layer of the SignedData payload is the unsecured data, which contains
 * in an Ieee1609Dot2Data_t structure.
 *
 * @param[in] args A pointer to the input arguments
 * @param[out] signed_data_payload A pointer to the SignedDataPayload_t to fill in
 *
 * @note The caller is responsible for freeing the SignedDataPayload_t structure and its contents
 *
 * @return 1 on success, 0 on failure
 */
static int generate_payload(const OscmsOctetBuffer *tbs_data_payload, SignedDataPayload_t **signed_data_payload)
{
    if (!tbs_data_payload || !signed_data_payload)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    // Get all the memory allocation and error checks out of the way first
    OscmsOctet *unsecured_data = (OscmsOctet *)calloc(tbs_data_payload->length, sizeof(OscmsOctet));
    if (!unsecured_data)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for unsecured data", __func__);
        return -1;
    }

    Ieee1609Dot2Content_t *content = (Ieee1609Dot2Content_t *)calloc(1, sizeof(Ieee1609Dot2Content_t));
    if (!content)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for Ieee1609Dot2Content_t", __func__);
        if (unsecured_data)
        {
            (void)explicit_bzero(unsecured_data, tbs_data_payload->length);
        }
        free(unsecured_data);
        return -1;
    }

    Ieee1609Dot2Data_t *data = (Ieee1609Dot2Data_t *)calloc(1, sizeof(Ieee1609Dot2Data_t));
    if (!data)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for Ieee1609Dot2Data_t", __func__);
        if (unsecured_data)
        {
            (void)explicit_bzero(unsecured_data, tbs_data_payload->length);
        }
        free(unsecured_data);
        free(content);
        return -1;
    }

    *signed_data_payload = (SignedDataPayload_t *)calloc(1, sizeof(SignedDataPayload_t));
    if (!*signed_data_payload)
    {
        if (unsecured_data)
        {
            (void)explicit_bzero(unsecured_data, tbs_data_payload->length);
        }
        free(unsecured_data);
        free(content);
        free(data);
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for SignedDataPayload_t", __func__);
        return -1;
    }

    // Now fill it in from the bottom up.

    // Fill in the IeeeDot2DataContent with the unsecured data
    content->present                   = Ieee1609Dot2Content_PR_unsecuredData;
    content->choice.unsecuredData.buf  = unsecured_data;
    content->choice.unsecuredData.size = tbs_data_payload->length;
    memcpy(unsecured_data, tbs_data_payload->data, tbs_data_payload->length);

    // Fill in the IeeeDot2Data
    data->protocolVersion = 3;
    data->content         = content;

    // Finally, the SignedDataPayload
    (*signed_data_payload)->data        = data;
    (*signed_data_payload)->extDataHash = 0;
    (*signed_data_payload)->omitted     = 0;
    return 0;
}

int generate_tbs_data(
    const OscmsOctetBuffer *tbs_data_payload, const OscmsPsid tbs_data_payload_psid, ToBeSignedData_t **tbs_data)
{
    if (!tbs_data_payload || !tbs_data)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    *tbs_data = (ToBeSignedData_t *)calloc(1, sizeof(ToBeSignedData_t));
    if (!*tbs_data)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for ToBeSignedData_t", __func__);
        return -1;
    }

    int rc = generate_payload(tbs_data_payload, &(*tbs_data)->payload);
    if (rc != 0)
    {
        oscms_log(LOG_CRIT, "%s: generate_payload failed", __func__);
        ASN_STRUCT_FREE(asn_DEF_ToBeSignedData, (void *)(*tbs_data));
        *tbs_data = 0;
        return -1;
    }

    (*tbs_data)->headerInfo.psid = tbs_data_payload_psid;

    return 0;
}

static int oscms_encode_to_be_signed_data(const ToBeSignedData_t *tbs_data, OscmsOctetBuffer *buffer)
{
    if (!buffer || !tbs_data)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    if (check_and_encode(tbs_data, &asn_DEF_ToBeSignedData, buffer) != 0)
    {
        return -1;
    }

    return 0;
}

SO_EXPORT int oscms_encode_tbs_data(
    const OscmsOctetBuffer *tbs_data_payload, const OscmsPsid tbs_data_payload_psid, OscmsOctetBuffer *buffer)
{
    if (!tbs_data_payload || !buffer)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameter provided", __func__);
        return -1;
    }

    ToBeSignedData_t *tbs_data = {0};

    int rc = generate_tbs_data(tbs_data_payload, tbs_data_payload_psid, &tbs_data);
    if (rc != 0)
    {
        oscms_log(LOG_CRIT, "%s: generate_tbs_data failed", __func__);
        return -1;
    }

    rc = oscms_encode_to_be_signed_data(tbs_data, buffer);

    oscms_log(LOG_DEBUG, "%s: oscms_encode_to_be_signed_data rc = %d", __func__, rc);
    ASN_STRUCT_FREE(asn_DEF_ToBeSignedData, tbs_data);
    return rc;
}
