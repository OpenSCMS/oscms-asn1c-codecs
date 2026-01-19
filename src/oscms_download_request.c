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

#include "oscms_codecs_api/oscms_download_request.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/EeRaDownloadRequestPlainSpdu.h"
#include "oscms_asn1c_generated/ScmsPdu-Scoped.h"

SO_EXPORT int oscms_decode_ee_ra_download_request(const OscmsOctetBuffer *encoded, OscmsEeRaDownloadRequest *request)
{
    if (!encoded || !encoded->data || encoded->length == 0 || !request)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    ScmsPdu_t *scms_pdu = NULL;
    (void)memset(request, 0, sizeof(OscmsEeRaDownloadRequest));

    if (decode_and_check(encoded, &asn_DEF_ScmsPdu, (void **)&scms_pdu) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to decode ScmsPdu", __func__);
        return -1;
    }

    if (scms_pdu->content.present != ScmsPdu__content_PR_ee_ra ||
        scms_pdu->content.choice.ee_ra.present != EeRaInterfacePdu_PR_eeRaDownloadRequest)
    {
        ASN_STRUCT_FREE(asn_DEF_ScmsPdu, scms_pdu);
        oscms_log(LOG_ERR, "%s: Invalid ScmsPdu", __func__);
        return -1;
    }

    EeRaDownloadRequest_t *internal = &scms_pdu->content.choice.ee_ra.choice.eeRaDownloadRequest;

    if (internal->generationTime > UINT32_MAX)
    {
        ASN_STRUCT_FREE(asn_DEF_ScmsPdu, scms_pdu);
        oscms_log(LOG_ERR, "%s: Invalid generation time", __func__);
        return -1;
    }
    request->generation_time = (OscmsTime32)internal->generationTime;

    if (oscms_octet_buffer_init_from_octet_string(&internal->filename, &request->filename, 0) != 0)
    {
        ASN_STRUCT_FREE(asn_DEF_ScmsPdu, scms_pdu);
        oscms_log(LOG_ERR, "%s: Failed to unpack filename", __func__);
        return -1;
    }

    ASN_STRUCT_FREE(asn_DEF_ScmsPdu, scms_pdu);
    return 0;
}

SO_EXPORT int oscms_decode_ee_ra_download_request_plain_spdu(
    const OscmsOctetBuffer *encoded, OscmsEeRaDownloadRequest *request)
{
    if (!encoded || !encoded->data || encoded->length == 0 || !request)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    // Decode the outer wrapper, which is a constrained Ieee1609Dot2Data-Unsecured
    EeRaDownloadRequestPlainSpdu_t *internal = NULL;
    if (decode_and_check(encoded, &asn_DEF_EeRaDownloadRequestPlainSpdu, (void **)&internal) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to decode EeRaDownloadRequestPlainSpdu", __func__);
        return -1;
    }

    // The unsecured content is the EeRaDownloadRequest encoded as an ScmsPdu
    OscmsOctetBuffer content = {
        .length = internal->content->choice.unsecuredData.size,
        .data   = internal->content->choice.unsecuredData.buf,
    };

    int rc = oscms_decode_ee_ra_download_request(&content, request);
    ASN_STRUCT_FREE(asn_DEF_EeRaDownloadRequestPlainSpdu, internal);
    return rc;
}
