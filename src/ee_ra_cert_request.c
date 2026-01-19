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

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ee_ra_cert_request.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "oscms_asn1c_generated/EeRaCertRequest.h"

#include "public_encryption_key.h"

SO_EXPORT int oscms_ee_ra_cert_request_from_internal(const void *internal_void, OscmsEeRaCertRequest *request)
{
    if (!internal_void || !request)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    memset(request, 0, sizeof(OscmsEeRaCertRequest));
    const EeRaCertRequest_t *internal = (const EeRaCertRequest_t *)internal_void;

    if (internal->generationTime > UINT32_MAX)
    {
        oscms_log(LOG_ERR, "%s: Invalid generation time", __func__);
        return -1;
    }

    request->generation_time = internal->generationTime;

    if (internal->type > OSCMS_CERTIFICATE_TYPE_MAX)
    {
        oscms_log(LOG_ERR, "%s: Invalid certificate type", __func__);
        return -1;
    }

    request->certificate_type = (OscmsCertificateType)internal->type;

    if (oscms_tbs_certificate_from_internal(&internal->tbsCert, &request->tbs_certificate) != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to unpack TbsCertificate", __func__);
        return -1;
    }

    if (internal->additionalParams)
    {
        request->additional_params = oscms_tracked_malloc(sizeof(OscmsAdditionalParams), &request->allocations);
        if (!request->additional_params)
        {
            oscms_log(LOG_ERR, "%s: Failed to allocate AdditionalParams", __func__);
            return -1;
        }
        request->additional_params->type = (OscmsAdditionalParamsType)internal->additionalParams->present;
        switch (request->additional_params->type)
        {
            case OSCMS_ADDITIONAL_PARAMS_TYPE_ORIGINAL:
            {
                const ButterflyParamsOriginal_t *original_internal = &internal->additionalParams->choice.original;
                OscmsButterflyParamsOriginal *original_request     = &request->additional_params->parameter.original;

                if (original_internal->signingExpansion.present != ButterflyExpansion_PR_aes128)
                {
                    return -1;
                }

                if (oscms_octet_buffer_init_from_octet_string(
                        &original_internal->signingExpansion.choice.aes128,
                        &original_request->signing_expansion,
                        &request->allocations) != 0)
                {
                    return -1;
                }

                if (original_internal->encryptionExpansion.present != ButterflyExpansion_PR_aes128)
                {
                    return -1;
                }

                if (oscms_octet_buffer_init_from_octet_string(
                        &original_internal->encryptionExpansion.choice.aes128,
                        &original_request->encryption_expansion,
                        &request->allocations) != 0)
                {
                    return -1;
                }

                if (oscms_public_encryption_key_from_internal(
                        &original_internal->encryptionKey, &original_request->encryption_key, &request->allocations) !=
                    0)
                {
                    return -1;
                }
                break;
            }

            case OSCMS_ADDITIONAL_PARAMS_TYPE_UNIFIED:

                if (internal->additionalParams->choice.unified.present != ButterflyExpansion_PR_aes128)
                {
                    return -1;
                }

                if (oscms_octet_buffer_init_from_octet_string(
                        &internal->additionalParams->choice.unified.choice.aes128,
                        &request->additional_params->parameter.unified,
                        &request->allocations) != 0)
                {
                    return -1;
                }
                break;

            case OSCMS_ADDITIONAL_PARAMS_TYPE_COMPACT_UNIFIED:

                if (internal->additionalParams->choice.compactUnified.present != ButterflyExpansion_PR_aes128)
                {
                    return -1;
                }

                if (oscms_octet_buffer_init_from_octet_string(
                        &internal->additionalParams->choice.compactUnified.choice.aes128,
                        &request->additional_params->parameter.compact_unified,
                        &request->allocations) != 0)
                {
                    return -1;
                }
                break;

            case OSCMS_ADDITIONAL_PARAMS_TYPE_ENCRYPTION_KEY:
                if (oscms_public_encryption_key_from_internal(
                        &internal->additionalParams->choice.encryptionKey,
                        &request->additional_params->parameter.encryption_key,
                        &request->allocations) != 0)
                {
                    return -1;
                }
                break;

            default:
                oscms_log(LOG_ERR, "%s: Unsupported AdditionalParams type", __func__);
                return -1;
        }
    }

    return 0;
}
