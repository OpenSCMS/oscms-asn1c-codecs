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
#include "oscms_codecs_api/oscms_ee_eca_cert_request.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

#include "oscms_asn1c_generated/EeEcaCertRequest.h"

SO_EXPORT int oscms_ee_eca_cert_request_from_internal(
    const void *internal_void, OscmsEeEcaCertRequest *ee_eca_cert_request)
{
    if (!internal_void || !ee_eca_cert_request)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    const EeEcaCertRequest_t *internal = (const EeEcaCertRequest_t *)internal_void;
    (void)memset(ee_eca_cert_request, 0, sizeof(OscmsEeEcaCertRequest));

    if (internal->type > OSCMS_CERTIFICATE_TYPE_MAX || internal->type < 0)
    {
        oscms_log(LOG_ERR, "%s: Invalid certificate type", __func__);
        return -1;
    }

    if (internal->generationTime > UINT32_MAX)
    {
        oscms_log(LOG_ERR, "%s: Invalid generation time", __func__);
        return -1;
    }

    ee_eca_cert_request->generation_time  = (OscmsTime32)internal->generationTime;
    ee_eca_cert_request->certificate_type = (OscmsCertificateType)internal->type;

    if (oscms_tbs_certificate_from_internal(&internal->tbsCert, &ee_eca_cert_request->tbs_certificate) != 0)
    {
        goto error_cleanup;
    }

    if (!internal->canonicalId)
    {
        return 0;
    }

    ee_eca_cert_request->canonical_id =
        oscms_octet_buffer_new_from_buffer(internal->canonicalId->buf, internal->canonicalId->size);

    if (!ee_eca_cert_request->canonical_id)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for canonicalId", __func__);
        goto error_cleanup;
    }

    if (oscms_sequence_add(&ee_eca_cert_request->allocations, ee_eca_cert_request->canonical_id->data) != 0)
    {
        goto error_cleanup;
    }

    if (oscms_sequence_add(&ee_eca_cert_request->allocations, ee_eca_cert_request->canonical_id) != 0)
    {
        goto error_cleanup;
    }
    return 0;

error_cleanup:
    oscms_empty_ee_eca_cert_request(ee_eca_cert_request);
    return -1;
}
