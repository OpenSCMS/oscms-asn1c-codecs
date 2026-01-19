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

#include <errno.h>

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_sequence.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "oscms_asn1c_generated/OCTET_STRING.h"

int oscms_octet_buffer_init_from_octet_string(
    const void *octet_string_void, OscmsOctetBuffer *octet_buffer, OscmsSequence *tracker)
{
    if (!octet_string_void || !octet_buffer)
    {
        return -1;
    }

    const OCTET_STRING_t *octet_string = (const OCTET_STRING_t *)octet_string_void;

    if (oscms_octet_buffer_init_from_buffer(octet_buffer, octet_string->buf, octet_string->size) != 0)
    {
        return -1;
    }

    if (tracker)
    {
        if (oscms_track_other(octet_buffer->data, tracker) != 0)
        {
            oscms_empty_octet_buffer(octet_buffer);
            return -1;
        }
    }

    return 0;
}

int oscms_octet_string_init_from_buffer(const uint8_t *buffer, size_t length, void *octet_string_void)
{
    if (!octet_string_void)
    {
        oscms_log(LOG_CRIT, "%s: octet_string_void is NULL", __func__);
        return -1;
    }

    // The ASN1C codecs uses an `int` for the buffer size, so we need to check if the buffer is too large
    if (length > INT_MAX)
    {
        oscms_log(LOG_CRIT, "%s: Buffer size too large: %zu", __func__, length);
        return -1;
    }

    memset(octet_string_void, 0, sizeof(OCTET_STRING_t));

    errno  = 0;
    int rc = OCTET_STRING_fromBuf((OCTET_STRING_t *)octet_string_void, (const char *)buffer, (int)length);

    if (rc != 0 || errno != 0)
    {
        oscms_log(LOG_CRIT, "%s: Failed to initialize OCTET STRING", __func__);
    }

    return 0;
}

int oscms_octet_string_init_from_octet_buffer(const OscmsOctetBuffer *octet_buffer, void *octet_string_void)
{
    if (!octet_buffer)
    {
        oscms_log(LOG_CRIT, "%s: octet_buffer is NULL", __func__);
        return -1;
    }

    OCTET_STRING_t *octet_string = (OCTET_STRING_t *)octet_string_void;
    return oscms_octet_string_init_from_buffer(octet_buffer->data, octet_buffer->length, octet_string);
}
