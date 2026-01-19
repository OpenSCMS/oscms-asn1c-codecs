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

#include "asn1c_utilities.h"
#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"

int decode_and_check(const OscmsOctetBuffer *encoded_data, const asn_TYPE_descriptor_t *td, void **sptr)
{
    if (!encoded_data || !td || !sptr || !encoded_data->data || encoded_data->length == 0)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    *sptr = 0; // Important, as this triggers the decoder to allocate memory for the decoded structure
    errno = 0;

    // Perform the actual decoding
    asn_dec_rval_t rval = asn_decode(0, ATS_CANONICAL_OER, td, sptr, encoded_data->data, encoded_data->length);
    if (rval.code != RC_OK || rval.consumed != encoded_data->length || errno != 0)
    {
        oscms_log(
            LOG_ERR,
            "%s: Failed to decode data as %s. Code = %d, consumed = %zu, data length = %zu",
            __func__,
            td->name,
            rval.code,
            rval.consumed,
            encoded_data->length);
        if (*sptr)
        {
            ASN_STRUCT_FREE(*td, *sptr);
            *sptr = 0;
        }
        return -1;
    }

    // Check for any constraint violations, and free the allocated structure on any error
    char errbuf[256];
    size_t errbuf_len = sizeof(errbuf);
    if (asn_check_constraints(td, *sptr, errbuf, &errbuf_len) != 0)
    {
        oscms_log(LOG_ERR, "%s: asn_check_constraints failed for %s: %s", __func__, td->name, errbuf);
        ASN_STRUCT_FREE(*td, *sptr);
        *sptr = 0;
        return -1;
    }

    return 0;
}

int check_and_encode(const void *sptr, const asn_TYPE_descriptor_t *td, OscmsOctetBuffer *encoded)
{
    if (!sptr || !td || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    encoded->data   = 0;
    encoded->length = 0;

    // Check for any constraint violations before encoding
    char errbuf[256];
    size_t errbuf_len = sizeof(errbuf);
    if (asn_check_constraints(td, sptr, errbuf, &errbuf_len) != 0)
    {
        oscms_log(LOG_ERR, "%s: asn_check_constraints failed for %s: %s", __func__, td->name, errbuf);
        return -1;
    }

    // Perform the actual encoding
    errno = 0;

    asn_encode_to_new_buffer_result_t enc_rval = asn_encode_to_new_buffer(0, ATS_CANONICAL_OER, td, sptr);
    if (!enc_rval.buffer || enc_rval.result.encoded < 0 || errno != 0)
    {
        oscms_log(
            LOG_ERR, "%s: Failed to encode data as %s at %s", __func__, td->name, enc_rval.result.failed_type->name);
        return -1;
    }

    // Return the encoded data as an OscmsOctetBuffer
    encoded->data   = enc_rval.buffer;
    encoded->length = enc_rval.result.encoded;
    return 0;
}

int allocate_asn1c_sequence_of(size_t elements, size_t element_size, asn_anonymous_sequence_ *sptr)
{
    if (!sptr)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    memset(sptr, 0, sizeof(asn_anonymous_sequence_));
    if (elements == 0)
    {
        return 0;
    }

    if (elements > INT_MAX)
    {
        oscms_log(LOG_CRIT, "%s: elements > INT_MAX, and a SEQUENCE_OF can't be that large", __func__);
        return -1;
    }

    sptr->array = calloc(elements, sizeof(void *));
    if (!sptr->array)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate array", __func__);
        return -1;
    }

    sptr->size = elements;

    for (size_t i = 0; i < elements; i++)
    {
        sptr->array[i] = calloc(1, element_size);
        if (!sptr->array[i])
        {
            // We failed to allocate an entry. Free all previously allocated entries
            // and the array itself.
            for (size_t j = 0; j < i; j++)
            {
                free(sptr->array[j]), sptr->array[j] = 0;
            }
            free(sptr->array), sptr->array = 0;
            sptr->count = sptr->size = 0;
            oscms_log(LOG_CRIT, "%s: Failed to allocate element %zu", __func__, i);
            return -1;
        }
        sptr->count++;
    }

    return 0;
}

int asn1c_add_to_sequence(void *sequence, void *pointer)
{
    if (!sequence)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    errno  = 0;
    int rc = asn_sequence_add(sequence, pointer);

    if (rc < 0 || errno != 0)
    {
        return -1;
    }

    return 0;
}
