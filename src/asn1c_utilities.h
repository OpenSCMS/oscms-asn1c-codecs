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

/**
 * @file asn1c_utilities.h
 * @brief Simple utilties for wrapping calls to the asn1c library
 *
 * Functions in this module wrap common code sequences encountered in interfacing with
 * the ASN1C generated code, such as encoding and decoding with error checking.
 */

#ifndef ASN1C_UTILITIES_H
#define ASN1C_UTILITIES_H

#include "oscms_codecs_api/base_types.h"

#include "oscms_asn1c_generated/asn_SEQUENCE_OF.h"
#include "oscms_asn1c_generated/asn_application.h"

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

    /**
     * @brief Decode COER-encoded data and check the constraints
     *
     * @param encoded_data COER encoded data to be decoded
     * @param td ASN.1 type descriptor fpr the tpe definition to control decoding
     * @param sptr Pointer to a pointer to a compatible internal structure to hold the output.
     *
     * The output structure will be dynamically allocated and must be freed by the caller using the ASN_STRUCT_FREE
     * macro.
     *
     * @return 0 on success
     */
    int decode_and_check(const OscmsOctetBuffer *encoded_data, const asn_TYPE_descriptor_t *td, void **sptr);

    /**
     * @brief Check the constraints on an internal structure and encode it
     *
     * @param sptr Pointer to a compatible internal structure to check and encode
     * @param td ASN.1 type descriptor fpr the tpe definition to control encoding
     * @param encoded Output buffer to hold the encoded data
     *
     * The output buffer will be dynamically allocated and must be freed by the caller using oscms_free_octet_buffer.
     *
     * @return 0 on success
     */
    int check_and_encode(const void *sptr, const asn_TYPE_descriptor_t *td, OscmsOctetBuffer *encoded);

    /**
     * @brief Pre-allocate and ASN1C SEQUENCE_OF structure
     *
     * Initialize an anonymous SEQUENCE_OF structure for encoding purposes.
     *
     * The embedded array of pointers is pre-allcoated, and then each element is also allocated ready for use.
     * This avoids the need to call asn_sequence_add, with it's inherent risk of errors on a re-allocation.
     *
     * @param elements Number of elements to be allocated
     * @param element_size Size of each element
     * @param sptr Pointer to a pointer to a compatible internal structure to hold the output.
     *
     * @return 0 on success
     */

    int allocate_asn1c_sequence_of(size_t elements, size_t element_size, asn_anonymous_sequence_ *sptr);

    /**
     * @brief Add an element to an ASN1C SEQUENCE_OF structure with full error checking
     *
     * @param sequence Pointer to the ASN1C SEQUENCE_OF structure
     * @param element Pointer to the element to be added
     *
     * @return 0 on success
     */
    int asn1c_add_to_sequence(void *sequence, void *pointer);
#ifdef __cplusplus
}
#endif //__cplusplus
#endif // ASN1C_UTILITIES_H
