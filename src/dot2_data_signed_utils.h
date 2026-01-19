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

#ifndef OSCMS_DOT2_DATA_SIGNED_UTILS_H
#define OSCMS_DOT2_DATA_SIGNED_UTILS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "oscms_codecs_api/dot2_data_signed.h"

#include "oscms_asn1c_generated/Ieee1609Dot2Data-Signed.h"

    /**
     * Generate the SignedData_t structure
     *
     * The SignedData_t structure contains the hash algorithm, the ToBeSignedData_t structure,
     * and the SignerIdentifier_t structure and signature.
     *
     * @param[in] args A pointer to the input arguments
     * @param[out] signed_data A pointer to a pointer to the SignedData_t structure to be filled in
     *
     * @note The caller is responsible for freeing the SignedData_t structure and its contents
     *
     * @return 0 on success, -1 on failure
     */
    int generate_signed_data(const OscmsDot2DataSignedArgs *args, SignedData_t **signed_data);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // OSCMS_DOT2_DATA_SIGNED_UTILS_H
