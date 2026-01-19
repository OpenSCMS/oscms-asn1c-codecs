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

#ifndef OSCMS_TBS_DATA_H
#define OSCMS_TBS_DATA_H

#include "oscms_asn1c_generated/ToBeSignedData.h"
#include "oscms_codecs_api/base_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Generate the ToBeSignedData_t structure
     *
     * The ToBeSignedData_t structure contains the PSID and the SignedData payload
     *
     * @param[in] tbs_data_payload A pointer to the payload data to be included in the ToBeSignedData_t structure
     * @param[in] tbs_data_payload_psid A pointer to the PSID to be included in the ToBeSignedData_t structure
     * @param[out] tbs_data A pointer to a pointer to the ToBeSignedData_t structure to be filled in
     *
     * @return 0 on success, -1 on failure
     *
     * @note The caller is responsible for freeing the ToBeSignedData_t structure and its contents
     */
    int generate_tbs_data(const OscmsOctetBuffer *tbs_data_payload,
                          const OscmsPsid tbs_data_payload_psid,
                          ToBeSignedData_t **tbs_data);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // OSCMS_TBS_DATA_H
