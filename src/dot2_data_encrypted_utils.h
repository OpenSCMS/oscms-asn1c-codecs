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

#ifndef OSCMS_DOT2_DATA_ENCRYPTED_UTILS_H
#define OSCMS_DOT2_DATA_ENCRYPTED_UTILS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "oscms_codecs_api/dot2_data_encrypted.h"

#include "oscms_asn1c_generated/Ieee1609Dot2Data-Encrypted.h"

    /**
     * @brief Encode an OscmsDot2DataEncrypted into an EncryptedData_t
     *
     * @param dot2_data_encrypted The OSCMS representation of an EncryptedData object
     * @param internal           The CODEC representation of an EncryptedData object
     *
     * @return 0 on success
     */
    int encode_encrypted_data(const OscmsDot2DataEncrypted *dot2_data_encrypted, EncryptedData_t *internal);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // OSCMS_DOT2_DATA_ENCRYPTED_UTILS_H
