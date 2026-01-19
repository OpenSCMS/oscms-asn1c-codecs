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

#include "oscms_asn1c_generated/EccP256CurvePoint.h"
#include "oscms_asn1c_generated/EccP384CurvePoint.h"

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ecc_curve.h"

int oscms_ecc_curve_point_from_internal(
    const void *internal_void,
    OscmsEccPointCurveType curve_type,
    OscmsEccCurvePoint *ecc_curve_point,
    OscmsSequence *tracker)
{
    if (!ecc_curve_point || !internal_void)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    memset(ecc_curve_point, 0, sizeof(*ecc_curve_point));
    ecc_curve_point->curve_type = curve_type;

    const OCTET_STRING_t *x_source = NULL;
    const OCTET_STRING_t *y_source = NULL;

    switch (curve_type)
    {
        case OSCMS_ECC_POINT_CURVE_TYPE_NONE:
            break;

        case OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256:
        case OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P256:
        case OSCMS_ECC_POINT_CURVE_TYPE_SM2:
        { // These are all P256
            const EccP256CurvePoint_t *internal = (const EccP256CurvePoint_t *)internal_void;
            ecc_curve_point->point_type         = (OscmsEccPointType)internal->present;
            switch (ecc_curve_point->point_type)
            {
                case OSCMS_ECC_POINT_TYPE_NONE:
                case OSCMS_ECC_POINT_TYPE_FILL:
                    break;

                case OSCMS_ECC_POINT_TYPE_X_ONLY:
                    x_source = &internal->choice.x_only;
                    break;
                case OSCMS_ECC_POINT_TYPE_COMPRESSED_Y_0:
                    x_source = &internal->choice.compressed_y_0;
                    break;
                case OSCMS_ECC_POINT_TYPE_COMPRESSED_Y_1:
                    x_source = &internal->choice.compressed_y_1;
                    break;
                case OSCMS_ECC_POINT_TYPE_UNCOMPRESSED:
                    x_source = &internal->choice.uncompressedP256.x;
                    y_source = &internal->choice.uncompressedP256.y;
                    break;

                default:
                    oscms_log(LOG_ERR, "%s: Invalid point type: %d", __func__, ecc_curve_point->point_type);
                    return -1;
            }

            break;
        }
        case OSCMS_ECC_POINT_CURVE_TYPE_NIST_P384:
        case OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P384:
        { // These are all P256
            const EccP384CurvePoint_t *internal = (const EccP384CurvePoint_t *)internal_void;
            ecc_curve_point->point_type         = (OscmsEccPointType)internal->present;
            switch (ecc_curve_point->point_type)
            {
                case OSCMS_ECC_POINT_TYPE_NONE:
                case OSCMS_ECC_POINT_TYPE_FILL:
                    break;

                case OSCMS_ECC_POINT_TYPE_X_ONLY:
                    x_source = &internal->choice.x_only;
                    break;
                case OSCMS_ECC_POINT_TYPE_COMPRESSED_Y_0:
                    x_source = &internal->choice.compressed_y_0;
                    break;
                case OSCMS_ECC_POINT_TYPE_COMPRESSED_Y_1:
                    x_source = &internal->choice.compressed_y_1;
                    break;
                case OSCMS_ECC_POINT_TYPE_UNCOMPRESSED:
                    x_source = &internal->choice.uncompressedP384.x;
                    y_source = &internal->choice.uncompressedP384.y;
                    break;

                default:
                    oscms_log(LOG_ERR, "%s: Invalid point type: %d", __func__, ecc_curve_point->point_type);
                    return -1;
            }
            break;
        }
        default:
            oscms_log(LOG_ERR, "%s: Invalid curve type: %d", __func__, curve_type);
            return -1;
    }

    if (x_source)
    {
        if (oscms_octet_buffer_init_from_octet_string(x_source, &ecc_curve_point->x, tracker) != 0)
        {
            return -1;
        }
    }

    if (y_source)
    {
        if (oscms_octet_buffer_init_from_octet_string(y_source, &ecc_curve_point->y, tracker) != 0)
        {
            return -1;
        }
    }

    return 0;
}

int oscms_internal_from_ecc_curve_point(const OscmsEccCurvePoint *ecc_curve_point, void *internal_void)
{
    if (!ecc_curve_point || !internal_void)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }
    // Internally, both Curve Point types are identical so we just deal with the P348 and P256
    // as a P256.
    EccP256CurvePoint_t *internal = (EccP256CurvePoint_t *)internal_void;

    memset(internal, 0, sizeof(*internal));
    OCTET_STRING_t *x = 0;
    OCTET_STRING_t *y = 0;
    internal->present = (EccP256CurvePoint_PR)ecc_curve_point->point_type;

    switch (ecc_curve_point->point_type)
    {
        case OSCMS_ECC_POINT_TYPE_NONE:
        case OSCMS_ECC_POINT_TYPE_FILL:
            break;

        case OSCMS_ECC_POINT_TYPE_X_ONLY:
            x = &internal->choice.x_only;
            break;

        case OSCMS_ECC_POINT_TYPE_COMPRESSED_Y_0:
            x = &internal->choice.compressed_y_0;
            break;

        case OSCMS_ECC_POINT_TYPE_COMPRESSED_Y_1:
            x = &internal->choice.compressed_y_1;
            break;

        case OSCMS_ECC_POINT_TYPE_UNCOMPRESSED:
            x = &internal->choice.uncompressedP256.x;
            y = &internal->choice.uncompressedP256.y;
            break;
    }

    if (x)
    {
        if (oscms_octet_string_init_from_octet_buffer(&ecc_curve_point->x, x) != 0)
        {
            return -1;
        }
    }

    if (y)
    {
        if (oscms_octet_string_init_from_octet_buffer(&ecc_curve_point->y, y) != 0)
        {
            return -1;
        }
    }
    return 0;
}
