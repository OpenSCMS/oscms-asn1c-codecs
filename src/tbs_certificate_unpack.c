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

#include "oscms_asn1c_generated/ToBeSignedCertificate.h"

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ecc_curve.h"
#include "oscms_codecs_api/oscms_sequence.h"
#include "oscms_codecs_api/oscms_tbs_certificate.h"
#include "oscms_codecs_api/oscms_utilities.h"

static int unpack_certificate_id(const CertificateId_t *internal, OscmsTbsCertificate *tbs_cert)
{
    OscmsCertificateId *id = &tbs_cert->id;
    memset(id, 0, sizeof(*id));

    id->type = (OscmsCertificateIdType)internal->present;
    switch (id->type)
    {
        case OSCMS_CERTIFICATE_ID_TYPE_LINKAGE:
        {
            if (internal->choice.linkageData.iCert < 0 || internal->choice.linkageData.iCert > UINT16_MAX)
            {
                return -1;
            }
            id->value.linkage_data.i_cert = internal->choice.linkageData.iCert;

            memcpy(
                id->value.linkage_data.linkage_value,
                internal->choice.linkageData.linkage_value.buf,
                size_t_min(
                    internal->choice.linkageData.linkage_value.size, sizeof(id->value.linkage_data.linkage_value)));

            const GroupLinkageValue_t *glv_internal = internal->choice.linkageData.group_linkage_value;
            if (glv_internal)
            {
                OscmsGroupLinkageValue *glv =
                    oscms_tracked_malloc(sizeof(OscmsGroupLinkageValue), &tbs_cert->allocations);
                id->value.linkage_data.group_linkage_value = glv;

                if (!id->value.linkage_data.group_linkage_value)
                {
                    return -1;
                }

                memcpy(
                    glv->j_value,
                    glv_internal->jValue.buf,
                    size_t_min(glv_internal->jValue.size, sizeof(glv->j_value)));
                memcpy(glv->value, glv_internal->value.buf, size_t_min(glv_internal->value.size, sizeof(glv->value)));
            }
            else
            {
                id->value.linkage_data.group_linkage_value = 0;
            }

            break;
        }
        case OSCMS_CERTIFICATE_ID_TYPE_HOSTNAME:
            if (oscms_octet_buffer_init_from_octet_string(
                    &internal->choice.name, &id->value.host_name, &tbs_cert->allocations) != 0)
            {
                return -1;
            }
            break;

        case OSCMS_CERTIFICATE_ID_TYPE_BIMARY_ID:
            if (oscms_octet_buffer_init_from_octet_string(
                    &internal->choice.binaryId, &id->value.binary_id, &tbs_cert->allocations) != 0)
            {
                return -1;
            }
            break;
        case OSCMS_CERTIFICATE_ID_TYPE_NONE:
            break;

        default:
            oscms_log(LOG_ERR, "%s: Invalid certificate id type: %d", __func__, id->type);
            return -1;
    }

    return 0;
}

static int unpack_verification_key_indicator(const VerificationKeyIndicator_t *internal, OscmsTbsCertificate *tbs_cert)
{
    OscmsVerificationKeyIndicator *vki = &tbs_cert->verify_key_indicator;
    memset(vki, 0, sizeof(*vki));

    vki->type = (OscmsVerificationKeyIndicatorType)internal->present;
    switch (vki->type)
    {
        case OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_NONE:
            break;
        case OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_KEY:
            // All if the elements of the union are either EccP256CurvePoints or EccP384CurvePoints and
            // these are bascically the same datastructure so we just point to one of them.
            if (oscms_ecc_curve_point_from_internal(
                    &internal->choice.verificationKey.choice.ecdsaNistP256,
                    (OscmsEccPointCurveType)internal->choice.verificationKey.present,
                    &vki->point,
                    &tbs_cert->allocations) != 0)
            {
                return -1;
            }
            break;
        case OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_RECONSTRUCTION:
            if (oscms_ecc_curve_point_from_internal(
                    &internal->choice.reconstructionValue,
                    OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256,
                    &vki->point,
                    &tbs_cert->allocations) != 0)
            {
                return -1;
            }
            break;
        default:
            oscms_log(LOG_ERR, "%s: Invalid verification key indicator type: %d", __func__, vki->type);
            return -1;
    }

    return 0;
}

static int unpack_app_permissions(const SequenceOfPsidSsp_t *internal, OscmsTbsCertificate *tbs_cert)
{
    if (internal->list.count == 0)
    {
        tbs_cert->app_permissions = NULL;
        return 0;
    }

    tbs_cert->app_permissions =
        oscms_tracked_calloc(internal->list.count, sizeof(OscmsPsidSsp), &tbs_cert->allocations);
    if (!tbs_cert->app_permissions)
    {
        return -1;
    }

    PsidSsp_t **list                = internal->list.array;
    tbs_cert->app_permissions_count = internal->list.count;

    for (int i = 0; i < internal->list.count; i++)
    {
        PsidSsp_t *psid_ssp      = list[i];
        OscmsPsidSsp *permission = &tbs_cert->app_permissions[i];
        permission->psid         = psid_ssp->psid;
        permission->ssp          = 0;
        if (psid_ssp->ssp)
        {
            permission->ssp = oscms_tracked_malloc(sizeof(OscmsSsp), &tbs_cert->allocations);
            if (!permission->ssp)
            {
                return -1;
            }
            permission->ssp->type         = (OscmsSspType)psid_ssp->ssp->present;
            permission->ssp->value.data   = 0;
            permission->ssp->value.length = 0;

            switch (permission->ssp->type)
            {
                case OSCMS_SSP_TYPE_NONE:
                    break;

                case OSCMS_SSP_TYPE_OPAQUE:
                    if (oscms_octet_buffer_init_from_octet_string(
                            &psid_ssp->ssp->choice.opaque, &permission->ssp->value, &tbs_cert->allocations) != 0)
                    {
                        return -1;
                    }
                    break;
                case OSCMS_SSP_TYPE_BITMAP:
                    if (oscms_octet_buffer_init_from_octet_string(
                            &psid_ssp->ssp->choice.bitmapSsp, &permission->ssp->value, &tbs_cert->allocations) != 0)
                    {
                        return -1;
                    }

                    break;
            }
        }
    }
    return 0;
}

static int unpack_identified_region(
    const IdentifiedRegion_t *internal, OscmsIdentifiedRegion *region, OscmsTbsCertificate *tbs_cert)
{
    region->type = (OscmsIdentifiedRegionType)internal->present;

    switch (region->type)
    {
        case OSCMS_IDENTIFIED_REGION_TYPE_NONE:
            break;

        case OSCMS_IDENTIFIED_REGION_TYPE_COUNTRY_ONLY:
            if (internal->choice.countryOnly < 0 || internal->choice.countryOnly > UINT16_MAX)
            {
                return -1;
            }

            region->value.country = internal->choice.countryOnly;
            break;

        case OSCMS_IDENTIFIED_REGION_TYPE_COUNTRY_AND_REGIONS:
        {
            if (internal->choice.countryAndRegions.countryOnly < 0 ||
                internal->choice.countryAndRegions.countryOnly > UINT16_MAX)
            {
                return -1;
            }

            region->value.country_and_region.country = internal->choice.countryAndRegions.countryOnly;
            OscmsOctetBuffer *regions                = &region->value.country_and_region.region; // for brevity

            if (internal->choice.countryAndRegions.regions.list.count < 0)
            {
                return -1;
            }

            // ASN1C uses a long for a Uint8_t type, which means we need to do this by hand
            regions->length = internal->choice.countryAndRegions.regions.list.count;
            if (regions->length == 0)
            {
                regions->data = NULL;
                break;
            }

            regions->data = oscms_tracked_malloc(regions->length, &tbs_cert->allocations);
            if (!regions->data)
            {
                return -1;
            }

            for (size_t i = 0; i < regions->length; i++)
            {
                Uint8_t region_value = *internal->choice.countryAndRegions.regions.list.array[i];
                if (region_value < 0 || region_value > UINT8_MAX)
                {
                    return -1;
                }
                regions->data[i] = (uint8_t)region_value;
            }
            break;
        }

        case OSCMS_IDENTIFIED_REGION_TYPE_COUNTRY_AND_SUBREGIONS:
        {
            OscmsCountryAndSubregions *c_and_s             = &region->value.country_and_subregions;
            const CountryAndSubregions_t *c_and_s_internal = &internal->choice.countryAndSubregions;

            if (c_and_s_internal->countryOnly < 0 || c_and_s_internal->countryOnly > UINT16_MAX ||
                c_and_s_internal->regionAndSubregions.list.count < 0)
            {
                return -1;
            }

            c_and_s->country         = c_and_s_internal->countryOnly;
            c_and_s->subregion_count = c_and_s_internal->regionAndSubregions.list.count;

            if (c_and_s->subregion_count == 0)
            {
                c_and_s->subregions = NULL;
                break;
            }

            c_and_s->subregions = oscms_tracked_calloc(
                c_and_s->subregion_count, sizeof(OscmsRegionAndSubregions), &tbs_cert->allocations);
            if (!c_and_s->subregions)
            {
                return -1;
            }

            for (size_t i = 0; i < c_and_s->subregion_count; i++)
            {
                RegionAndSubregions_t *region_and_subregions = c_and_s_internal->regionAndSubregions.list.array[i];
                if (region_and_subregions->region < 0 || region_and_subregions->region > UINT8_MAX ||
                    region_and_subregions->subregions.list.count < 0)
                {
                    return -1;
                }

                c_and_s->subregions[i].region          = region_and_subregions->region;
                c_and_s->subregions[i].subregion_count = region_and_subregions->subregions.list.count;
                if (c_and_s->subregions[i].subregion_count == 0)
                {
                    c_and_s->subregions[i].subregions = NULL;
                    continue;
                }

                c_and_s->subregions[i].subregions = oscms_tracked_calloc(
                    region_and_subregions->subregions.list.count, sizeof(uint16_t), &tbs_cert->allocations);
                if (!c_and_s->subregions[i].subregions)
                {
                    return -1;
                }
                (void)memcpy(
                    c_and_s->subregions[i].subregions,
                    region_and_subregions->subregions.list.array,
                    sizeof(uint16_t) * region_and_subregions->subregions.list.count);
            }
            break;
        }
        default:
            oscms_log(LOG_ERR, "%s: Invalid identified region type: %d", __func__, region->type);
            return -1;
    }
    return 0;
}

static int unpack_region(const GeographicRegion_t *internal, OscmsTbsCertificate *tbs_cert)
{
    OscmsGeographicalRegion *region = oscms_tracked_malloc(sizeof(OscmsGeographicalRegion), &tbs_cert->allocations);
    if (!region)
    {
        return -1;
    }
    tbs_cert->region = region;
    region->type     = (OscmsGeographicalRegionType)internal->present;

    switch (region->type)
    {
        case OSCMS_GEOGRAPHICAL_REGION_TYPE_NONE:
            break;

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_CIRCULAR:
            if (!oscms_is_valid_latitude(internal->choice.circularRegion.center.latitude) ||
                !oscms_is_valid_longitude(internal->choice.circularRegion.center.longitude) ||
                internal->choice.circularRegion.radius < 0 || internal->choice.circularRegion.radius > UINT16_MAX)
            {
                return -1;
            }
            region->value.circular.center.latitude  = internal->choice.circularRegion.center.latitude;
            region->value.circular.center.longitude = internal->choice.circularRegion.center.longitude;
            region->value.circular.radius           = internal->choice.circularRegion.radius;
            break;

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_RECTANGULAR:

        {
            if (internal->choice.rectangularRegion.list.count < 0)
            {
                return -1;
            }
            region->value.rectangular.rectangle_count = internal->choice.rectangularRegion.list.count;

            if (region->value.rectangular.rectangle_count == 0)
            {
                region->value.rectangular.rectangles = NULL;
                break;
            }

            region->value.rectangular.rectangles = oscms_tracked_calloc(
                region->value.rectangular.rectangle_count, sizeof(OscmsRectangularRegion), &tbs_cert->allocations);
            if (!region->value.rectangular.rectangles)
            {
                return -1;
            }
            RectangularRegion_t **internal_rects = internal->choice.rectangularRegion.list.array;
            OscmsRectangularRegion *rects        = region->value.rectangular.rectangles;
            for (size_t i = 0; i < region->value.rectangular.rectangle_count; i++)
            {
                RectangularRegion_t *internal_rect = internal_rects[i];
                OscmsRectangularRegion *rect       = &rects[i];

                if (!oscms_is_valid_latitude(internal_rect->northWest.latitude) ||
                    !oscms_is_valid_longitude(internal_rect->northWest.longitude) ||
                    !oscms_is_valid_latitude(internal_rect->southEast.latitude) ||
                    !oscms_is_valid_longitude(internal_rect->southEast.longitude))
                {
                    return -1;
                }
                rect->top_left.latitude      = internal_rect->northWest.latitude;
                rect->top_left.longitude     = internal_rect->northWest.longitude;
                rect->bottom_right.latitude  = internal_rect->southEast.latitude;
                rect->bottom_right.longitude = internal_rect->southEast.longitude;
            }

            break;
        }

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_POLYGONAL:
        {
            if (internal->choice.polygonalRegion.list.count < 0)
            {
                return -1;
            }

            region->value.polygonal.point_count = internal->choice.polygonalRegion.list.count;
            region->value.polygonal.points      = NULL;

            if (region->value.polygonal.point_count == 0)
            {
                break;
            }

            region->value.polygonal.points = oscms_tracked_calloc(
                region->value.polygonal.point_count, sizeof(OscmsTwoDLocation), &tbs_cert->allocations);
            if (!region->value.polygonal.points)
            {
                return -1;
            }

            TwoDLocation_t **internal_points = internal->choice.polygonalRegion.list.array;
            OscmsTwoDLocation *points        = region->value.polygonal.points;

            for (size_t i = 0; i < region->value.polygonal.point_count; i++)
            {
                const TwoDLocation_t *internal_point = internal_points[i];
                OscmsTwoDLocation *point             = &points[i];
                if (!oscms_is_valid_latitude(internal_point->latitude) ||
                    !oscms_is_valid_longitude(internal_point->longitude))
                {
                    return -1;
                }
                point->latitude  = internal_point->latitude;
                point->longitude = internal_point->longitude;
            }
            break;
        }

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_IDENTIFIED:
        {
            if (internal->choice.identifiedRegion.list.count < 0)
            {
                return -1;
            }
            region->value.identified_regions.count = internal->choice.identifiedRegion.list.count;

            if (region->value.identified_regions.count == 0)
            {
                region->value.identified_regions.regions = NULL;
                break;
            }

            region->value.identified_regions.regions = oscms_tracked_calloc(
                region->value.identified_regions.count, sizeof(OscmsIdentifiedRegion), &tbs_cert->allocations);
            if (!region->value.identified_regions.regions)
            {
                return -1;
            }

            IdentifiedRegion_t **internal_regions = internal->choice.identifiedRegion.list.array;
            OscmsIdentifiedRegion *regions        = region->value.identified_regions.regions;
            for (size_t i = 0; i < region->value.identified_regions.count; i++)
            {
                if (unpack_identified_region(internal_regions[i], &regions[i], tbs_cert) != 0)
                {
                    return -1;
                }
            }
            break;
        }

        default:
            oscms_log(LOG_ERR, "%s: Invalid region type: %d", __func__, region->type);
            return -1;
    }
    return 0;
}

static int unpack_subject_permissions(
    const SubjectPermissions_t *internal, OscmsSubjectPermissions *permissions_ptr, OscmsTbsCertificate *tbs_cert)
{
    if (internal->present == SubjectPermissions_PR_all)
    {
        permissions_ptr->type                 = OSCMS_SUBJECT_PERMISSION_TYPE_ALL;
        permissions_ptr->explicit_permissions = 0;
        permissions_ptr->explicit_count       = 0;
        return 0;
    }

    permissions_ptr->type = OSCMS_SUBJECT_PERMISSION_TYPE_EXPLICIT;

    if (internal->choice.Explicit.list.count < 0)
    {
        return -1;
    }

    permissions_ptr->explicit_permissions =
        oscms_tracked_calloc(internal->choice.Explicit.list.count, sizeof(OscmsPsidSspRange), &tbs_cert->allocations);
    if (!permissions_ptr->explicit_permissions)
    {
        return -1;
    }

    permissions_ptr->explicit_count = internal->choice.Explicit.list.count;

    for (size_t i = 0; i < permissions_ptr->explicit_count; i++)
    {
        const PsidSspRange_t *internal_pssr = internal->choice.Explicit.list.array[i];
        OscmsPsidSspRange *pssr             = permissions_ptr->explicit_permissions + i;
        pssr->psid                          = internal_pssr->psid;
        if (!internal_pssr->sspRange)
        {
            pssr->ssp_range = NULL;
            continue;
        }
        pssr->ssp_range = oscms_tracked_malloc(sizeof(OscmsSspRange), &tbs_cert->allocations);
        if (!pssr->ssp_range)
        {
            return -1;
        }
        memset(pssr->ssp_range, 0, sizeof(OscmsSspRange));

        pssr->ssp_range->type = (OscmsSspRangeType)internal_pssr->sspRange->present;
        switch (pssr->ssp_range->type)
        {
            case OSCMS_SSP_RANGE_TYPE_OPAQUE:
            {
                const SequenceOfOctetString_t *internal_seq = &internal_pssr->sspRange->choice.opaque;
                if (internal_seq->list.count == 0)
                {
                    pssr->ssp_range->value.opaque.buffers      = NULL;
                    pssr->ssp_range->value.opaque.buffer_count = 0;
                    break;
                }

                pssr->ssp_range->value.opaque.buffers =
                    oscms_tracked_calloc(internal_seq->list.count, sizeof(OscmsOctetBuffer), &tbs_cert->allocations);
                if (!pssr->ssp_range->value.opaque.buffers)
                {
                    return -1;
                }
                pssr->ssp_range->value.opaque.buffer_count = internal_seq->list.count;

                for (size_t j = 0; j < pssr->ssp_range->value.opaque.buffer_count; j++)
                {
                    OscmsOctetBuffer *buffer = pssr->ssp_range->value.opaque.buffers + j;

                    if (oscms_octet_buffer_init_from_octet_string(
                            internal_seq->list.array[j], buffer, &tbs_cert->allocations) != 0)
                    {
                        return -1;
                    }
                }
                break;
            }

            case OSCMS_SSP_RANGE_TYPE_ALL:
                break;

            case OSCMS_SSP_RANGE_TYPE_BITMAP:
            {
                if (oscms_octet_buffer_init_from_octet_string(
                        &internal_pssr->sspRange->choice.bitmapSspRange.sspValue,
                        &pssr->ssp_range->value.bitmap_ssp_range.ssp_value,
                        &tbs_cert->allocations) != 0)
                {
                    return -1;
                }
                if (oscms_octet_buffer_init_from_octet_string(
                        &internal_pssr->sspRange->choice.bitmapSspRange.sspBitmask,
                        &pssr->ssp_range->value.bitmap_ssp_range.ssp_bitmask,
                        &tbs_cert->allocations) != 0)
                {
                    return -1;
                }
                break;
            }

            default:
                oscms_log(LOG_ERR, "%s: Invalid ssp range type: %d", __func__, pssr->ssp_range->type);
                return -1;
        }
    }
    return 0;
}

static int unpack_psid_group_permissions(
    const SequenceOfPsidGroupPermissions_t *internal,
    OscmsPsidGroupPermissions **permissions_ptr,
    size_t *permissions_count,
    OscmsTbsCertificate *tbs_cert)
{
    if (internal->list.count <= 0)
    {
        *permissions_ptr   = NULL;
        *permissions_count = 0;
        return 0;
    }

    *permissions_ptr =
        oscms_tracked_calloc(internal->list.count, sizeof(OscmsPsidGroupPermissions), &tbs_cert->allocations);
    if (!*permissions_ptr)
    {
        return -1;
    }

    *permissions_count = internal->list.count;
    for (size_t i = 0; i < *permissions_count; i++)
    {
        const PsidGroupPermissions_t *internal_pgp = internal->list.array[i];
        OscmsPsidGroupPermissions *pgp             = (*permissions_ptr) + i;

        if (internal_pgp->minChainLength)
        {
            pgp->minimum_chain_length     = *internal_pgp->minChainLength;
            pgp->has_minimum_chain_length = true;
        }

        pgp->chain_depth_range = internal_pgp->chainLengthRange;

        if (!internal_pgp->eeType || !internal_pgp->eeType->buf)
        {
            pgp->ee_type = OSCMS_END_ENTITY_TYPE_APP;
        }
        else
        {
            pgp->ee_type = internal_pgp->eeType->buf[0];
        }

        if (unpack_subject_permissions(&internal_pgp->subjectPermissions, &pgp->subject_permissions, tbs_cert) != 0)
        {
            return -1;
        }
    }
    return 0;
}

// Public functions

/**
 * Convert an internal representation of a TBS Certificate to the API's representation.
 *
 * @param internal The internal representation of the TBS certificate.
 * @param tbs_certificate The TBS certificate to convert.
 *
 * @return 0 on success.
 */
int oscms_tbs_certificate_from_internal(const void *internal_void, OscmsTbsCertificate *tbs_cert)
{
    if (!tbs_cert || !internal_void)
    {
        oscms_log(LOG_CRIT, "%s: NULL parameters", __func__);
        return -1;
    }

    // We will need to track a *lot* of allocated buffers
    oscms_sequence_init(&tbs_cert->allocations);
    oscms_tbs_certificate_init(tbs_cert);

    const ToBeSignedCertificate_t *internal = (const ToBeSignedCertificate_t *)internal_void;

    if (internal->validityPeriod.duration.present > Duration_PR_years || internal->validityPeriod.duration.present < 0)
    {
        oscms_log(LOG_ERR, "%s: Invalid duration type: %d", __func__, internal->validityPeriod.duration.present);
        return -1;
    }

    if (unpack_certificate_id(&internal->id, tbs_cert) != 0)
    {
        goto error_cleanup;
    }

    (void)memcpy(
        tbs_cert->craca_id, internal->cracaId.buf, size_t_min(internal->cracaId.size, sizeof(tbs_cert->craca_id)));

    // Lots of range checks to keep Coverity happy for the following assignments
    //
    // These are triggered by the fact that ASN1C uses a `signed long` to store `Uint32`
    // and `Uint16` ASN.1 types, and we need to cast them to smaller unsigned values.
    if (internal->crlSeries > UINT16_MAX || internal->validityPeriod.start > UINT32_MAX ||
        internal->validityPeriod.duration.present > UINT16_MAX ||
        internal->validityPeriod.duration.present > UINT16_MAX || internal->validityPeriod.duration.choice.hours < 0 ||
        internal->validityPeriod.duration.choice.hours > UINT16_MAX)
    {
        goto error_cleanup;
    }

    tbs_cert->crl_series            = internal->crlSeries;
    tbs_cert->validity_period_start = internal->validityPeriod.start;
    tbs_cert->validity_period_units = (OscmsValidityDurationUnits)internal->validityPeriod.duration.present;
    tbs_cert->validity_period =
        (uint16_t)internal->validityPeriod.duration.choice.hours; // All choices are the same size

    if (unpack_verification_key_indicator(&internal->verifyKeyIndicator, tbs_cert) != 0)
    {
        goto error_cleanup;
    }

    if (internal->appPermissions)
    {
        if (unpack_app_permissions(internal->appPermissions, tbs_cert) != 0)
        {
            goto error_cleanup;
        }
    }

    if (internal->region)
    {
        if (unpack_region(internal->region, tbs_cert) != 0)
        {
            goto error_cleanup;
        }
    }

    if (internal->assuranceLevel)
    {
        tbs_cert->assurance_level =
            oscms_octet_buffer_new_from_buffer(internal->assuranceLevel->buf, internal->assuranceLevel->size);
        if (!tbs_cert->assurance_level)
        {
            goto error_cleanup;
        }
        if (tbs_cert->assurance_level->data)
        {
            if (oscms_track_other(tbs_cert->assurance_level->data, &tbs_cert->allocations) != 0)
            {
                // failed to track the internal buffer, so clean this one up before returning
                oscms_free_octet_buffer(tbs_cert->assurance_level);
                tbs_cert->assurance_level = NULL;
                goto error_cleanup;
            }
        }
    }

    if (internal->certIssuePermissions)
    {
        if (unpack_psid_group_permissions(
                internal->certIssuePermissions,
                &tbs_cert->cert_issue_permissions,
                &tbs_cert->cert_issue_permissions_count,
                tbs_cert) != 0)
        {
            goto error_cleanup;
        }
    }
    else
    {
        tbs_cert->cert_issue_permissions_count = 0;
        tbs_cert->cert_issue_permissions       = NULL;
    }

    if (internal->certRequestPermissions)
    {
        if (unpack_psid_group_permissions(
                internal->certRequestPermissions,
                &tbs_cert->cert_request_permissions,
                &tbs_cert->cert_request_permissions_count,
                tbs_cert) != 0)
        {
            goto error_cleanup;
        }
    }
    else
    {
        tbs_cert->cert_request_permissions_count = 0;
        tbs_cert->cert_request_permissions       = NULL;
    }

    if (internal->encryptionKey)
    {
        tbs_cert->encryption_key = oscms_tracked_malloc(sizeof(OscmsPublicEncryptionKey), &tbs_cert->allocations);
        if (!tbs_cert->encryption_key)
        {
            goto error_cleanup;
        }
        if (internal->encryptionKey->supportedSymmAlg > OSCMS_SYMMETRIC_ALGORITHM_MAX)
        {
            goto error_cleanup;
        }

        tbs_cert->encryption_key->algorithm = (OscmsSymmetricAlgorithmType)internal->encryptionKey->supportedSymmAlg;
        const OscmsEccPointCurveType curve_point_type_map[] = {
            OSCMS_ECC_POINT_CURVE_TYPE_NONE,
            OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256,
            OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P256,
            OSCMS_ECC_POINT_CURVE_TYPE_SM2,
        };
        if (oscms_ecc_curve_point_from_internal(
                &internal->encryptionKey->publicKey.choice.eciesNistP256,
                curve_point_type_map[internal->encryptionKey->publicKey.present],
                &tbs_cert->encryption_key->key,
                &tbs_cert->allocations) != 0)
        {
            goto error_cleanup;
        }
    }
    else
    {
        tbs_cert->encryption_key = NULL;
    }

    if (internal->flags && internal->flags->buf && internal->flags->size != 0)
    {
        tbs_cert->flags = oscms_tracked_malloc(sizeof(OscmsBitString), &tbs_cert->allocations);
        if (!tbs_cert->flags)
        {
            goto error_cleanup;
        }

        if (oscms_octet_buffer_init_from_buffer(&tbs_cert->flags->data, internal->flags->buf, internal->flags->size) !=
            0)
        {
            goto error_cleanup;
        }

        tbs_cert->flags->unused_bits = internal->flags->bits_unused;
    }
    else
    {
        tbs_cert->flags = NULL;
    }

    return 0;

error_cleanup:
    oscms_empty_tbs_certificate(tbs_cert);
    return -1;
}
