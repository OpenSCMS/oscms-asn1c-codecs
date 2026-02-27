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

#include "oscms_asn1c_generated/ToBeSignedCertificate.h"

#include "oscms_codecs_api/logging.h"
#include "oscms_codecs_api/octet_buffer.h"
#include "oscms_codecs_api/oscms_ecc_curve.h"
#include "oscms_codecs_api/oscms_sequence.h"
#include "oscms_codecs_api/oscms_tbs_certificate.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "asn1c_utilities.h"

/**
 * @brief Free an ASN.1 OCTET STRING structure
 *
 * This is a wrapper for the ASN.1 OCTET STRING free function. It is used to initialize the `free` element of
 * a SequenceOfOctetString structure.
 */
static void free_octet_string(OCTET_STRING_t *octet_string)
{
    OCTET_STRING_free(&asn_DEF_OCTET_STRING, octet_string, ASFM_FREE_EVERYTHING);
}

static int pack_certificate_id(const OscmsTbsCertificate *tbs_cert, CertificateId_t *internal)
{
    memset(internal, 0, sizeof(*internal));

    switch (tbs_cert->id.type)
    {
        case OSCMS_CERTIFICATE_ID_TYPE_LINKAGE:
            internal->present                  = CertificateId_PR_linkageData;
            internal->choice.linkageData.iCert = tbs_cert->id.value.linkage_data.i_cert;
            if (oscms_octet_string_init_from_buffer(
                    tbs_cert->id.value.linkage_data.linkage_value,
                    internal->choice.linkageData.linkage_value.size,
                    &internal->choice.linkageData.linkage_value) != 0)
            {
                return -1;
            }

            if (tbs_cert->id.value.linkage_data.group_linkage_value)
            {
                if (oscms_octet_string_init_from_buffer(
                        tbs_cert->id.value.linkage_data.group_linkage_value->j_value,
                        4,
                        &internal->choice.linkageData.group_linkage_value->jValue) != 0)
                {
                    return -1;
                }
                if (oscms_octet_string_init_from_buffer(
                        tbs_cert->id.value.linkage_data.group_linkage_value->value,
                        4,
                        &internal->choice.linkageData.group_linkage_value->value) != 0)
                {
                    return -1;
                }
            }
            else
            {
                internal->choice.linkageData.group_linkage_value = 0;
            }

            break;

        case OSCMS_CERTIFICATE_ID_TYPE_HOSTNAME:
            internal->present = CertificateId_PR_name;
            if (oscms_octet_string_init_from_octet_buffer(&tbs_cert->id.value.host_name, &internal->choice.name) != 0)
            {
                return -1;
            }
            break;

        case OSCMS_CERTIFICATE_ID_TYPE_BINARY_ID:
            internal->present = CertificateId_PR_binaryId;
            if (oscms_octet_string_init_from_octet_buffer(&tbs_cert->id.value.binary_id, &internal->choice.binaryId) !=
                0)
            {
                return -1;
            }
            break;

        case OSCMS_CERTIFICATE_ID_TYPE_NONE:
            internal->present = CertificateId_PR_none;
            break;

        default:
            return -1;
    }

    return 0;
}

static int pack_identified_region(const OscmsIdentifiedRegion *region, IdentifiedRegion_t *internal)
{
    if (!region || !internal)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }
    memset(internal, 0, sizeof(IdentifiedRegion_t));

    switch (region->type)
    {
        case OSCMS_IDENTIFIED_REGION_TYPE_NONE:
            internal->present = IdentifiedRegion_PR_NOTHING;
            break;

        case OSCMS_IDENTIFIED_REGION_TYPE_COUNTRY_ONLY:
            internal->present            = IdentifiedRegion_PR_countryOnly;
            internal->choice.countryOnly = region->value.country;
            break;

        case OSCMS_IDENTIFIED_REGION_TYPE_COUNTRY_AND_REGIONS:
        {
            internal->present                              = IdentifiedRegion_PR_countryAndRegions;
            internal->choice.countryAndRegions.countryOnly = region->value.country_and_region.country;

            SequenceOfUint8_t *internal_seq = &internal->choice.countryAndRegions.regions;
            internal_seq->list.count = internal_seq->list.size = 0;
            internal_seq->list.array                           = 0;
            internal_seq->list.free                            = (void (*)(Uint8_t *))free;

            for (size_t i = 0; i < region->value.country_and_region.region.length; i++)
            {
                // Counter-intuitively, ASN1C uses a long for a Uint8_t type, which  means we need to do this by hand
                Uint8_t *tmp = malloc(sizeof(Uint8_t));
                if (!tmp)
                {
                    goto error_cleanup;
                }

                *tmp = region->value.country_and_region.region.data[i];

                if (asn1c_add_to_sequence(&internal_seq->list, tmp) != 0)
                {
                    free(tmp);
                    goto error_cleanup;
                }
            }

            break;
        }
        case OSCMS_IDENTIFIED_REGION_TYPE_COUNTRY_AND_SUBREGIONS:
        {
            internal->present                                 = IdentifiedRegion_PR_countryAndSubregions;
            internal->choice.countryAndSubregions.countryOnly = region->value.country_and_subregions.country;
            const OscmsRegionAndSubregions *subregions        = region->value.country_and_subregions.subregions;
            if (!subregions)
            {
                oscms_log(LOG_ERR, "%s: Empty list of RegionAndSubregions", __func__);
                goto error_cleanup;
            }

            SequenceOfRegionAndSubregions_t *internal_rs_seq =
                &internal->choice.countryAndSubregions.regionAndSubregions;

            internal_rs_seq->list.count = internal_rs_seq->list.size = 0;
            internal_rs_seq->list.array                              = 0;

            for (size_t i = 0; i < subregions->subregion_count; i++)
            {
                RegionAndSubregions_t *internal_rs = calloc(1, sizeof(RegionAndSubregions_t));
                if (!internal_rs)
                {
                    oscms_log(LOG_CRIT, "%s: Failed to allocate RegionAndSubregions_t", __func__);
                    goto error_cleanup;
                }

                internal_rs->region = subregions[i].region;
                if (!subregions[i].subregions)
                {
                    free(internal_rs);
                    oscms_log(LOG_ERR, "%s: Empty list of subregions", __func__);
                    goto error_cleanup;
                }

                internal_rs->subregions.list.count = internal_rs->subregions.list.size = 0;
                internal_rs->subregions.list.array                                     = 0;

                for (size_t j = 0; j < subregions[i].subregion_count; j++)
                {
                    Uint16_t *internal_sr = malloc(sizeof(Uint16_t));
                    if (!internal_sr)
                    {
                        ASN_STRUCT_FREE(asn_DEF_RegionAndSubregions, internal_rs);
                        oscms_log(LOG_CRIT, "%s: Failed to allocate Subregion_t", __func__);
                        goto error_cleanup;
                    }

                    *internal_sr = subregions[i].subregions[j];
                    if (asn1c_add_to_sequence(&internal_rs->subregions, internal_sr) != 0)
                    {
                        ASN_STRUCT_FREE(asn_DEF_RegionAndSubregions, internal_rs);
                        free(internal_sr);
                        goto error_cleanup;
                    }
                }

                if (asn1c_add_to_sequence(internal_rs_seq, internal_rs) != 0)
                {
                    ASN_STRUCT_FREE(asn_DEF_RegionAndSubregions, internal_rs);
                    goto error_cleanup;
                }
            }
            break;
        }
        default:
            goto error_cleanup;
    }
    return 0;

error_cleanup:
    ASN_STRUCT_RESET(asn_DEF_IdentifiedRegion, internal);
    return -1;
}

static int pack_region(const OscmsGeographicalRegion *region, GeographicRegion_t *internal)
{
    if (!region || !internal)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    switch (region->type)
    {
        case OSCMS_GEOGRAPHICAL_REGION_TYPE_NONE:
            internal->present = GeographicRegion_PR_NOTHING;
            break;

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_CIRCULAR:
            internal->present                                = GeographicRegion_PR_circularRegion;
            internal->choice.circularRegion.center.latitude  = region->value.circular.center.latitude;
            internal->choice.circularRegion.center.longitude = region->value.circular.center.longitude;
            internal->choice.circularRegion.radius           = region->value.circular.radius;
            break;

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_RECTANGULAR:
        {
            internal->present = GeographicRegion_PR_rectangularRegion;
            if (!region->value.rectangular.rectangles || region->value.rectangular.rectangle_count == 0)
            {
                oscms_log(LOG_ERR, "%s: Rectangular region must have at least one rectangle", __func__);
                return -1;
            }

            SequenceOfRectangularRegion_t *internal_seq = &internal->choice.rectangularRegion;
            internal_seq->list.count = internal_seq->list.size = 0;
            internal_seq->list.array                           = NULL;
            internal_seq->list.free                            = (void (*)(RectangularRegion_t *))free;

            for (size_t i = 0; i < region->value.rectangular.rectangle_count; i++)
            {
                const OscmsRectangularRegion *rect = &region->value.rectangular.rectangles[i];
                RectangularRegion_t *internal_rect = malloc(sizeof(RectangularRegion_t));
                if (!internal_rect)
                {
                    oscms_log(LOG_CRIT, "%s: Memory allocation failed", __func__);
                    return -1;
                }
                internal_rect->northWest.latitude  = rect->top_left.latitude;
                internal_rect->northWest.longitude = rect->top_left.longitude;
                internal_rect->southEast.latitude  = rect->bottom_right.latitude;
                internal_rect->southEast.longitude = rect->bottom_right.longitude;
                if (asn1c_add_to_sequence(internal_seq, internal_rect) != 0)
                {
                    free(internal_rect);
                    return -1;
                }
            }
            break;
        }

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_POLYGONAL:
            internal->present = GeographicRegion_PR_polygonalRegion;
            if (!region->value.polygonal.points || region->value.polygonal.point_count == 0)
            {
                oscms_log(LOG_ERR, "%s: Polygonal region must have at least one point", __func__);
                return -1;
            }

            PolygonalRegion_t *internal_seq = &internal->choice.polygonalRegion;
            internal_seq->list.count = internal_seq->list.size = 0;
            internal_seq->list.array                           = 0;
            internal_seq->list.free                            = (void (*)(TwoDLocation_t *))free;

            for (size_t i = 0; i < region->value.polygonal.point_count; i++)
            {
                const OscmsTwoDLocation *point = &region->value.polygonal.points[i];
                TwoDLocation_t *internal_point = malloc(sizeof(TwoDLocation_t));
                if (!internal_point)
                {
                    oscms_log(LOG_CRIT, "%s: Memory allocation failed", __func__);
                    return -1;
                }
                internal_point->latitude  = point->latitude;
                internal_point->longitude = point->longitude;
                if (asn1c_add_to_sequence(&internal_seq, internal_point) != 0)
                {
                    free(internal_point);
                    return -1;
                }
            }
            break;

        case OSCMS_GEOGRAPHICAL_REGION_TYPE_IDENTIFIED:
        {
            internal->present = GeographicRegion_PR_identifiedRegion;

            SequenceOfIdentifiedRegion_t *internal_idregion_seq = &internal->choice.identifiedRegion;
            internal_idregion_seq->list.count = internal_idregion_seq->list.size = 0;
            internal_idregion_seq->list.array                                    = NULL;
            internal_idregion_seq->list.free                                     = (void (*)(IdentifiedRegion_t *))free;

            if (!region->value.identified_regions.regions || region->value.identified_regions.count == 0)
            {
                oscms_log(LOG_ERR, "%s: Identified region must have at least one region", __func__);
                return -1;
            }

            for (size_t i = 0; i < region->value.identified_regions.count; i++)
            {
                const OscmsIdentifiedRegion *args_region = &region->value.identified_regions.regions[i];
                IdentifiedRegion_t *internal_region      = malloc(sizeof(IdentifiedRegion_t));
                if (!internal_region)
                {
                    oscms_log(LOG_CRIT, "%s: Memory allocation failed", __func__);
                    return -1;
                }
                if (pack_identified_region(args_region, internal_region) != 0)
                {
                    free(internal_region);
                    return -1;
                }
                if (asn1c_add_to_sequence(internal_idregion_seq, internal_region) != 0)
                {
                    free(internal_region);
                    return -1;
                }
            }
            break;
        }
        default:
            return -1;
    }

    return 0;
}

static int pack_verification_key_indicator(
    const OscmsVerificationKeyIndicator *indicator, VerificationKeyIndicator_t *internal)
{
    memset(internal, 0, sizeof(*internal));
    void *dest_curve = 0;

    switch (indicator->type)
    {
        case OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_NONE:
            internal->present = VerificationKeyIndicator_PR_NOTHING;
            break;

        case OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_KEY:
        {
            internal->present = VerificationKeyIndicator_PR_verificationKey;

            switch (indicator->point.curve_type)
            {
                case OSCMS_ECC_POINT_CURVE_TYPE_NONE:
                    oscms_log(LOG_ERR, "%s: Invalid verification key indicator type: NONE", __func__);
                    return -1;

                case OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256:
                    internal->choice.verificationKey.present = PublicVerificationKey_PR_ecdsaNistP256;
                    dest_curve                               = &internal->choice.verificationKey.choice.ecdsaNistP256;
                    break;

                case OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P256:
                    internal->choice.verificationKey.present = PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
                    dest_curve = &internal->choice.verificationKey.choice.ecdsaBrainpoolP256r1;
                    break;

                case OSCMS_ECC_POINT_CURVE_TYPE_NIST_P384:
                    internal->choice.verificationKey.present = PublicVerificationKey_PR_ecdsaNistP384;
                    dest_curve                               = &internal->choice.verificationKey.choice.ecdsaNistP384;
                    break;

                case OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P384:
                    internal->choice.verificationKey.present = PublicVerificationKey_PR_ecdsaBrainpoolP384r1;
                    dest_curve = &internal->choice.verificationKey.choice.ecdsaBrainpoolP384r1;
                    break;

                case OSCMS_ECC_POINT_CURVE_TYPE_SM2:
                    internal->choice.verificationKey.present = PublicVerificationKey_PR_ecsigSm2;
                    dest_curve                               = &internal->choice.verificationKey.choice.ecsigSm2;
                    break;

                default:
                    oscms_log(
                        LOG_ERR,
                        "%s: Invalid verification key indicator type: %d",
                        __func__,
                        indicator->point.curve_type);
                    return -1;
            }

            break;
        }
        case OSCMS_VERIFICATION_KEY_INDICATOR_TYPE_RECONSTRUCTION:
            internal->present = VerificationKeyIndicator_PR_reconstructionValue;
            dest_curve        = &internal->choice.reconstructionValue;
            break;

        default:
            oscms_log(LOG_ERR, "%s: Invalid verification key indicator type: %d", __func__, indicator->type);
            return -1;
    }

    return oscms_internal_from_ecc_curve_point(&indicator->point, dest_curve);
}

static int pack_app_permissions(const OscmsPsidSsp *permissions, size_t num_permissions, SequenceOfPsidSsp_t *internal)
{
    internal->list.size = internal->list.count = 0;

    for (size_t i = 0; i < num_permissions; i++)
    {
        PsidSsp_t *psid_ssp = calloc(1, sizeof(PsidSsp_t));
        if (!psid_ssp)
        {
            return -1;
        }
        psid_ssp->psid = permissions[i].psid;

        if (permissions[i].ssp)
        {
            psid_ssp->ssp = calloc(1, sizeof(*psid_ssp->ssp));
            if (!psid_ssp->ssp)
            {
                oscms_log(LOG_CRIT, "%s: Failed to allocate memory for PsidSsp.ssp", __func__);
                free(psid_ssp);
                return -1;
            }
            psid_ssp->ssp->present = (ServiceSpecificPermissions_PR)permissions[i].ssp->type;
            switch (permissions[i].ssp->type)
            {
                case OSCMS_SSP_TYPE_NONE:
                    break;

                case OSCMS_SSP_TYPE_OPAQUE:
                    if (oscms_octet_string_init_from_octet_buffer(
                            &permissions[i].ssp->value, &psid_ssp->ssp->choice.opaque) != 0)
                    {
                        free(psid_ssp->ssp), psid_ssp->ssp = 0;
                        free(psid_ssp);
                        return -1;
                    }
                    break;

                case OSCMS_SSP_TYPE_BITMAP:
                    if (oscms_octet_string_init_from_octet_buffer(
                            &permissions[i].ssp->value, &psid_ssp->ssp->choice.bitmapSsp) != 0)
                    {
                        free(psid_ssp->ssp), psid_ssp->ssp = 0;
                        free(psid_ssp);
                        return -1;
                    }
                    break;

                default:
                    oscms_log(
                        LOG_ERR,
                        "%s: Invalid service specific permission type: %d",
                        __func__,
                        permissions[i].ssp->type);
                    free(psid_ssp->ssp), psid_ssp->ssp = 0;
                    free(psid_ssp);
                    return -1;
            }
        }
        if (asn1c_add_to_sequence(internal, psid_ssp) < 0)
        {
            free(psid_ssp->ssp), psid_ssp->ssp = 0;
            free(psid_ssp);
            return -1;
        }
    }
    return 0;
}

static int pack_subject_permissions(const OscmsSubjectPermissions *permissions, SubjectPermissions_t *internal)
{
    if (permissions->type != OSCMS_SUBJECT_PERMISSION_TYPE_EXPLICIT)
    {
        return 0;
    }
    internal->present = SubjectPermissions_PR_explicit;

    SequenceOfPsidSspRange_t *internal_psr_seq = &internal->choice.Explicit;
    internal_psr_seq->list.size = internal_psr_seq->list.count = 0;
    internal_psr_seq->list.free                                = (void (*)(PsidSspRange_t *))free;

    for (size_t i = 0; i < permissions->explicit_count; i++)
    {
        PsidSspRange_t *internal_psr = calloc(1, sizeof(PsidSspRange_t));
        if (!internal_psr)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for PsidSspRange_t", __func__);
            return -1;
        }

        const OscmsPsidSspRange *psr = &permissions->explicit_permissions[i];
        internal_psr->psid           = psr->psid;
        if (psr->ssp_range)
        {
            internal_psr->sspRange = calloc(1, sizeof(*internal_psr->sspRange));
            if (!internal_psr->sspRange)
            {
                oscms_log(LOG_CRIT, "%s: Failed to allocate memory for PsidSspRange.sspRange", __func__);
                free(internal_psr);
                return -1;
            }

            internal_psr->sspRange->present = (SspRange_PR)psr->ssp_range->type;
            switch (psr->ssp_range->type)
            {
                case OSCMS_SSP_RANGE_TYPE_OPAQUE:
                {
                    SequenceOfOctetString_t *internal_opaque_seq = &internal_psr->sspRange->choice.opaque;
                    internal_opaque_seq->list.size = internal_opaque_seq->list.count = 0;
                    internal_opaque_seq->list.free                                   = free_octet_string;

                    const OscmsOctetBuffer *buffers = psr->ssp_range->value.opaque.buffers;
                    if (!buffers && psr->ssp_range->value.opaque.buffer_count != 0)
                    {
                        oscms_log(LOG_CRIT, "%s: No buffers provided for non-zero count", __func__);
                        free(internal_psr->sspRange), internal_psr->sspRange = 0;
                        free(internal_psr);
                        return -1;
                    }

                    for (size_t j = 0; j < psr->ssp_range->value.opaque.buffer_count; j++)
                    {
                        if (buffers[j].length > INT_MAX)
                        {
                            oscms_log(LOG_CRIT, "%s: Buffer too large", __func__);
                            free(internal_psr->sspRange), internal_psr->sspRange = 0;
                            free(internal_psr);
                            return -1;
                        }

                        OCTET_STRING_t *internal_buffer = OCTET_STRING_new_fromBuf(
                            &asn_DEF_OCTET_STRING, (const char *)buffers[j].data, (int)buffers[j].length);

                        if (!internal_buffer)
                        {
                            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for OCTET_STRING_t", __func__);
                            free(internal_psr->sspRange), internal_psr->sspRange = 0;
                            free(internal_psr);
                            return -1;
                        }

                        if (asn1c_add_to_sequence(internal_opaque_seq, internal_buffer) < 0)
                        {
                            free(internal_psr->sspRange), internal_psr->sspRange = 0;
                            free(internal_psr);
                            return -1;
                        }
                    }
                    break;
                }

                case OSCMS_SSP_RANGE_TYPE_BITMAP:
                {
                    if (oscms_octet_string_init_from_octet_buffer(
                            &psr->ssp_range->value.bitmap_ssp_range.ssp_value,
                            &internal_psr->sspRange->choice.bitmapSspRange.sspValue) != 0)
                    {
                        free(internal_psr->sspRange), internal_psr->sspRange = 0;
                        free(internal_psr);
                        return -1;
                    }
                    if (oscms_octet_string_init_from_octet_buffer(
                            &psr->ssp_range->value.bitmap_ssp_range.ssp_bitmask,
                            &internal_psr->sspRange->choice.bitmapSspRange.sspBitmask) != 0)
                    {
                        free(internal_psr->sspRange), internal_psr->sspRange = 0;
                        free(internal_psr);
                        return -1;
                    }
                    break;
                }

                default:
                    break;
            }
        }
        if (asn1c_add_to_sequence(internal_psr_seq, internal_psr) < 0)
        {
            free(internal_psr);
            return -1;
        }
    }
    return 0;
}

static int pack_psid_group_permissions(
    const OscmsPsidGroupPermissions *permissions,
    size_t num_permissions,
    SequenceOfPsidGroupPermissions_t **internal_ptr)
{
    *internal_ptr = calloc(1, sizeof(SequenceOfPsidGroupPermissions_t));
    if (!*internal_ptr)
    {
        oscms_log(LOG_CRIT, "%s: Failed to allocate memory for SequenceOfPsidGroupPermissions_t", __func__);
        return -1;
    }

    SequenceOfPsidGroupPermissions_t *internal = *internal_ptr;
    internal->list.size = internal->list.count = 0;
    internal->list.free                        = (void (*)(PsidGroupPermissions_t *))free;

    for (size_t i = 0; i < num_permissions; i++)
    {
        PsidGroupPermissions_t *pgp = calloc(1, sizeof(PsidGroupPermissions_t));
        if (!pgp)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for PsidGroupPermissions_t", __func__);
            return -1;
        }
        pgp->chainLengthRange = permissions[i].chain_depth_range;

        if (permissions[i].has_minimum_chain_length)
        {
            pgp->minChainLength = calloc(1, sizeof(*pgp->minChainLength));
            if (!pgp->minChainLength)
            {
                oscms_log(LOG_CRIT, "%s: Failed to allocate memory for PsidGroupPermissions.minChainLength", __func__);
                free(pgp);
                return -1;
            }
            *pgp->minChainLength = permissions[i].minimum_chain_length;
        }

        if (permissions[i].ee_type != OSCMS_END_ENTITY_TYPE_NONE)
        {
            pgp->eeType = calloc(1, sizeof(*pgp->eeType));
            if (!pgp->eeType)
            {
                oscms_log(LOG_CRIT, "%s: Failed to allocate memory for PsidGroupPermissions.eeType", __func__);
                free(pgp->minChainLength), pgp->minChainLength = 0;
                free(pgp);
                return -1;
            }
            pgp->eeType->buf = malloc(1);
            if (!pgp->eeType->buf)
            {
                oscms_log(LOG_CRIT, "%s: Failed to allocate memory for PsidGroupPermissions.eeType.buf", __func__);
                free(pgp->minChainLength), pgp->minChainLength = 0;
                free(pgp);
                return -1;
            }

            pgp->eeType->buf[0]      = permissions[i].ee_type;
            pgp->eeType->size        = 1;
            pgp->eeType->bits_unused = 0;

            if (pack_subject_permissions(&permissions[i].subject_permissions, &pgp->subjectPermissions) != 0)
            {
                free(pgp->minChainLength), pgp->minChainLength = 0;
                free(pgp);
                return -1;
            }
        }
        if (asn1c_add_to_sequence(internal, pgp) < 0)
        {
            free(pgp->minChainLength), pgp->minChainLength = 0;
            free(pgp);
            return -1;
        }
    }
    return 0;
}

static int pack_encryption_key(const OscmsPublicEncryptionKey *key, PublicEncryptionKey_t *internal)
{
    internal->supportedSymmAlg = (e_SymmAlgorithm)key->algorithm;
    switch (key->key.curve_type)
    {
        case OSCMS_ECC_POINT_CURVE_TYPE_NIST_P256:
            internal->publicKey.present = BasePublicEncryptionKey_PR_eciesNistP256;
            break;
        case OSCMS_ECC_POINT_CURVE_TYPE_BRAINPOOL_P256:
            internal->publicKey.present = BasePublicEncryptionKey_PR_eciesBrainpoolP256r1;
            break;
        case OSCMS_ECC_POINT_CURVE_TYPE_SM2:
            internal->publicKey.present = BasePublicEncryptionKey_PR_ecencSm2;
            break;

        default:
            oscms_log(LOG_ERR, "%s: Invalid curve type for public key: %d", __func__, key->key.curve_type);
            return -1;
    }

    if (oscms_internal_from_ecc_curve_point(&key->key, &internal->publicKey.choice.eciesNistP256) != 0)
    {
        return -1;
    }
    return 0;
}

/**
 * Convert the API's representation of the TBS certificate to an internal representation.
 *
 * @param tbs_certificate The TBS certificate to convert.
 * @param internal The internal representation of the TBS certificate.
 *
 * @return 0 on success.
 */
int oscms_internal_from_tbs_certificate(const OscmsTbsCertificate *tbs_certificate, void *internal_void)
{
    if (!tbs_certificate || !internal_void)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    ToBeSignedCertificate_t *internal = (ToBeSignedCertificate_t *)internal_void;
    oscms_tbs_certificate_init_internal(internal);

    if (pack_certificate_id(tbs_certificate, &internal->id) != 0)
    {
        return -1;
    }

    if (oscms_octet_string_init_from_buffer(
            tbs_certificate->craca_id, sizeof(tbs_certificate->craca_id), &internal->cracaId) != 0)
    {
        return -1;
    }

    internal->crlSeries = tbs_certificate->crl_series;

    internal->validityPeriod.start                 = tbs_certificate->validity_period_start;
    internal->validityPeriod.duration.present      = (Duration_PR)tbs_certificate->validity_period_units;
    internal->validityPeriod.duration.choice.years = tbs_certificate->validity_period;

    if (tbs_certificate->region)
    {
        internal->region = calloc(1, sizeof(*internal->region));
        if (!internal->region)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for region", __func__);
            return -1;
        }

        if (pack_region(tbs_certificate->region, internal->region) != 0)
        {
            return -1;
        }
    }

    if (pack_verification_key_indicator(&tbs_certificate->verify_key_indicator, &internal->verifyKeyIndicator) != 0)
    {
        return -1;
    }

    if (tbs_certificate->app_permissions)
    {
        internal->appPermissions = calloc(1, sizeof(*internal->appPermissions));
        if (!internal->appPermissions)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for app permissions", __func__);
            return -1;
        }

        if (pack_app_permissions(
                tbs_certificate->app_permissions, tbs_certificate->app_permissions_count, internal->appPermissions) !=
            0)
        {
            return -1;
        }
    }

    if (tbs_certificate->assurance_level)
    {
        internal->assuranceLevel = calloc(1, sizeof(*internal->assuranceLevel));
        if (!internal->assuranceLevel)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for assurance level", __func__);
            return -1;
        }

        if (oscms_octet_string_init_from_octet_buffer(tbs_certificate->assurance_level, internal->assuranceLevel) != 0)
        {
            return -1;
        }
    }

    if (tbs_certificate->cert_issue_permissions && tbs_certificate->cert_issue_permissions_count != 0)
    {
        if (pack_psid_group_permissions(
                tbs_certificate->cert_issue_permissions,
                tbs_certificate->cert_issue_permissions_count,
                &internal->certIssuePermissions) != 0)
        {
            return -1;
        }
    }

    if (tbs_certificate->cert_request_permissions && tbs_certificate->cert_request_permissions_count != 0)
    {
        if (pack_psid_group_permissions(
                tbs_certificate->cert_request_permissions,
                tbs_certificate->cert_request_permissions_count,
                &internal->certRequestPermissions) != 0)
        {
            return -1;
        }
    }

    if (tbs_certificate->encryption_key)
    {
        internal->encryptionKey = calloc(1, sizeof(*internal->encryptionKey));
        if (!internal->encryptionKey)
        {
            oscms_log(LOG_CRIT, "%s: Failed to allocate memory for encryption key", __func__);
            return -1;
        }

        if (pack_encryption_key(tbs_certificate->encryption_key, internal->encryptionKey) != 0)
        {
            return -1;
        }
    }

    return 0;
}

/**
 * Initialize an internal representation of the TBS certificate structure.
 *
 * All fields are set to their default values (if applicable), all pointers (I.e. OPTIONAL fields) are set to NULL.
 *
 * @param internal The TBS certificate to initialize.
 *
 */
void oscms_tbs_certificate_init_internal(void *internal)
{
    ToBeSignedCertificate_t *tbs_certificate = (ToBeSignedCertificate_t *)internal;
    memset(tbs_certificate, 0, sizeof(*tbs_certificate));
    tbs_certificate->region                 = NULL;
    tbs_certificate->assuranceLevel         = NULL;
    tbs_certificate->encryptionKey          = NULL;
    tbs_certificate->flags                  = NULL;
    tbs_certificate->certRequestPermissions = NULL;
    tbs_certificate->certIssuePermissions   = NULL;
    tbs_certificate->appPermissions         = NULL;
}
