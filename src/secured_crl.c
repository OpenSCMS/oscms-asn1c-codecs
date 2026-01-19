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
#include "oscms_codecs_api/oscms_secured_crl.h"
#include "oscms_codecs_api/oscms_utilities.h"

#include "oscms_asn1c_generated/CrlContents.h"
#include "oscms_asn1c_generated/SecuredCrl.h"

#include "asn1c_utilities.h"

static int sequence_of_inidivual_revocations_to_internal(
    const OscmsIndividualRevocation *revocations, size_t count, SequenceOfIndividualRevocation_t *internal)
{
    memset(internal, 0, sizeof(SequenceOfIndividualRevocation_t));
    if (count == 0)
    {
        return 0;
    }

    if (!revocations)
    {
        oscms_log(LOG_CRIT, "%s: revocations is NULL", __func__);
        return -1;
    }

    if (allocate_asn1c_sequence_of(count, sizeof(IndividualRevocation_t), _A_SEQUENCE_FROM_VOID(internal)) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < count; i++)
    {
        IndividualRevocation_t *internal_entry = internal->list.array[i];
        const OscmsIndividualRevocation *entry = &revocations[i];

        if (oscms_octet_string_init_from_buffer(
                entry->linkage_seed_1, sizeof(entry->linkage_seed_1), &internal_entry->linkageSeed1) != 0)
        {
            return -1;
        }
        if (oscms_octet_string_init_from_buffer(
                entry->linkage_seed_2, sizeof(entry->linkage_seed_2), &internal_entry->linkageSeed2) != 0)
        {
            return -1;
        }
    }
    return 0;
}

static int sequence_of_linkage_seeds_to_internal(
    const OscmsLinkageSeed *linkage_seeds, size_t count, SequenceOfLinkageSeed_t **internal_ptr)
{
    *internal_ptr = 0;

    if (count == 0)
    {
        return 0;
    }

    if (!linkage_seeds)
    {
        oscms_log(LOG_CRIT, "%s: linkage_seeds is NULL", __func__);
        return -1;
    }

    SequenceOfLinkageSeed_t *internal = calloc(1, sizeof(SequenceOfLinkageSeed_t));
    if (!internal)
    {
        return -1;
    }
    *internal_ptr = internal;

    if (allocate_asn1c_sequence_of(count, sizeof(LinkageSeed_t), _A_SEQUENCE_FROM_VOID(internal)) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < count; i++)
    {
        LinkageSeed_t *internal_entry = internal->list.array[i];
        const OscmsLinkageSeed *entry = &linkage_seeds[i];

        if (oscms_octet_string_init_from_buffer((const uint8_t *)entry, sizeof(*entry), internal_entry) != 0)
        {
            return -1;
        }
    }
    return 0;
}

static int sequence_of_imax_groups_to_internal(
    const OscmsIMaxGroup *imax_groups, size_t count, SequenceOfIMaxGroup_t *internal)
{
    memset(internal, 0, sizeof(SequenceOfIMaxGroup_t));
    if (count == 0)
    {
        return 0;
    }

    if (!imax_groups)
    {
        oscms_log(LOG_CRIT, "%s: imax_groups is NULL", __func__);
        return -1;
    }

    if (allocate_asn1c_sequence_of(count, sizeof(IMaxGroup_t), _A_SEQUENCE_FROM_VOID(internal)) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < count; i++)
    {
        IMaxGroup_t *internal_entry = internal->list.array[i];
        const OscmsIMaxGroup *entry = &imax_groups[i];
        internal_entry->iMax        = entry->i_max;

        if (sequence_of_inidivual_revocations_to_internal(
                entry->revocations, entry->revocations_count, &internal_entry->contents) != 0)
        {
            return -1;
        }

        if (sequence_of_linkage_seeds_to_internal(
                (const OscmsLinkageSeed *)entry->single_seeds,
                entry->single_seeds_count,
                &internal_entry->singleSeed) != 0)
        {
            return -1;
        }
    }
    return 0;
}

static int sequence_of_la_groups_to_internal(const OscmsLaGroup *la_groups, size_t count, SequenceOfLAGroup_t *internal)
{
    memset(internal, 0, sizeof(SequenceOfLAGroup_t));
    if (count == 0)
    {
        return 0;
    }

    if (!la_groups)
    {
        oscms_log(LOG_CRIT, "%s: la_groups is NULL", __func__);
        return -1;
    }

    if (allocate_asn1c_sequence_of(count, sizeof(LAGroup_t), _A_SEQUENCE_FROM_VOID(internal)) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < count; i++)
    {
        LAGroup_t *internal_entry = internal->list.array[i];
        const OscmsLaGroup *entry = &la_groups[i];

        if (oscms_octet_string_init_from_buffer(entry->la1_id, sizeof(entry->la1_id), &internal_entry->la1Id) != 0)
        {
            return -1;
        }
        if (oscms_octet_string_init_from_buffer(entry->la2_id, sizeof(entry->la2_id), &internal_entry->la2Id) != 0)
        {
            return -1;
        }

        if (sequence_of_imax_groups_to_internal(
                entry->imax_groups, entry->imax_groups_count, &internal_entry->contents) != 0)
        {
            return -1;
        }
    }
    return 0;
}

static int j_max_group_to_internal(const OscmsJMaxGroup *jmax_group, JMaxGroup_t *internal)
{
    memset(internal, 0, sizeof(JMaxGroup_t));
    internal->jmax = jmax_group->j_max;

    if (sequence_of_la_groups_to_internal(jmax_group->groups, jmax_group->groups_count, &internal->contents) != 0)
    {
        return -1;
    }

    return 0;
}

static int jmax_group_sequence_to_internal(
    const OscmsJMaxGroup *jmax_group, size_t count, SequenceOfJMaxGroup_t **internal)
{
    if (count > 0)
    {
        if (!jmax_group)
        {
            oscms_log(LOG_CRIT, "%s: Non-zero Individual count with NULL array", __func__);
            return -1;
        }

        *internal = calloc(count, sizeof(SequenceOfJMaxGroup_t));
        if (!*internal)
        {
            return -1;
        }

        if (allocate_asn1c_sequence_of(count, sizeof(JMaxGroup_t), _A_SEQUENCE_FROM_VOID(*internal)) != 0)
        {
            return -1;
        }

        for (size_t i = 0; i < count; i++)
        {
            if (j_max_group_to_internal(&jmax_group[i], (*internal)->list.array[i]) != 0)
            {
                return -1;
            }
        }
    }

    return 0;
}

static int tbs_hash_id_crl_to_internal(const OscmsTbsHashIdCrl *tbshash_id_crl, ToBeSignedHashIdCrl_t *internal)
{
    internal->crlSerial = tbshash_id_crl->crl_serial;

    if (allocate_asn1c_sequence_of(
            tbshash_id_crl->revocation_info_count,
            sizeof(HashBasedRevocationInfo_t),
            _A_SEQUENCE_FROM_VOID(&internal->entries)) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < tbshash_id_crl->revocation_info_count; i++)
    {
        HashBasedRevocationInfo_t *internal_entry = internal->entries.list.array[i];
        const OscmsHashBasedRevocationInfo *entry = &tbshash_id_crl->revocation_info[i];

        internal_entry->expiry = entry->expiry;
        if (oscms_octet_string_init_from_buffer(entry->id, sizeof(entry->id), &internal_entry->id) != 0)
        {
            // Caller will invoke ASN_STRUCT_RESET on error
            return -1;
        }
    }
    return 0;
}

static int sequence_of_group_single_seed_crl_entry_to_internal(
    const OscmsGroupSingleSeedCrlEntry *single_seed_crl_entries,
    size_t count,
    SequenceOfGroupSingleSeedCrlEntry_t **internal_ptr)
{
    if (count > 0)
    {
        if (!single_seed_crl_entries)
        {
            oscms_log(LOG_CRIT, "%s: Non-zero Individual count with NULL array", __func__);
            return -1;
        }
    }
    else
    {
        *internal_ptr = 0;
        return 0;
    }

    *internal_ptr = calloc(1, sizeof(SequenceOfGroupSingleSeedCrlEntry_t));

    if (!*internal_ptr)
    {
        return -1;
    }

    SequenceOfGroupSingleSeedCrlEntry_t *internal = *internal_ptr;

    if (allocate_asn1c_sequence_of(count, sizeof(GroupSingleSeedCrlEntry_t), _A_SEQUENCE_FROM_VOID(internal)) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < count; i++)
    {
        GroupSingleSeedCrlEntry_t *internal_entry = internal->list.array[i];
        const OscmsGroupSingleSeedCrlEntry *entry = &single_seed_crl_entries[i];

        internal_entry->iMax = entry->i_max;
        if (oscms_octet_string_init_from_buffer(entry->la_id, sizeof(entry->la_id), &internal_entry->laId) != 0)
        {
            // Caller will invoke ASN_STRUCT_RESET on error
            return -1;
        }

        if (oscms_octet_string_init_from_buffer(
                entry->linkage_seed, sizeof(entry->linkage_seed), &internal_entry->linkageSeed) != 0)
        {
            // Caller will invoke ASN_STRUCT_RESET on error
            return -1;
        }
    }

    return 0;
}
static int sequence_of_group_crl_entry_to_internal(
    const OscmsGroupCrlEntry *group_crl_entries, size_t count, SequenceOfGroupCrlEntry_t **internal_ptr)
{
    if (count > 0)
    {
        if (!group_crl_entries)
        {
            oscms_log(LOG_CRIT, "%s: Non-zero Individual count with NULL array", __func__);
            return -1;
        }
    }
    else
    {
        *internal_ptr = 0;
        return 0;
    }

    *internal_ptr = calloc(1, sizeof(SequenceOfGroupCrlEntry_t));

    if (!*internal_ptr)
    {
        return -1;
    }

    SequenceOfGroupCrlEntry_t *internal = *internal_ptr;

    if (allocate_asn1c_sequence_of(count, sizeof(GroupCrlEntry_t), _A_SEQUENCE_FROM_VOID(internal)) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < count; i++)
    {
        GroupCrlEntry_t *internal_entry = internal->list.array[i];
        const OscmsGroupCrlEntry *entry = &group_crl_entries[i];
        internal_entry->iMax            = entry->i_max;

        if (oscms_octet_string_init_from_buffer(entry->la1_id, sizeof(entry->la1_id), &internal_entry->la1Id) != 0)
        {
            return -1;
        }

        if (oscms_octet_string_init_from_buffer(
                entry->linkage_seed_1, sizeof(entry->linkage_seed_1), &internal_entry->linkageSeed1) != 0)
        {
            return -1;
        }

        if (oscms_octet_string_init_from_buffer(entry->la2_id, sizeof(entry->la2_id), &internal_entry->la2Id) != 0)
        {
            return -1;
        }

        if (oscms_octet_string_init_from_buffer(
                entry->linkage_seed_2, sizeof(entry->linkage_seed_2), &internal_entry->linkageSeed2) != 0)
        {
        }
    }
    return 0;
}

static int tbs_lv_crl_to_internal(const OscmsTbsLvCrl *api, ToBeSignedLinkageValueCrl_t *internal)
{
    internal->iRev         = api->i_rev;
    internal->indexWithinI = api->index_within_i;

    if (jmax_group_sequence_to_internal(api->individual, api->individual_count, &internal->individual) != 0)
    {
        return -1;
    }

    if (sequence_of_group_crl_entry_to_internal(api->groups, api->groups_count, &internal->groups) != 0)
    {
        return -1;
    }

    if (sequence_of_group_single_seed_crl_entry_to_internal(
            api->groups_single_seed, api->groups_single_seed_count, &internal->groupsSingleSeed) != 0)
    {
        return -1;
    }

    return 0;
}

static int tbs_lv_crl_with_alg_to_internal(
    const OscmsTbsLvCrlWithAlgorithmId *api, ToBeSignedLinkageValueCrlWithAlgIdentifier_t *internal)
{
    memset(internal, 0, sizeof(ToBeSignedLinkageValueCrlWithAlgIdentifier_t));

    // This variant is basically a ToBeSignedLinkageValueCrl but all OPTIONAL fields present.
    // Nut we can't call tbs_lv_crl_to_internal because of the presence of two NULL fields
    // in the internal representation.

    // Check that constraints are met.
    if (api->groups_count == 0 || api->groups_single_seed_count == 0 || api->individual_count == 0)
    {
        oscms_log(LOG_ERR, "%s: Missing mandatory field", __func__);
        return -1;
    }

    if (!api->groups || !api->groups_single_seed || !api->individual)
    {
        oscms_log(LOG_CRIT, "%s: Mandatory field with non-zero count but NULL pointer", __func__);
        return -1;
    }

    internal->iRev         = api->i_rev;
    internal->indexWithinI = api->index_within_i;

    if (jmax_group_sequence_to_internal(api->individual, api->individual_count, &internal->individual) != 0)
    {
        return -1;
    }

    if (sequence_of_group_crl_entry_to_internal(api->groups, api->groups_count, &internal->groups) != 0)
    {
        return -1;
    }

    if (sequence_of_group_single_seed_crl_entry_to_internal(
            api->groups_single_seed, api->groups_single_seed_count, &internal->groupsSingleSeed) != 0)
    {
        return -1;
    }

    return 0;
}

static int type_specific_crl_contents_to_internal(
    const OscmsTypeSpecificCrlContents *type_specific_crl_contents, TypeSpecificCrlContents_t *internal)
{
    if (!type_specific_crl_contents || !internal)
    {
        return -1;
    }

    memset(internal, 0, sizeof(TypeSpecificCrlContents_t));
    internal->present = (TypeSpecificCrlContents_PR)type_specific_crl_contents->type;

    int rc = 0;

    switch (internal->present)
    {
        case TypeSpecificCrlContents_PR_fullHashCrl:
            rc = tbs_hash_id_crl_to_internal(
                &type_specific_crl_contents->contents.full_hash_crl, &internal->choice.fullHashCrl);
            break;

        case TypeSpecificCrlContents_PR_deltaHashCrl:
            rc = tbs_hash_id_crl_to_internal(
                &type_specific_crl_contents->contents.delta_hash_crl, &internal->choice.deltaHashCrl);
            break;

        case TypeSpecificCrlContents_PR_fullLinkedCrl:
            rc = tbs_lv_crl_to_internal(
                &type_specific_crl_contents->contents.full_linked_crl, &internal->choice.fullLinkedCrl);
            break;

        case TypeSpecificCrlContents_PR_deltaLinkedCrl:
            rc = tbs_lv_crl_to_internal(
                &type_specific_crl_contents->contents.delta_linked_crl, &internal->choice.deltaLinkedCrl);
            break;

        case TypeSpecificCrlContents_PR_fullLinkedCrlWithAlg:
            rc = tbs_lv_crl_with_alg_to_internal(
                &type_specific_crl_contents->contents.full_linked_crl_with_alg, &internal->choice.fullLinkedCrlWithAlg);
            break;

        case TypeSpecificCrlContents_PR_deltaLinkedCrlWithAlg:
            rc = tbs_lv_crl_with_alg_to_internal(
                &type_specific_crl_contents->contents.delta_linked_crl_with_alg,
                &internal->choice.deltaLinkedCrlWithAlg);
            break;

        default:
            oscms_log(LOG_ERR, "%s: Invalid TypeSpecificCrlContents", __func__);
            rc = -1;
            break;
    }

    return rc;
}

SO_EXPORT int oscms_encode_crl_contents(const OscmsSecuredCrl *secured_crl, OscmsOctetBuffer *encoded)
{
    if (!secured_crl || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    memset(encoded, 0, sizeof(OscmsOctetBuffer));
    CrlContents_t internal = {0};

    internal.version   = 1;
    internal.crlSeries = secured_crl->crl_series;
    internal.issueDate = secured_crl->issue_date;
    internal.nextCrl   = secured_crl->next_crl;

    if (secured_crl->priority_info_present)
    {
        internal.priorityInfo.priority = calloc(1, sizeof(*internal.priorityInfo.priority));

        if (!internal.priorityInfo.priority)
        {
            ASN_STRUCT_RESET(asn_DEF_CrlContents, &internal);
            oscms_log(LOG_CRIT, "%s: Failed to allocate PriorityInfo", __func__);
            return -1;
        }
        *(internal.priorityInfo.priority) = (Uint8_t)secured_crl->priority_info;
    }

    if (oscms_octet_string_init_from_buffer(secured_crl->crl_craca, sizeof(OscmsHashedId8), &internal.crlCraca) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_CrlContents, &internal);
        oscms_log(LOG_CRIT, "%s: Failed to initialize CrlCraca", __func__);
        return -1;
    }

    if (type_specific_crl_contents_to_internal(&secured_crl->type_specific, &internal.typeSpecific) != 0)
    {
        ASN_STRUCT_RESET(asn_DEF_CrlContents, &internal);
        oscms_log(LOG_CRIT, "%s: Failed to initialize TypeSpecificCrlContents", __func__);
        return -1;
    }

    int rc = check_and_encode(&internal, &asn_DEF_CrlContents, encoded);

    if (rc != 0)
    {
        oscms_log(LOG_ERR, "%s: Failed to encode CrlContents", __func__);
    }

    ASN_STRUCT_RESET(asn_DEF_CrlContents, &internal);
    return rc;
}

SO_EXPORT int oscms_encode_secured_crl_spdu(const OscmsDot2DataSignedArgs *secured_crl, OscmsOctetBuffer *encoded)
{
    if (!secured_crl || !encoded)
    {
        oscms_log(LOG_CRIT, "%s: Invalid input parameters", __func__);
        return -1;
    }

    // Make a local copy, so we can enforce the PSID constraint

    OscmsDot2DataSignedArgs local_copy = *secured_crl;
    local_copy.payload_psid            = OSCMS_PSID_CRL;

    return oscms_encode_dot2_data_signed(&local_copy, encoded);
}
