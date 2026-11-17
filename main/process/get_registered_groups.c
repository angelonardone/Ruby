#ifndef AMALGAMATED_BUILD
#include "../group.h"
#include "../jade_assert.h"
#include "../process.h"
#include "../storage.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../wallet.h"

#include "process_utils.h"

// Ruby: the DistributedCryptography Taproot groups registered for the current wallet (see register_group.c)
// reply: { group_name: { label, type ("delegated" | "multisig"), threshold, num_signers, owner (bool) }, ... }

typedef struct {
    char name[NVS_KEY_NAME_MAX_SIZE];
    char label[MAX_GROUP_LABEL_LEN + 1];
    uint8_t type;
    uint8_t threshold;
    uint8_t num_signers;
    bool owner;
} group_desc_t;

typedef struct {
    group_desc_t groups[MAX_GROUP_REGISTRATIONS];
    size_t num_groups;
} group_descriptions_t;

void reply_registered_groups(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    const group_descriptions_t* descriptions = (const group_descriptions_t*)ctx;
    JADE_ASSERT(descriptions->num_groups <= MAX_GROUP_REGISTRATIONS);

    CborEncoder root_encoder;
    CborError cberr = cbor_encoder_create_map(container, &root_encoder, descriptions->num_groups);
    JADE_ASSERT(cberr == CborNoError);

    for (size_t i = 0; i < descriptions->num_groups; ++i) {
        const group_desc_t* const desc = descriptions->groups + i;

        cberr = cbor_encode_text_stringz(&root_encoder, desc->name);
        JADE_ASSERT(cberr == CborNoError);

        CborEncoder entry_encoder;
        cberr = cbor_encoder_create_map(&root_encoder, &entry_encoder, 5);
        JADE_ASSERT(cberr == CborNoError);

        add_string_to_map(&entry_encoder, "label", desc->label);
        add_string_to_map(&entry_encoder, "type", group_type_rpc_name(desc->type));
        add_uint_to_map(&entry_encoder, "threshold", desc->threshold);
        add_uint_to_map(&entry_encoder, "num_signers", desc->num_signers);
        add_boolean_to_map(&entry_encoder, "owner", desc->owner);

        cberr = cbor_encoder_close_container(&root_encoder, &entry_encoder);
        JADE_ASSERT(cberr == CborNoError);
    }

    cberr = cbor_encoder_close_container(container, &root_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void get_registered_groups_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    group_descriptions_t* const descriptions = JADE_CALLOC(1, sizeof(group_descriptions_t));
    group_data_t* const group = JADE_MALLOC(sizeof(group_data_t));

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_registered_groups");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);

    char names[MAX_GROUP_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE];
    size_t num_names = 0;
    if (!storage_get_all_group_registration_names(names, MAX_GROUP_REGISTRATIONS, &num_names)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to load group registrations");
        goto cleanup;
    }

    for (size_t i = 0; i < num_names; ++i) {
        const char* errmsg = NULL;
        if (!group_load_from_storage(names[i], group, &errmsg)) {
            // Corrupt or for another wallet - just log and skip
            JADE_LOGD("Group %s: %s", names[i], errmsg ? errmsg : "not valid");
            continue;
        }
        group_desc_t* const desc = descriptions->groups + descriptions->num_groups++;
        strcpy(desc->name, names[i]);
        strcpy(desc->label, group->label);
        desc->type = group->type;
        desc->threshold = group->threshold;
        desc->num_signers = group->num_signers;
        desc->owner = group->we_are_owner;
    }

    const size_t buflen = 256 + (128 * descriptions->num_groups);
    uint8_t* const buf = JADE_MALLOC(buflen);
    jade_process_reply_to_message_result(&process->ctx, buf, buflen, descriptions, reply_registered_groups);
    free(buf);
    JADE_LOGI("Success");

cleanup:
    free(group);
    free(descriptions);
}
#endif // AMALGAMATED_BUILD
