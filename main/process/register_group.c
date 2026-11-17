#ifndef AMALGAMATED_BUILD
#include "../group.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../utils/util.h"
#include "../wallet.h"

#include "process_utils.h"

#include <ctype.h>
#include <sodium/utils.h>

// Ruby: register a DistributedCryptography Taproot group (see group.h and RUBY-GROUPS.md)
//
// params: network, group_name (storage key, <= 15 chars), label (shown on Ruby, <= 40 chars),
//         type ("delegated" | "multisig" | "musig2-delegated" | "musig2-multisig"), threshold (k),
//         owner: { receiving: xpub, change: xpub }              (delegated and musig2-delegated only)
//         signers: [ { receiving: xpub, change: xpub }, ... ]  (the members / every signer, any order)
//         receiving_path, change_path: this Ruby's chain paths (its key in the group is one of the xpubs above)

bool show_register_group_activity(const group_data_t* group, const char* address0, bool overwriting);

// Longest xpub string accepted (111 characters for a BIP32 serialized key)
#define MAX_XPUB_STR_LEN 120

static bool group_rpc_get_xpub(const char* field, const CborValue* map, const uint32_t version, struct ext_key* key)
{
    char xpub[MAX_XPUB_STR_LEN];
    size_t written = 0;
    rpc_get_string(field, sizeof(xpub), map, xpub, &written);
    if (!written || written >= sizeof(xpub) || bip32_key_from_base58_n(xpub, written, key) != WALLY_OK) {
        return false;
    }
    // A public key of the right network
    return key->version == version;
}

static bool group_rpc_get_chain_xpubs(const CborValue* map, const uint32_t version, struct ext_key* receiving, struct ext_key* change)
{
    return map && cbor_value_is_map(map) && group_rpc_get_xpub("receiving", map, version, receiving)
        && group_rpc_get_xpub("change", map, version, change);
}

static bool group_same_key(const struct ext_key* a, const struct ext_key* b)
{
    return !memcmp(a->pub_key, b->pub_key, sizeof(a->pub_key));
}

static bool group_same_xpub(const struct ext_key* a, const struct ext_key* b)
{
    return group_same_key(a, b) && !memcmp(a->chain_code, b->chain_code, sizeof(a->chain_code));
}

// Parse and check everything; on error set errmsg
static bool group_rpc_parse(
    const CborValue* params, const network_t network_id, char* group_name, group_data_t* group, const char** errmsg)
{
    group->network_id = network_id;

    size_t written = 0;
    rpc_get_string("group_name", NVS_KEY_NAME_MAX_SIZE, params, group_name, &written);
    if (!written || !storage_key_name_valid(group_name)) {
        *errmsg = "Missing or invalid group_name";
        return false;
    }

    written = 0;
    rpc_get_string("label", sizeof(group->label), params, group->label, &written);
    if (!written || written > MAX_GROUP_LABEL_LEN || !string_all(group->label, isprint)) {
        *errmsg = "Missing or invalid label";
        return false;
    }

    char type[24]; // "musig2-delegated" + nul
    written = 0;
    rpc_get_string("type", sizeof(type), params, type, &written);
    if (written && !strcmp(type, "delegated")) {
        group->type = GROUP_TYPE_DELEGATED;
    } else if (written && !strcmp(type, "multisig")) {
        group->type = GROUP_TYPE_MULTISIG;
    } else if (written && !strcmp(type, "musig2-delegated")) {
        group->type = GROUP_TYPE_MUSIG2_DELEGATED;
    } else if (written && !strcmp(type, "musig2-multisig")) {
        group->type = GROUP_TYPE_MUSIG2_MULTISIG;
    } else {
        *errmsg = "Invalid group type";
        return false;
    }

    uint32_t threshold = 0;
    if (!rpc_get_uint32("threshold", params, &threshold) || !threshold || threshold > MAX_GROUP_SIGNERS
        || (group_type_is_musig2(group->type) && threshold < 2)) {
        *errmsg = "Invalid threshold";
        return false;
    }
    group->threshold = (uint8_t)threshold;

    const uint32_t version
        = network_to_type(network_id) == NETWORK_TYPE_MAIN ? BIP32_VER_MAIN_PUBLIC : BIP32_VER_TEST_PUBLIC;

    if (group_type_has_owner(group->type)) {
        CborValue owner;
        if (!rpc_get_map("owner", params, &owner)
            || !group_rpc_get_chain_xpubs(&owner, version, &group->owner[GROUP_CHAIN_RECEIVING], &group->owner[GROUP_CHAIN_CHANGE])) {
            *errmsg = "Missing or invalid owner keys";
            return false;
        }
    } else if (rpc_has_field_data("owner", params)) {
        *errmsg = "A Multi Signature group has no owner";
        return false;
    }

    CborValue signers;
    size_t num_signers = 0;
    if (!rpc_get_array("signers", params, &signers, &num_signers) || num_signers < 2
        || num_signers > MAX_GROUP_SIGNERS) {
        *errmsg = "Invalid signers (2 to 15)";
        return false;
    }
    CborValue item;
    if (cbor_value_enter_container(&signers, &item) != CborNoError) {
        *errmsg = "Invalid signers";
        return false;
    }
    for (size_t i = 0; i < num_signers; ++i) {
        if (!group_rpc_get_chain_xpubs(&item, version, &group->signers[GROUP_CHAIN_RECEIVING][i],
                &group->signers[GROUP_CHAIN_CHANGE][i])
            || cbor_value_advance(&item) != CborNoError) {
            *errmsg = "Invalid signer keys";
            return false;
        }
    }
    group->num_signers = (uint8_t)num_signers;

    const size_t num_leaves = group_num_leaves(num_signers, threshold);
    if (!num_leaves || num_leaves > MAX_GROUP_LEAVES) {
        *errmsg = "Too many combinations of signers for Ruby";
        return false;
    }

    // Every key of a chain different (owner included)
    for (size_t c = 0; c < 2; ++c) {
        for (size_t i = 0; i < num_signers; ++i) {
            if (group_type_has_owner(group->type) && group_same_key(&group->signers[c][i], &group->owner[c])) {
                *errmsg = "The owner is also a signer";
                return false;
            }
            for (size_t j = i + 1; j < num_signers; ++j) {
                if (group_same_key(&group->signers[c][i], &group->signers[c][j])) {
                    *errmsg = "Two signers have the same key";
                    return false;
                }
            }
        }
    }

    // This Ruby's chains: its xpubs at the given paths must be the owner's or one signer's (on both chains)
    const char* path_fields[2] = { "receiving_path", "change_path" };
    bool owner_match = group_type_has_owner(group->type);
    bool signer_match = true;
    for (size_t c = 0; c < 2; ++c) {
        if (!rpc_get_bip32_path(path_fields[c], params, group->chain_path[c], MAX_PATH_LEN - 1, &group->chain_path_len[c])
            || !group->chain_path_len[c]) {
            *errmsg = "Missing or invalid receiving_path / change_path";
            return false;
        }
        struct ext_key ours;
        if (!wallet_get_hdkey(
                group->chain_path[c], group->chain_path_len[c], BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &ours)) {
            *errmsg = "Failed to derive this Ruby's keys";
            return false;
        }
        owner_match = owner_match && group_same_xpub(&group->owner[c], &ours);
        bool found = false;
        for (size_t i = 0; i < num_signers && !found; ++i) {
            found = group_same_xpub(&group->signers[c][i], &ours);
        }
        signer_match = signer_match && found;
    }
    if (!owner_match && !signer_match) {
        *errmsg = "This Ruby is not a participant of the group";
        return false;
    }
    group->we_are_owner = owner_match;

    // The order the addresses are built with
    group_sort_signers(group);
    return true;
}

void register_group_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    group_data_t* const group = JADE_CALLOC(1, sizeof(group_data_t));
    uint8_t* registration = NULL;
    char* address0 = NULL;
    char* address1 = NULL;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "register_group");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    const char* errmsg = NULL;
    char group_name[NVS_KEY_NAME_MAX_SIZE];
    if (!group_rpc_parse(&params, network_id, group_name, group, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        goto cleanup;
    }

    // The first receiving and change addresses: checks the keys and is shown for verification
    if (!group_get_address(group, network_id, GROUP_CHAIN_RECEIVING, 0, &address0)
        || !group_get_address(group, network_id, GROUP_CHAIN_CHANGE, 0, &address1)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to calculate the group addresses");
        goto cleanup;
    }
    JADE_LOGI("Group %s: %s %u of %u, first address %s", group_name, group_type_name(group->type), group->threshold,
        group->num_signers, address0);

    const size_t registration_len = group_record_len(group);
    registration = JADE_MALLOC(registration_len);
    if (!group_to_bytes(group, registration, registration_len)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to serialise group");
        goto cleanup;
    }

    const bool overwriting = storage_group_name_exists(group_name);
    if (overwriting) {
        // Identical record: nothing to ask
        size_t written = 0;
        uint8_t* const existing = JADE_MALLOC(registration_len);
        const bool identical = storage_get_group_registration(group_name, existing, registration_len, &written)
            && written == registration_len && !sodium_memcmp(existing, registration, registration_len);
        free(existing);
        if (identical) {
            JADE_LOGI("Group %s: identical registration exists", group_name);
            jade_process_reply_to_message_ok(process);
            goto cleanup;
        }
    } else if (storage_get_group_registration_count() >= MAX_GROUP_REGISTRATIONS) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Already have maximum number of groups");
        goto cleanup;
    }

    // Never fill the storage (the PIN counter must stay writable)
    if (!storage_has_room_for_blob(registration_len)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Not enough storage space on Ruby");
        goto cleanup;
    }

    if (!show_register_group_activity(group, address0, overwriting)) {
        JADE_LOGW("User declined to register group");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined to register group");
        goto cleanup;
    }

    if (!storage_set_group_registration(group_name, registration, registration_len)) {
        await_error("Error saving group");
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to persist group data");
        goto cleanup;
    }

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    if (address0) {
        JADE_WALLY_VERIFY(wally_free_string(address0));
    }
    if (address1) {
        JADE_WALLY_VERIFY(wally_free_string(address1));
    }
    free(registration);
    free(group);
}
#endif // AMALGAMATED_BUILD
