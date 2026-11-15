#ifndef AMALGAMATED_BUILD
#include "psbt.h"
#include "../keychain.h"
#include "../sensitive.h"
#include "../wallet.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "util.h"

#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_script.h>

// Ruby: an input spent by the key path of a taproot output that also commits to scripts (merkle root present).
// True only if: one key, no leaf hashes for it, a 32-byte merkle root, and the coin spent is the P2TR of that key
// tweaked with that merkle root (BIP341).
static bool key_iter_is_taproot_keypath_with_scripts(
    const key_iter* iter, const struct wally_map* keypaths, const struct wally_map_item* merkle_root)
{
    JADE_ASSERT(iter && iter->is_input);
    if (keypaths->num_items != 1 || !merkle_root->value || merkle_root->value_len != SHA256_LEN) {
        return false;
    }
    const struct wally_psbt_input* input = &iter->psbt->inputs[iter->index];
    const struct wally_map_item* key = &keypaths->items[0];
    if (!key->key || key->key_len != EC_XONLY_PUBLIC_KEY_LEN) {
        return false;
    }
    // A leaf hash for the key means it signs a script, not the key path
    for (size_t i = 0; i < input->taproot_leaf_hashes.num_items; ++i) {
        if (input->taproot_leaf_hashes.items[i].value_len) {
            return false;
        }
    }
    const struct wally_tx_output* utxo = NULL;
    if (wally_psbt_get_input_best_utxo(iter->psbt, iter->index, &utxo) != WALLY_OK || !utxo || !utxo->script
        || utxo->script_len != 2 + EC_XONLY_PUBLIC_KEY_LEN || utxo->script[0] != OP_1
        || utxo->script[1] != EC_XONLY_PUBLIC_KEY_LEN) {
        return false;
    }
    uint8_t tweaked[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_bip341_tweak(
            key->key, key->key_len, merkle_root->value, merkle_root->value_len, 0, tweaked, sizeof(tweaked))
        != WALLY_OK) {
        return false;
    }
    return !memcmp(tweaked + 1, utxo->script + 2, EC_XONLY_PUBLIC_KEY_LEN);
}

// Ruby: BIP341 TapLeaf hash of a leaf script (leaf version, compact-size length, script)
static bool tapleaf_hash(const uint8_t leaf_version, const uint8_t* script, const size_t script_len, uint8_t* hash_out)
{
    if (!script || !script_len || script_len > 0xffff) {
        return false;
    }
    const size_t prefix_len = script_len < 0xfd ? 2 : 4;
    uint8_t* const buf = JADE_MALLOC(prefix_len + script_len);
    buf[0] = leaf_version;
    if (prefix_len == 2) {
        buf[1] = (uint8_t)script_len;
    } else {
        buf[1] = 0xfd;
        buf[2] = (uint8_t)(script_len & 0xff);
        buf[3] = (uint8_t)(script_len >> 8);
    }
    memcpy(buf + prefix_len, script, script_len);
    const int ret = wally_bip340_tagged_hash(buf, prefix_len + script_len, "TapLeaf", hash_out, SHA256_LEN);
    free(buf);
    return ret == WALLY_OK;
}

// Ruby: true if the script is a BIP342 multi_a script (<k1> CHECKSIG <k2> CHECKSIGADD ... <k> NUMEQUAL) and one of
// its keys is the x-only key given.
static bool tapscript_is_multi_a_with_key(const uint8_t* script, const size_t script_len, const uint8_t* xonly)
{
    size_t pos = 0, num_keys = 0;
    bool found = false;
    while (pos + 1 + EC_XONLY_PUBLIC_KEY_LEN + 1 <= script_len && script[pos] == EC_XONLY_PUBLIC_KEY_LEN) {
        const uint8_t op = script[pos + 1 + EC_XONLY_PUBLIC_KEY_LEN];
        if (op != (num_keys ? OP_CHECKSIGADD : OP_CHECKSIG)) {
            return false;
        }
        if (!memcmp(script + pos + 1, xonly, EC_XONLY_PUBLIC_KEY_LEN)) {
            found = true;
        }
        pos += 1 + EC_XONLY_PUBLIC_KEY_LEN + 1;
        ++num_keys;
    }
    if (!num_keys || num_keys > 999) {
        return false;
    }
    // The threshold: OP_1..OP_16, or a minimal push of 1 or 2 bytes (k > 16), then OP_NUMEQUAL as the last opcode
    size_t k = 0;
    if (pos + 2 == script_len && script[pos] >= OP_1 && script[pos] <= OP_16) {
        k = script[pos] - OP_1 + 1;
    } else if (pos + 3 == script_len && script[pos] == 1 && script[pos + 1] > 16 && script[pos + 1] < 0x80) {
        k = script[pos + 1];
    } else if (pos + 4 == script_len && script[pos] == 2 && (script[pos + 2] || script[pos + 1] >= 0x80)
        && script[pos + 2] < 0x80) {
        k = script[pos + 1] | ((size_t)script[pos + 2] << 8);
    } else {
        return false;
    }
    if (script[script_len - 1] != OP_NUMEQUAL || !k || k > num_keys) {
        return false;
    }
    return found;
}

// Ruby: BIP341 check that a leaf (by its hash) is committed in the P2TR coin spent, using its control block:
// control block = (leaf version | output key parity) || internal key || merkle path (32 bytes per level, at most 128).
static bool taproot_control_block_commits(const uint8_t* control, const size_t control_len, const uint8_t leaf_version,
    const uint8_t* leaf_hash, const struct wally_tx_output* utxo)
{
    if (!control || control_len < 1 + EC_XONLY_PUBLIC_KEY_LEN
        || (control_len - 1 - EC_XONLY_PUBLIC_KEY_LEN) % SHA256_LEN
        || (control_len - 1 - EC_XONLY_PUBLIC_KEY_LEN) / SHA256_LEN > 128 || (control[0] & 0xfe) != leaf_version) {
        return false;
    }
    if (!utxo || !utxo->script || utxo->script_len != 2 + EC_XONLY_PUBLIC_KEY_LEN || utxo->script[0] != OP_1
        || utxo->script[1] != EC_XONLY_PUBLIC_KEY_LEN) {
        return false;
    }
    uint8_t node[SHA256_LEN];
    uint8_t branch[2 * SHA256_LEN];
    memcpy(node, leaf_hash, SHA256_LEN);
    for (size_t off = 1 + EC_XONLY_PUBLIC_KEY_LEN; off < control_len; off += SHA256_LEN) {
        const uint8_t* sibling = control + off;
        // TapBranch: the two hashes in lexicographic order
        if (memcmp(node, sibling, SHA256_LEN) < 0) {
            memcpy(branch, node, SHA256_LEN);
            memcpy(branch + SHA256_LEN, sibling, SHA256_LEN);
        } else {
            memcpy(branch, sibling, SHA256_LEN);
            memcpy(branch + SHA256_LEN, node, SHA256_LEN);
        }
        if (wally_bip340_tagged_hash(branch, sizeof(branch), "TapBranch", node, sizeof(node)) != WALLY_OK) {
            return false;
        }
    }
    uint8_t tweaked[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_bip341_tweak(
            control + 1, EC_XONLY_PUBLIC_KEY_LEN, node, sizeof(node), 0, tweaked, sizeof(tweaked))
        != WALLY_OK) {
        return false;
    }
    // The output key, and its parity as written in the control block
    return !memcmp(tweaked + 1, utxo->script + 2, EC_XONLY_PUBLIC_KEY_LEN)
        && ((tweaked[0] == 0x03) == ((control[0] & 1) == 1));
}

const struct wally_map_item* psbt_find_taproot_leaf_script(
    const struct wally_psbt_input* input, const uint8_t* leaf_hash, const struct wally_tx_output* utxo)
{
    JADE_ASSERT(input);
    JADE_ASSERT(leaf_hash);
    uint8_t hash[SHA256_LEN];
    for (size_t i = 0; i < input->taproot_leaf_scripts.num_items; ++i) {
        // key: the control block; value: the script followed by its leaf version
        const struct wally_map_item* item = &input->taproot_leaf_scripts.items[i];
        if (!item->key || !item->value || item->value_len < 2) {
            continue;
        }
        const uint8_t leaf_version = item->value[item->value_len - 1];
        if (leaf_version != 0xc0 || !tapleaf_hash(leaf_version, item->value, item->value_len - 1, hash)
            || memcmp(hash, leaf_hash, SHA256_LEN)) {
            continue;
        }
        if (utxo && !taproot_control_block_commits(item->key, item->key_len, leaf_version, hash, utxo)) {
            return NULL; // the leaf is not in the coin spent
        }
        return item;
    }
    return NULL;
}

// Ruby: an input spent by a script path (Delegated group member, Multi Signature group): our key signs the BIP342
// multi_a leaf scripts its leaf hashes name. True only if: one key (x-only), at least one leaf hash for it, and for
// every leaf hash a leaf script in the psbt that hashes to it (leaf version 0xc0), is a multi_a script holding our
// key, and whose control block proves the leaf is committed in the coin spent (BIP341). Nothing is signed by the
// key path.
static bool key_iter_is_taproot_scriptpath(const key_iter* iter, const struct wally_map* keypaths)
{
    JADE_ASSERT(iter && iter->is_input);
    if (keypaths->num_items != 1) {
        return false;
    }
    const struct wally_psbt_input* input = &iter->psbt->inputs[iter->index];
    const struct wally_map_item* key = &keypaths->items[0];
    if (!key->key || key->key_len != EC_XONLY_PUBLIC_KEY_LEN) {
        return false;
    }
    size_t found = 0;
    if (wally_map_find(&input->taproot_leaf_hashes, key->key, key->key_len, &found) != WALLY_OK || !found) {
        return false;
    }
    const struct wally_map_item* hashes = &input->taproot_leaf_hashes.items[found - 1];
    if (!hashes->value || !hashes->value_len || hashes->value_len % SHA256_LEN
        || hashes->value_len / SHA256_LEN > MAX_TAPROOT_LEAVES_SIGNED) {
        return false;
    }
    const struct wally_tx_output* utxo = NULL;
    if (wally_psbt_get_input_best_utxo(iter->psbt, iter->index, &utxo) != WALLY_OK || !utxo) {
        return false;
    }
    for (size_t off = 0; off < hashes->value_len; off += SHA256_LEN) {
        const struct wally_map_item* leaf = psbt_find_taproot_leaf_script(input, hashes->value + off, utxo);
        if (!leaf || !tapscript_is_multi_a_with_key(leaf->value, leaf->value_len - 1, key->key)) {
            return false;
        }
    }
    return true;
}

// Ensure a taproot input/output is single-key and keypath-only
// (until taproots with scripts are supported)
static bool key_iter_is_supported_taproot(const key_iter* iter, const struct wally_map* keypaths)
{
    if (keypaths->num_items > 1) {
        return false; // More than one keypath: a multisig script-path spend
    }
    if (iter->is_input) {
        const struct wally_psbt_input* input = &iter->psbt->inputs[iter->index];
        if (input->taproot_leaf_scripts.num_items) {
            // Ruby: a script-path spend. Accepted only for multi_a leaves holding our key that the coin spent
            // really commits to (see key_iter_is_taproot_scriptpath); signed per leaf in sign_psbt.
            return key_iter_is_taproot_scriptpath(iter, keypaths);
        }
        // TODO: use the wally merkle root accessor when it is exposed
        const uint32_t psbt_in_tap_merkle_root = 0x18; // From BIP-174
        const struct wally_map_item* merkle_root
            = wally_map_get_integer(&input->psbt_fields, psbt_in_tap_merkle_root);
        if (merkle_root) {
            // Ruby: the KEY PATH of an output that also has scripts (the owner of a Delegated group spends alone,
            // BIP341: output key = our key tweaked with the merkle root of the scripts). Accepted only when it is
            // really that: one key, no leaf hash for it, and the coin spent pays to exactly our key tweaked with
            // this merkle root. Wally signs with the same tweak.
            return key_iter_is_taproot_keypath_with_scripts(iter, keypaths, merkle_root);
        }
    } else {
        const struct wally_psbt_output* output = &iter->psbt->outputs[iter->index];
        if (output->taproot_tree.num_items) {
            return false; // Taptree present: script-path present
        }
    }
    return true; // One key, no merkle root, no scripts: OK
}

static bool key_iter_init(
    const struct wally_psbt* psbt, const size_t index, const bool is_input, const bool is_private, key_iter* iter)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(index < (is_input ? psbt->num_inputs : psbt->num_outputs));
    JADE_ASSERT(iter);
    iter->psbt = psbt;
    iter->index = index;
    iter->key_index = 0;
    --iter->key_index; // Incrementing will wrap around to 0 i.e. the first key
    iter->is_input = is_input;
    iter->is_private = is_private;
    iter->is_ga_2of3_recovery_key = false;
    // We are a taproot key iterator only if we have taproot keypaths
    if (is_input) {
        iter->is_taproot = psbt->inputs[index].taproot_leaf_paths.num_items != 0;
    } else {
        iter->is_taproot = psbt->outputs[index].taproot_leaf_paths.num_items != 0;
    }
    iter->is_valid = true;
    return key_iter_next(iter);
}

bool key_iter_input_begin(const struct wally_psbt* psbt, const size_t index, key_iter* iter)
{
    return key_iter_init(psbt, index, /* is_input */ true, /* is_private */ true, iter);
}

bool key_iter_input_begin_public(const struct wally_psbt* psbt, const size_t index, key_iter* iter)
{
    return key_iter_init(psbt, index, /* is_input */ true, /* is_private */ false, iter);
}

bool key_iter_output_begin_public(const struct wally_psbt* psbt, const size_t index, key_iter* iter)
{
    return key_iter_init(psbt, index, /* is_input */ false, /* is_private */ false, iter);
}

static const struct wally_map* key_iter_get_keypaths(const key_iter* iter)
{
    JADE_ASSERT(iter && iter->is_valid);
    if (iter->is_input) {
        const struct wally_psbt_input* input = &iter->psbt->inputs[iter->index];
        return iter->is_taproot ? &input->taproot_leaf_paths : &input->keypaths;
    }
    const struct wally_psbt_output* output = &iter->psbt->outputs[iter->index];
    return iter->is_taproot ? &output->taproot_leaf_paths : &output->keypaths;
}

// If the keypaths match those of a Green 2of3 multisig subaccount, take the
// (3'/subaccount') path from the user key and derive the parent recovery key.
// Should only be called when the first keypath has been determined to
// be a non-main account Green server key, and when 3 keypaths are present.
static bool key_iter_get_green_2of3_recovery_key(const key_iter* iter, const struct wally_map* keypaths,
    struct ext_key* recovery_hdkey, const uint32_t server_subaccount)
{
    JADE_ASSERT(iter && iter->is_valid);
    JADE_ASSERT(keypaths);
    JADE_ASSERT(recovery_hdkey);
    JADE_ASSERT(server_subaccount != 0); // Must not be called for the main account
    uint32_t path[GA_USER_PATH_MAX_LEN];
    const size_t start_idx = 1; // Ignore the Green server key at key index 0
    for (size_t index = start_idx; index < keypaths->num_items; ++index) {
        size_t path_len = 0;
        int ret = wally_map_keypath_get_item_path(keypaths, index, path, sizeof(path) / sizeof(path[0]), &path_len);
        JADE_WALLY_VERIFY(ret);
        uint32_t subaccount = 0;
        if (!is_potential_green_user_path(path, path_len, &subaccount) || subaccount != server_subaccount) {
            continue; // Didn't find a user key matching the servers subaccount key
        }
        // Keypath looks like the user key in a 2of3 (m/3'/subaccount'/1/pointer)
        // Use the first 2 elements (m/3'/subaccount') to derive a candidate parent recovery key
        ret = bip32_key_from_parent_path(&keychain_get()->xpriv, path, 2, BIP32_FLAG_KEY_PRIVATE, recovery_hdkey);
        return ret == WALLY_OK;
    }

    return false;
}

bool key_iter_next(key_iter* iter)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    size_t found_index;
    ++iter->key_index;
    if (iter->is_taproot && !iter->key_index) {
        // First iteration: validate
        iter->is_valid = key_iter_is_supported_taproot(iter, keypaths);
    }
    if (iter->is_valid) {
        int ret;
        typedef int (*get_bip32_key_fn)(
            const struct wally_map*, size_t, const struct ext_key*, struct ext_key*, size_t*);
        get_bip32_key_fn get_key
            = iter->is_private ? wally_map_keypath_get_bip32_key_from : wally_map_keypath_get_bip32_public_key_from;

        ret = get_key(keypaths, iter->key_index, &keychain_get()->xpriv, &iter->hdkey, &found_index);
        JADE_WALLY_VERIFY(ret);
        if (found_index == 0 && key_iter_get_num_keys(iter) == 3) {
            // Didn't match any of the 3 keys present: check Green 2of3 parent recovery key
            size_t path_len = 0;
            uint32_t path[MAX_GASERVICE_PATH_LEN];
            ret = wally_map_keypath_get_item_path(keypaths, 0, path, sizeof(path) / sizeof(path[0]), &path_len);
            JADE_WALLY_VERIFY(ret);
            uint32_t server_subaccount = 0;
            if (is_potential_green_server_path(path, path_len, &server_subaccount) && server_subaccount != 0) {
                // First key looks like a Green server key for a non-main account.
                // Derive a recovery key using the user key path and attempt to match it.
                struct ext_key recovery_hdkey;
                SENSITIVE_PUSH(&recovery_hdkey, sizeof(recovery_hdkey));
                if (key_iter_get_green_2of3_recovery_key(iter, keypaths, &recovery_hdkey, server_subaccount)) {
                    ret = get_key(keypaths, iter->key_index, &recovery_hdkey, &iter->hdkey, &found_index);
                    if (ret == WALLY_OK && found_index) {
                        // Mark this as a potential recovery key subject to future script validation
                        iter->is_ga_2of3_recovery_key = true;
                    }
                }
                SENSITIVE_POP(&recovery_hdkey);
            }
        }
        if (found_index) {
            iter->is_valid = true; // Found
            iter->key_index = found_index - 1; // Adjust to 0-based index
        } else {
            iter->is_valid = false; // Not found
        }
    }
    return iter->is_valid;
}

size_t key_iter_get_num_keys(const key_iter* iter)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    return keypaths->num_items;
}

bool key_iter_contains_pubkey(const key_iter* iter, const uint8_t* pubkey, const size_t pubkey_len)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    size_t written;
    const int ret = wally_map_find(keypaths, pubkey, pubkey_len, &written);
    return ret == WALLY_OK && written != 0;
}

bool key_iter_get_pubkey_at(const key_iter* iter, const size_t key_index, uint8_t* pubkey, const size_t pubkey_len)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    size_t written;
    const int ret = wally_map_get_item_key(keypaths, key_index, pubkey, pubkey_len, &written);
    // written must exactly match pubkey_len, so that we only match
    // compressed/uncompressed pubkeys depending on the callers intent
    return ret == WALLY_OK && written == pubkey_len;
}

void key_iter_get_fingerprint_at(
    const key_iter* iter, const size_t key_index, uint8_t* fingerprint, const size_t fingerprint_len)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    const int ret = wally_map_keypath_get_item_fingerprint(keypaths, key_index, fingerprint, fingerprint_len);
    JADE_WALLY_VERIFY(ret);
}

bool key_iter_get_path_at(
    const key_iter* iter, const size_t key_index, uint32_t* path, const size_t path_len, size_t* written)
{
    const struct wally_map* keypaths = key_iter_get_keypaths(iter);
    const int ret = wally_map_keypath_get_item_path(keypaths, key_index, path, path_len, written);
    return ret == WALLY_OK && *written <= path_len;
}

bool key_iter_get_path(const key_iter* iter, uint32_t* path, const size_t path_len, size_t* written)
{
    return key_iter_get_path_at(iter, iter->key_index, path, path_len, written);
}
#endif // AMALGAMATED_BUILD
