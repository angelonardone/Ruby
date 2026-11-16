#ifndef AMALGAMATED_BUILD
#include "group.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include "utils/temporary_stack.h"
#include "utils/util.h"
#include "wallet.h"

#include <sodium/utils.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>

// Record layout (all integers little endian), version 1:
//   version(1) network(1) type(1) k(1) n(1) flags(1: bit 0 = this Ruby is the owner)
//   label_len(1) label
//   2 x [ path_len(1) path(4 * path_len) ]                 this Ruby's receiving and change chain paths
//   Delegated only: owner receiving xpub(78) owner change xpub(78)
//   n x receiving xpub(78)   n x change xpub(78)           sorted, as used for the addresses
//   hmac(32)                                               HMAC-SHA256 with the wallet master key
static const uint8_t GROUP_RECORD_VERSION = 1;
#define GROUP_FLAG_OWNER 0x01

#ifndef OP_CHECKSIGADD
#define OP_CHECKSIGADD 0xba // BIP342
#endif

static inline void group_uint32_from_le(const uint8_t* buffer, uint32_t* val)
{
    *val = (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) | ((uint32_t)buffer[3] << 24);
}

#define TAPLEAF_VERSION_TAPSCRIPT 0xc0
#define XONLY_LEN EC_XONLY_PUBLIC_KEY_LEN
// Largest leaf script: MAX_GROUP_SIGNERS x (push 32 + key + CHECKSIG(ADD)) + OP_k + NUMEQUAL
#define MAX_LEAF_SCRIPT_LEN (MAX_GROUP_SIGNERS * (1 + XONLY_LEN + 1) + 2)

#define GROUP_RECORD_MAX_LEN                                                                                           \
    (7 + MAX_GROUP_LABEL_LEN + 2 * (1 + 4 * MAX_PATH_LEN) + 2 * BIP32_SERIALIZED_LEN                                   \
        + 2 * MAX_GROUP_SIGNERS * BIP32_SERIALIZED_LEN + HMAC_SHA256_LEN)

const char* group_type_name(const uint8_t type)
{
    return type == GROUP_TYPE_DELEGATED ? "Delegated" : type == GROUP_TYPE_MULTISIG ? "Multi Signature" : "Unknown";
}

size_t group_num_leaves(const size_t n, size_t k)
{
    if (!n || !k || k > n) {
        return 0;
    }
    if (k > n - k) {
        k = n - k;
    }
    size_t result = 1;
    for (size_t i = 0; i < k; ++i) {
        result = result * (n - i) / (i + 1); // exact at every step
        if (result > MAX_GROUP_LEAVES) {
            return SIZE_MAX;
        }
    }
    return result;
}

// The library sorts the signers by ExtPubKey.ToBytes() (depth, parent fingerprint, child number, chain code, key):
// the BIP32 serialization without the 4-byte version (equal for all of them).
static int compare_serialized_xpubs(const struct ext_key* a, const struct ext_key* b)
{
    uint8_t sa[BIP32_SERIALIZED_LEN], sb[BIP32_SERIALIZED_LEN];
    JADE_WALLY_VERIFY(bip32_key_serialize(a, BIP32_FLAG_KEY_PUBLIC, sa, sizeof(sa)));
    JADE_WALLY_VERIFY(bip32_key_serialize(b, BIP32_FLAG_KEY_PUBLIC, sb, sizeof(sb)));
    return memcmp(sa + 4, sb + 4, sizeof(sa) - 4);
}

void group_sort_signers(group_data_t* group)
{
    JADE_ASSERT(group);
    JADE_ASSERT(group->num_signers <= MAX_GROUP_SIGNERS);
    struct ext_key tmp;
    for (size_t chain = 0; chain < 2; ++chain) {
        struct ext_key* const keys = group->signers[chain];
        for (size_t i = 1; i < group->num_signers; ++i) {
            for (size_t j = i; j > 0 && compare_serialized_xpubs(&keys[j - 1], &keys[j]) > 0; --j) {
                tmp = keys[j];
                keys[j] = keys[j - 1];
                keys[j - 1] = tmp;
            }
        }
    }
}

// The leaves of the tree are generated in order (lexicographic k-combinations) while the tree is walked left to
// right, so no list of leaves is kept in memory.
typedef struct {
    size_t n;
    size_t k;
    const uint8_t (*xonly)[XONLY_LEN]; // the signers' derived x-only keys, in signer order
    uint8_t combination[MAX_GROUP_SIGNERS];
    size_t leaves_left;
} leaf_iter_t;

static bool next_leaf_hash(leaf_iter_t* it, uint8_t* hash_out)
{
    if (!it->leaves_left) {
        return false;
    }

    // BIP387 sortedmulti_a: the keys of this combination in x-only order
    const uint8_t* keys[MAX_GROUP_SIGNERS];
    for (size_t i = 0; i < it->k; ++i) {
        const uint8_t* key = it->xonly[it->combination[i]];
        size_t j = i;
        while (j > 0 && memcmp(keys[j - 1], key, XONLY_LEN) > 0) {
            keys[j] = keys[j - 1];
            --j;
        }
        keys[j] = key;
    }

    // TapLeaf hash of: leaf version, compact size, <x1> CHECKSIG <x2> CHECKSIGADD ... OP_k NUMEQUAL
    uint8_t buf[4 + MAX_LEAF_SCRIPT_LEN];
    const size_t script_len = it->k * (1 + XONLY_LEN + 1) + 2;
    size_t pos = 0;
    buf[pos++] = TAPLEAF_VERSION_TAPSCRIPT;
    if (script_len < 0xfd) {
        buf[pos++] = (uint8_t)script_len;
    } else {
        buf[pos++] = 0xfd;
        buf[pos++] = (uint8_t)(script_len & 0xff);
        buf[pos++] = (uint8_t)(script_len >> 8);
    }
    for (size_t i = 0; i < it->k; ++i) {
        buf[pos++] = XONLY_LEN;
        memcpy(buf + pos, keys[i], XONLY_LEN);
        pos += XONLY_LEN;
        buf[pos++] = i ? OP_CHECKSIGADD : OP_CHECKSIG;
    }
    JADE_ASSERT(it->k >= 1 && it->k <= 16);
    buf[pos++] = (uint8_t)(OP_1 + it->k - 1);
    buf[pos++] = OP_NUMEQUAL;
    JADE_ASSERT(pos <= sizeof(buf));

    if (wally_bip340_tagged_hash(buf, pos, "TapLeaf", hash_out, SHA256_LEN) != WALLY_OK) {
        return false;
    }

    // Next combination
    --it->leaves_left;
    if (it->leaves_left) {
        size_t i = it->k;
        while (i > 0 && it->combination[i - 1] == it->n - it->k + i - 1) {
            --i;
        }
        JADE_ASSERT(i > 0);
        ++it->combination[i - 1];
        for (size_t j = i; j < it->k; ++j) {
            it->combination[j] = it->combination[j - 1] + 1;
        }
    }
    return true;
}

// TapBranch of two hashes: in lexicographic order. 'hash' (the right one) is replaced by the branch hash.
static bool tap_branch(const uint8_t* left, uint8_t* hash)
{
    uint8_t branch[2 * SHA256_LEN];
    const bool left_first = memcmp(left, hash, SHA256_LEN) <= 0;
    memcpy(branch, left_first ? left : hash, SHA256_LEN);
    memcpy(branch + SHA256_LEN, left_first ? hash : left, SHA256_LEN);
    return wally_bip340_tagged_hash(branch, sizeof(branch), "TapBranch", hash, SHA256_LEN) == WALLY_OK;
}

// The merkle root of the defined tree (see group.h): tree(S) = leaf if |S| == 1, else
// { tree(first ceil(|S|/2)), tree(rest) }. Walked without recursion (the stack of the calling task is small): an
// explicit stack of the nodes from the root to the current one (depth <= 11 for 2000 leaves), each with its number
// of leaves and, once its left subtree is done, that subtree's hash. The leaves are produced in order.
#define GROUP_TREE_MAX_DEPTH 16
typedef struct {
    size_t count;
    bool have_left;
    uint8_t left[SHA256_LEN];
} tree_node_t;

static bool tree_root(leaf_iter_t* it, const size_t num_leaves, uint8_t* root)
{
    tree_node_t* const nodes = JADE_CALLOC(GROUP_TREE_MAX_DEPTH, sizeof(tree_node_t));
    size_t depth = 0;
    nodes[0].count = num_leaves;
    uint8_t hash[SHA256_LEN];
    bool ok = true;
    while (ok) {
        // Down the left side to a leaf
        while (nodes[depth].count > 1) {
            JADE_ASSERT(depth + 1 < GROUP_TREE_MAX_DEPTH);
            nodes[depth + 1].count = (nodes[depth].count + 1) / 2;
            nodes[depth + 1].have_left = false;
            ++depth;
        }
        if (!next_leaf_hash(it, hash)) {
            ok = false;
            break;
        }
        // Up: a finished node is the left subtree of its parent (go to the right one) or completes the parent
        while (true) {
            if (depth == 0) {
                memcpy(root, hash, SHA256_LEN);
                free(nodes);
                return true;
            }
            tree_node_t* const parent = &nodes[depth - 1];
            if (!parent->have_left) {
                memcpy(parent->left, hash, SHA256_LEN);
                parent->have_left = true;
                nodes[depth].count = parent->count - (parent->count + 1) / 2;
                nodes[depth].have_left = false;
                break; // down the right subtree
            }
            if (!tap_branch(parent->left, hash)) {
                ok = false;
                break;
            }
            --depth;
        }
    }
    free(nodes);
    return false;
}

// BIP327 KeyAgg(KeySort(keys)) as an x-only key
static bool musig_key_agg(const uint8_t (*compressed)[EC_PUBLIC_KEY_LEN], const size_t n, uint8_t* xonly_out)
{
    const secp256k1_context* ctx = (const secp256k1_context*)wally_get_secp_context();
    JADE_ASSERT(ctx);

    // KeySort: by the 33-byte compressed encoding
    const uint8_t* sorted[MAX_GROUP_SIGNERS];
    for (size_t i = 0; i < n; ++i) {
        size_t j = i;
        while (j > 0 && memcmp(sorted[j - 1], compressed[i], EC_PUBLIC_KEY_LEN) > 0) {
            sorted[j] = sorted[j - 1];
            --j;
        }
        sorted[j] = compressed[i];
    }

    secp256k1_pubkey pubkeys[MAX_GROUP_SIGNERS];
    const secp256k1_pubkey* pointers[MAX_GROUP_SIGNERS];
    for (size_t i = 0; i < n; ++i) {
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkeys[i], sorted[i], EC_PUBLIC_KEY_LEN)) {
            return false;
        }
        pointers[i] = &pubkeys[i];
    }
    secp256k1_xonly_pubkey aggregate;
    return secp256k1_musig_pubkey_agg(ctx, &aggregate, NULL, pointers, n)
        && secp256k1_xonly_pubkey_serialize(ctx, xonly_out, &aggregate);
}

static bool group_get_script_impl(
    const group_data_t* group, const uint8_t chain, const uint32_t index, uint8_t* script, const size_t script_len)
{
    JADE_ASSERT(group);
    JADE_ASSERT(chain <= GROUP_CHAIN_CHANGE);
    JADE_ASSERT(script);
    if (script_len < WALLY_SCRIPTPUBKEY_P2TR_LEN || index & BIP32_INITIAL_HARDENED_CHILD) {
        return false;
    }
    const size_t n = group->num_signers;
    const size_t k = group->threshold;
    const size_t num_leaves = group_num_leaves(n, k);
    if (n < 2 || n > MAX_GROUP_SIGNERS || !num_leaves || num_leaves > MAX_GROUP_LEAVES) {
        return false;
    }

    // Every signer key derived once
    uint8_t(*compressed)[EC_PUBLIC_KEY_LEN] = JADE_MALLOC(MAX_GROUP_SIGNERS * EC_PUBLIC_KEY_LEN);
    uint8_t(*xonly)[XONLY_LEN] = JADE_MALLOC(MAX_GROUP_SIGNERS * XONLY_LEN);
    bool ok = true;
    struct ext_key child;
    for (size_t i = 0; ok && i < n; ++i) {
        ok = bip32_key_from_parent(
                 &group->signers[chain][i], index, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &child)
            == WALLY_OK;
        if (ok) {
            memcpy(compressed[i], child.pub_key, EC_PUBLIC_KEY_LEN);
            memcpy(xonly[i], child.pub_key + 1, XONLY_LEN);
        }
    }

    // The internal key
    uint8_t internal[XONLY_LEN];
    if (ok && group->type == GROUP_TYPE_DELEGATED) {
        ok = bip32_key_from_parent(&group->owner[chain], index, BIP32_FLAG_KEY_PUBLIC | BIP32_FLAG_SKIP_HASH, &child)
            == WALLY_OK;
        if (ok) {
            memcpy(internal, child.pub_key + 1, XONLY_LEN);
        }
    } else if (ok && group->type == GROUP_TYPE_MULTISIG) {
        ok = musig_key_agg((const uint8_t(*)[EC_PUBLIC_KEY_LEN])compressed, n, internal);
    } else {
        ok = false;
    }

    // The merkle root of the defined tree
    uint8_t merkle_root[SHA256_LEN];
    if (ok) {
        leaf_iter_t it = { .n = n, .k = k, .xonly = (const uint8_t(*)[XONLY_LEN])xonly, .leaves_left = num_leaves };
        for (size_t i = 0; i < k; ++i) {
            it.combination[i] = (uint8_t)i;
        }
        ok = tree_root(&it, num_leaves, merkle_root) && !it.leaves_left;
    }

    // BIP341 output key and P2TR script
    uint8_t tweaked[EC_PUBLIC_KEY_LEN];
    if (ok) {
        ok = wally_ec_public_key_bip341_tweak(
                 internal, sizeof(internal), merkle_root, sizeof(merkle_root), 0, tweaked, sizeof(tweaked))
            == WALLY_OK;
    }
    if (ok) {
        script[0] = OP_1;
        script[1] = XONLY_LEN;
        memcpy(script + 2, tweaked + 1, XONLY_LEN);
    }

    free(xonly);
    free(compressed);
    return ok;
}

// The address is calculated on a temporary stack of its own (as Jade does for descriptors): the callers (eg.
// get_receive_address, sign_psbt) already use much of the main task's stack, and key derivation, MuSig key
// aggregation and hashing need a few KB more.
#define GROUP_SCRIPT_STACK_SIZE (10 * 1024) // measured: up to ~7.4 KB used (Multi Signature, KeyAgg)

typedef struct {
    const group_data_t* group;
    uint8_t chain;
    uint32_t index;
    uint8_t* script;
    size_t script_len;
} group_script_args_t;

bool group_get_script_task(void* ctx)
{
    const group_script_args_t* args = (const group_script_args_t*)ctx;
    return group_get_script_impl(args->group, args->chain, args->index, args->script, args->script_len);
}

bool group_get_script(
    const group_data_t* group, const uint8_t chain, const uint32_t index, uint8_t* script, const size_t script_len)
{
    JADE_ASSERT(group);
    JADE_ASSERT(script);
    group_script_args_t args
        = { .group = group, .chain = chain, .index = index, .script = script, .script_len = script_len };
    return run_in_temporary_task(GROUP_SCRIPT_STACK_SIZE, group_get_script_task, &args);
}

bool group_get_address(
    const group_data_t* group, const network_t network_id, const uint8_t chain, const uint32_t index, char** address)
{
    JADE_ASSERT(group);
    JADE_INIT_OUT_PPTR(address);
    uint8_t script[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    if (!group_get_script(group, chain, index, script, sizeof(script))) {
        return false;
    }
    return wally_addr_segwit_from_bytes(script, sizeof(script), network_to_bech32_prefix(network_id), 0, address)
        == WALLY_OK;
}

bool group_path_to_chain_index(
    const group_data_t* group, const uint32_t* path, const size_t path_len, uint8_t* chain, uint32_t* index)
{
    JADE_ASSERT(group);
    JADE_ASSERT(path);
    JADE_ASSERT(chain);
    JADE_ASSERT(index);
    for (uint8_t c = 0; c < 2; ++c) {
        const size_t len = group->chain_path_len[c];
        if (path_len == len + 1 && !memcmp(path, group->chain_path[c], len * sizeof(uint32_t))
            && !(path[len] & BIP32_INITIAL_HARDENED_CHILD)) {
            *chain = c;
            *index = path[len];
            return true;
        }
    }
    return false;
}

size_t group_record_len(const group_data_t* group)
{
    JADE_ASSERT(group);
    const size_t label_len = strlen(group->label);
    JADE_ASSERT(label_len <= MAX_GROUP_LABEL_LEN);
    const size_t num_xpubs = 2 * group->num_signers + (group->type == GROUP_TYPE_DELEGATED ? 2 : 0);
    return 7 + label_len + 2 + 4 * (group->chain_path_len[0] + group->chain_path_len[1])
        + num_xpubs * BIP32_SERIALIZED_LEN + HMAC_SHA256_LEN;
}

bool group_to_bytes(const group_data_t* group, uint8_t* output, const size_t output_len)
{
    JADE_ASSERT(group);
    JADE_ASSERT(output);
    if (output_len != group_record_len(group) || output_len > GROUP_RECORD_MAX_LEN) {
        return false;
    }
    uint8_t* p = output;
    *p++ = GROUP_RECORD_VERSION;
    *p++ = (uint8_t)group->network_id;
    *p++ = group->type;
    *p++ = group->threshold;
    *p++ = group->num_signers;
    *p++ = group->we_are_owner ? GROUP_FLAG_OWNER : 0;
    const size_t label_len = strlen(group->label);
    *p++ = (uint8_t)label_len;
    memcpy(p, group->label, label_len);
    p += label_len;
    for (size_t c = 0; c < 2; ++c) {
        JADE_ASSERT(group->chain_path_len[c] <= MAX_PATH_LEN);
        *p++ = (uint8_t)group->chain_path_len[c];
        for (size_t i = 0; i < group->chain_path_len[c]; ++i) {
            uint32_to_le(group->chain_path[c][i], p);
            p += sizeof(uint32_t);
        }
    }
    if (group->type == GROUP_TYPE_DELEGATED) {
        for (size_t c = 0; c < 2; ++c) {
            JADE_WALLY_VERIFY(bip32_key_serialize(&group->owner[c], BIP32_FLAG_KEY_PUBLIC, p, BIP32_SERIALIZED_LEN));
            p += BIP32_SERIALIZED_LEN;
        }
    }
    for (size_t c = 0; c < 2; ++c) {
        for (size_t i = 0; i < group->num_signers; ++i) {
            JADE_WALLY_VERIFY(
                bip32_key_serialize(&group->signers[c][i], BIP32_FLAG_KEY_PUBLIC, p, BIP32_SERIALIZED_LEN));
            p += BIP32_SERIALIZED_LEN;
        }
    }
    JADE_ASSERT(p + HMAC_SHA256_LEN == output + output_len);
    return wallet_hmac_with_master_key(output, output_len - HMAC_SHA256_LEN, p, HMAC_SHA256_LEN);
}

bool group_from_bytes(const uint8_t* bytes, const size_t bytes_len, group_data_t* group)
{
    JADE_ASSERT(bytes);
    JADE_ASSERT(group);
    if (bytes_len < 7 + 2 + HMAC_SHA256_LEN || bytes_len > GROUP_RECORD_MAX_LEN) {
        return false;
    }

    // Check the hmac first: a record of another wallet (or a corrupt one) is not used
    uint8_t hmac[HMAC_SHA256_LEN];
    if (!wallet_hmac_with_master_key(bytes, bytes_len - HMAC_SHA256_LEN, hmac, sizeof(hmac))
        || sodium_memcmp(bytes + bytes_len - HMAC_SHA256_LEN, hmac, sizeof(hmac))) {
        JADE_LOGW("Group record HMAC error/mismatch");
        return false;
    }

    const uint8_t* p = bytes;
    const uint8_t* const end = bytes + bytes_len - HMAC_SHA256_LEN;
#define NEED(nbytes)                                                                                                   \
    do {                                                                                                               \
        if ((size_t)(end - p) < (size_t)(nbytes)) {                                                                    \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

    memset(group, 0, sizeof(group_data_t));
    NEED(7);
    if (*p++ != GROUP_RECORD_VERSION) {
        return false;
    }
    group->network_id = (network_t)*p++;
    if (network_to_type(group->network_id) == NETWORK_TYPE_NONE) {
        return false;
    }
    group->type = *p++;
    group->threshold = *p++;
    group->num_signers = *p++;
    group->we_are_owner = (*p++ & GROUP_FLAG_OWNER) != 0;
    const size_t label_len = *p++;
    if (label_len > MAX_GROUP_LABEL_LEN) {
        return false;
    }
    NEED(label_len);
    memcpy(group->label, p, label_len);
    group->label[label_len] = '\0';
    p += label_len;

    const size_t num_leaves = group_num_leaves(group->num_signers, group->threshold);
    if ((group->type != GROUP_TYPE_DELEGATED && group->type != GROUP_TYPE_MULTISIG) || group->num_signers < 2
        || group->num_signers > MAX_GROUP_SIGNERS || !num_leaves || num_leaves > MAX_GROUP_LEAVES
        || (group->we_are_owner && group->type != GROUP_TYPE_DELEGATED)) {
        return false;
    }

    for (size_t c = 0; c < 2; ++c) {
        NEED(1);
        group->chain_path_len[c] = *p++;
        if (!group->chain_path_len[c] || group->chain_path_len[c] >= MAX_PATH_LEN) {
            return false;
        }
        NEED(4 * group->chain_path_len[c]);
        for (size_t i = 0; i < group->chain_path_len[c]; ++i) {
            group_uint32_from_le(p, &group->chain_path[c][i]);
            p += sizeof(uint32_t);
        }
    }
    if (group->type == GROUP_TYPE_DELEGATED) {
        for (size_t c = 0; c < 2; ++c) {
            NEED(BIP32_SERIALIZED_LEN);
            if (bip32_key_unserialize(p, BIP32_SERIALIZED_LEN, &group->owner[c]) != WALLY_OK) {
                return false;
            }
            p += BIP32_SERIALIZED_LEN;
        }
    }
    for (size_t c = 0; c < 2; ++c) {
        for (size_t i = 0; i < group->num_signers; ++i) {
            NEED(BIP32_SERIALIZED_LEN);
            if (bip32_key_unserialize(p, BIP32_SERIALIZED_LEN, &group->signers[c][i]) != WALLY_OK) {
                return false;
            }
            p += BIP32_SERIALIZED_LEN;
        }
    }
#undef NEED
    return p == end;
}

bool group_load_from_storage(const char* name, group_data_t* group, const char** errmsg)
{
    JADE_ASSERT(name);
    JADE_ASSERT(group);
    JADE_INIT_OUT_PPTR(errmsg);

    uint8_t* const bytes = JADE_MALLOC(GROUP_RECORD_MAX_LEN);
    size_t written = 0;
    bool ok = storage_get_group_registration(name, bytes, GROUP_RECORD_MAX_LEN, &written);
    if (!ok) {
        *errmsg = "Failed to load group registration";
    } else if (!group_from_bytes(bytes, written, group)) {
        *errmsg = "Group registration not valid for this wallet";
        ok = false;
    }
    free(bytes);
    return ok;
}
#endif // AMALGAMATED_BUILD
