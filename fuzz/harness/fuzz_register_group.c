/*
 * RPC 'register_group' (main/process/register_group.c group_rpc_parse()) and the group code it feeds (main/group.c:
 * the group's addresses, the record kept in storage). The host sends the whole group: type, threshold, owner and
 * signers' xpubs, this Ruby's chain paths. The real firmware files are compiled as in the firmware (fw_amalgam.h);
 * "this Ruby" is a test wallet (keychain_get, and wallet_get_hdkey / wallet_hmac_with_master_key /
 * storage_key_name_valid copied from the firmware below). Network: testnet.
 *
 * The first input byte picks the mode:
 *
 * even: RAW. The rest is a whole RPC request (CBOR), filtered as Ruby does (fw_rpc.h), its params to
 *       group_rpc_parse(). Checked: memory safety, the sensitive stack, and on acceptance check_group() below.
 *
 * odd:  STRUCTURED. The harness builds a valid request (type, n signers, k, this Ruby as owner or as one signer,
 *       paths) from the input, then maybe applies ONE input-chosen break (bad group_name or label, unknown type,
 *       k out of range, missing / unexpected owner, one signer, repeated signer, owner also signer, mainnet xpub,
 *       garbage xpub, this Ruby not in the group, too many combinations, missing path). Ruby must accept it exactly
 *       when there is no break, and an accepted group must pass check_group().
 *
 * check_group(): k / n / type in range; signers sorted as the library sorts them; the owner flag true only when this
 * Ruby is the owner; the label printable; for groups of at most LEAF_CAP leaves (address cost grows with the leaves),
 * on both chains, for index 0 and an input-chosen index: group_get_script() gives a P2TR script, twice the same,
 * group_get_address() works, and the address path maps back to its chain and index; the storage record
 * round-trips (group_to_bytes / group_from_bytes, same fields, same bytes) and any changed byte is refused.
 */
#include "fw_amalgam.h"

#include "../../main/utils/network.c"
#include "../../main/group.c"
#include "../../main/process/register_group.c"

#include "firmware_stubs.h"
#include "fw_rpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LEAF_CAP 256
#define NUM_PARTICIPANTS 16

#define SETUP_OK(expr)                                                                                                 \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            fprintf(stderr, "harness setup failed: %s (line %d)\n", #expr, __LINE__);                                  \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

/* ---- "this Ruby": a test wallet, and the firmware functions that use it ---- */

static keychain_t test_keychain;

const keychain_t* keychain_get(void) { return &test_keychain; }

/* wallet.c */
bool wallet_get_hdkey(const uint32_t* path, const size_t path_len, const uint32_t flags, struct ext_key* output)
{
    JADE_ASSERT(path_len == 0 || path);
    if (!output) {
        return false;
    }
    if (path_len == 0) {
        memcpy(output, &keychain_get()->xpriv, sizeof(struct ext_key));
        if (flags & BIP32_FLAG_KEY_PUBLIC) {
            JADE_WALLY_VERIFY(bip32_key_strip_private_key(output));
        }
        return true;
    }
    return bip32_key_from_parent_path(&keychain_get()->xpriv, path, path_len, flags, output) == WALLY_OK;
}

/* wallet.c */
bool wallet_hmac_with_master_key(const uint8_t* data, const size_t data_len, uint8_t* output, const size_t output_len)
{
    if (!data || data_len == 0 || !output || output_len != HMAC_SHA256_LEN) {
        return false;
    }
    return wally_hmac_sha256(keychain_get()->xpriv.priv_key + 1, sizeof(keychain_get()->xpriv.priv_key) - 1, data,
               data_len, output, output_len)
        == WALLY_OK;
}

/* storage.c */
bool storage_key_name_valid(const char* name)
{
    const char* pch = name;
    while (*pch != '\0') {
        if ((pch - name) >= NVS_KEY_NAME_MAX_SIZE) {
            return false;
        }
        const unsigned char c = *pch;
        if (!isgraph(c)) {
            return false;
        }
        ++pch;
    }
    return pch > name;
}

/* ---- test participants: master j from seed "ruby group participant" | j; chain c at m/86'/1'/0'/(2+c) ---- */

static struct ext_key participant_chain[NUM_PARTICIPANTS][2];
static char participant_xpub[NUM_PARTICIPANTS][2][120];
static char participant_xpub_main[2][120]; /* participant 0's chains with the mainnet version */
static const uint32_t OUR_PATH[2][4] = { { 0x80000056, 0x80000001, 0x80000007, 2 }, { 0x80000056, 0x80000001, 0x80000007, 3 } };
static char our_xpub[2][120];

static void init_wallets(void)
{
    static bool done;
    if (done)
        return;
    uint8_t seed[64];
    memset(seed, 0x52, sizeof(seed)); /* 'R' */
    SETUP_OK(bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_TEST_PRIVATE, 0, &test_keychain.xpriv) == WALLY_OK);
    for (int j = 0; j < NUM_PARTICIPANTS; ++j) {
        uint8_t msg[23] = "ruby group participant";
        msg[22] = (uint8_t)j;
        SETUP_OK(wally_sha512(msg, sizeof(msg), seed, sizeof(seed)) == WALLY_OK);
        struct ext_key master;
        SETUP_OK(bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_TEST_PRIVATE, 0, &master) == WALLY_OK);
        for (int c = 0; c < 2; ++c) {
            const uint32_t path[4] = { 0x80000056, 0x80000001, 0x80000000, (uint32_t)(2 + c) };
            SETUP_OK(bip32_key_from_parent_path(&master, path, 4, BIP32_FLAG_KEY_PUBLIC, &participant_chain[j][c])
                == WALLY_OK);
            char* s = NULL;
            SETUP_OK(bip32_key_to_base58(&participant_chain[j][c], BIP32_FLAG_KEY_PUBLIC, &s) == WALLY_OK);
            strcpy(participant_xpub[j][c], s);
            wally_free_string(s);
            if (j == 0) {
                struct ext_key main_key = participant_chain[j][c];
                main_key.version = BIP32_VER_MAIN_PUBLIC;
                SETUP_OK(bip32_key_to_base58(&main_key, BIP32_FLAG_KEY_PUBLIC, &s) == WALLY_OK);
                strcpy(participant_xpub_main[c], s);
                wally_free_string(s);
            }
        }
    }
    for (int c = 0; c < 2; ++c) {
        struct ext_key ours;
        char* s = NULL;
        SETUP_OK(wallet_get_hdkey(OUR_PATH[c], 4, BIP32_FLAG_KEY_PUBLIC, &ours));
        SETUP_OK(bip32_key_to_base58(&ours, BIP32_FLAG_KEY_PUBLIC, &s) == WALLY_OK);
        strcpy(our_xpub[c], s);
        wally_free_string(s);
    }
    done = true;
}

/* ---- input reader ---- */

typedef struct {
    const uint8_t* p;
    size_t len, pos;
} reader_t;

static uint8_t next_byte(reader_t* r) { return r->pos < r->len ? r->p[r->pos++] : 0; }

/* ---- parse, as register_group_process() ---- */

static bool parse(const CborValue* params, char* group_name, group_data_t* group)
{
    const char* errmsg = NULL;
    memset(group, 0, sizeof(*group)); /* JADE_CALLOC in the process */
    const bool ok = group_rpc_parse(params, NETWORK_BITCOIN_TESTNET, group_name, group, &errmsg);
    if (fuzz_sensitive_depth())
        abort();
    if (!ok && !errmsg)
        abort();
    return ok;
}

static void same_group(const group_data_t* a, const group_data_t* b)
{
    if (a->network_id != b->network_id || a->type != b->type || a->threshold != b->threshold
        || a->num_signers != b->num_signers || a->we_are_owner != b->we_are_owner || strcmp(a->label, b->label))
        abort();
    for (int c = 0; c < 2; ++c) {
        if (a->chain_path_len[c] != b->chain_path_len[c]
            || memcmp(a->chain_path[c], b->chain_path[c], a->chain_path_len[c] * sizeof(uint32_t)))
            abort();
        if (group_type_has_owner(a->type)
            && (memcmp(a->owner[c].pub_key, b->owner[c].pub_key, 33)
                || memcmp(a->owner[c].chain_code, b->owner[c].chain_code, 32)))
            abort();
        for (size_t i = 0; i < a->num_signers; ++i)
            if (memcmp(a->signers[c][i].pub_key, b->signers[c][i].pub_key, 33)
                || memcmp(a->signers[c][i].chain_code, b->signers[c][i].chain_code, 32))
                abort();
    }
}

static void check_group(const group_data_t* g, reader_t* r)
{
    if (g->type < GROUP_TYPE_DELEGATED || g->type > GROUP_TYPE_MUSIG2_MULTISIG)
        abort();
    if (!g->threshold || g->threshold > MAX_GROUP_SIGNERS || (group_type_is_musig2(g->type) && g->threshold < 2))
        abort();
    if (g->num_signers < 2 || g->num_signers > MAX_GROUP_SIGNERS)
        abort();
    const size_t num_leaves = group_num_leaves(g->num_signers, g->threshold);
    if (!num_leaves || num_leaves > MAX_GROUP_LEAVES)
        abort();
    const size_t label_len = strnlen(g->label, sizeof(g->label));
    if (!label_len || label_len > MAX_GROUP_LABEL_LEN)
        abort();
    for (size_t i = 0; i < label_len; ++i)
        if (g->label[i] < 0x20 || g->label[i] > 0x7e)
            abort();
    for (int c = 0; c < 2; ++c) {
        struct ext_key ours;
        SETUP_OK(wallet_get_hdkey(g->chain_path[c], g->chain_path_len[c], BIP32_FLAG_KEY_PUBLIC, &ours));
        if (g->we_are_owner
            && (!group_type_has_owner(g->type) || memcmp(g->owner[c].pub_key, ours.pub_key, 33)
                || memcmp(g->owner[c].chain_code, ours.chain_code, 32)))
            abort(); /* "owner" but this Ruby is not the owner */
        for (size_t i = 1; i < g->num_signers; ++i)
            if (compare_serialized_xpubs(&g->signers[c][i - 1], &g->signers[c][i]) >= 0)
                abort(); /* not sorted (or a repeated signer) */
    }

    if (num_leaves <= LEAF_CAP) {
        const uint32_t indexes[2] = { 0, (((uint32_t)next_byte(r) << 8) | next_byte(r)) };
        for (uint8_t c = 0; c < 2; ++c) {
            for (int n = 0; n < 2; ++n) {
                uint8_t script[34], again[34];
                if (!group_get_script(g, c, indexes[n], script, sizeof(script)) || script[0] != OP_1 || script[1] != 32)
                    abort(); /* no P2TR script for a registered group */
                if (!group_get_script(g, c, indexes[n], again, sizeof(again)) || memcmp(script, again, sizeof(script)))
                    abort(); /* not deterministic */
                char* address = NULL;
                if (!group_get_address(g, NETWORK_BITCOIN_TESTNET, c, indexes[n], &address) || !address)
                    abort();
                wally_free_string(address);
                uint32_t path[MAX_PATH_LEN];
                memcpy(path, g->chain_path[c], g->chain_path_len[c] * sizeof(uint32_t));
                path[g->chain_path_len[c]] = indexes[n];
                uint8_t chain = 9;
                uint32_t index = 0;
                if (!group_path_to_chain_index(g, path, g->chain_path_len[c] + 1, &chain, &index) || chain != c
                    || index != indexes[n])
                    abort(); /* the address path does not map back */
            }
        }
        if (fuzz_sensitive_depth())
            abort();
    }

    /* the storage record */
    const size_t len = group_record_len(g);
    uint8_t* record = malloc(len);
    uint8_t* record2 = malloc(len);
    SETUP_OK(record && record2);
    if (!group_to_bytes(g, record, len))
        abort();
    group_data_t* back = calloc(1, sizeof(group_data_t));
    SETUP_OK(back);
    if (!group_from_bytes(record, len, back))
        abort(); /* Ruby cannot read back the record it wrote */
    same_group(g, back);
    if (!group_to_bytes(back, record2, len) || memcmp(record, record2, len))
        abort();
    const size_t pos = (((size_t)next_byte(r) << 8) | next_byte(r)) % len;
    record[pos] ^= (uint8_t)(1 + next_byte(r) % 255);
    if (group_from_bytes(record, len, back))
        abort(); /* a changed record was accepted */
    free(back);
    free(record2);
    free(record);
}

/* ---- RAW mode ---- */

static void fuzz_raw(const uint8_t* data, const size_t size)
{
    init_wallets();
    CborParser parser;
    CborValue message, params;
    if (!fuzz_rpc_params(data, size, &parser, &message, &params))
        return;
    char group_name[NVS_KEY_NAME_MAX_SIZE];
    group_data_t* group = calloc(1, sizeof(group_data_t));
    SETUP_OK(group);
    if (parse(&params, group_name, group)) {
        reader_t r = { data, size, size > 8 ? size - 8 : 0 };
        check_group(group, &r);
    }
    free(group);
}

/* ---- STRUCTURED mode ---- */

enum {
    BREAK_NONE,
    BREAK_NAME_SPACE,
    BREAK_NAME_LONG,
    BREAK_LABEL_NONPRINT,
    BREAK_LABEL_LONG,
    BREAK_TYPE,
    BREAK_K_ZERO,
    BREAK_K_BIG,
    BREAK_MUSIG_K1,
    BREAK_OWNER_MISSING,
    BREAK_OWNER_ON_MULTISIG,
    BREAK_ONE_SIGNER,
    BREAK_REPEATED_SIGNER,
    BREAK_OWNER_IS_SIGNER,
    BREAK_MAINNET_XPUB,
    BREAK_GARBAGE_XPUB,
    BREAK_NOT_PARTICIPANT,
    BREAK_TOO_MANY_COMBINATIONS,
    BREAK_PATH_MISSING,
    NUM_BREAKS
};

static const char* const TYPES[4] = { "delegated", "multisig", "musig2-delegated", "musig2-multisig" };

static void encode_path(CborEncoder* map, const char* field, const uint32_t* path, const size_t len)
{
    CborEncoder array;
    cbor_encode_text_stringz(map, field);
    cbor_encoder_create_array(map, &array, len);
    for (size_t i = 0; i < len; ++i)
        cbor_encode_uint(&array, path[i]);
    cbor_encoder_close_container(map, &array);
}

static void encode_chains(CborEncoder* enc, const char* receiving, const char* change)
{
    CborEncoder m;
    cbor_encoder_create_map(enc, &m, 2);
    cbor_encode_text_stringz(&m, "receiving");
    cbor_encode_text_stringz(&m, receiving);
    cbor_encode_text_stringz(&m, "change");
    cbor_encode_text_stringz(&m, change);
    cbor_encoder_close_container(enc, &m);
}

static void fuzz_structured(const uint8_t* data, const size_t size)
{
    static uint8_t msg[16384];
    init_wallets();
    reader_t r = { data, size, 0 };

    const int type = next_byte(&r) % 4;
    const bool has_owner = type == 0 || type == 2;
    const bool musig2 = type >= 2;
    int brk = next_byte(&r) % NUM_BREAKS;
    if ((brk == BREAK_MUSIG_K1 && !musig2) || (brk == BREAK_OWNER_MISSING && !has_owner)
        || ((brk == BREAK_OWNER_ON_MULTISIG) && has_owner) || (brk == BREAK_OWNER_IS_SIGNER && !has_owner))
        brk = BREAK_NONE;
    size_t n = 2 + next_byte(&r) % 5; /* 2..6 signers */
    size_t k = (musig2 ? 2 : 1) + next_byte(&r) % (n - (musig2 ? 1 : 0));
    if (brk == BREAK_ONE_SIGNER) {
        n = 1;
        k = 1;
    } else if (brk == BREAK_TOO_MANY_COMBINATIONS) {
        n = 15;
        k = 7; /* C(15,7) = 6435 > 2000 */
    } else if (brk == BREAK_K_ZERO) {
        k = 0;
    } else if (brk == BREAK_K_BIG) {
        k = 16;
    } else if (brk == BREAK_MUSIG_K1) {
        k = 1;
    }
    /* this Ruby: the owner (types with an owner, when the input says so) or signer number our_pos */
    const bool we_own = has_owner && brk != BREAK_NOT_PARTICIPANT && (next_byte(&r) & 1);
    const size_t our_pos = next_byte(&r) % n;

    CborEncoder root, map, params, signers;
    cbor_encoder_init(&root, msg, sizeof(msg), 0);
    cbor_encoder_create_map(&root, &map, 3);
    cbor_encode_text_stringz(&map, "id");
    cbor_encode_text_stringz(&map, "1");
    cbor_encode_text_stringz(&map, "method");
    cbor_encode_text_stringz(&map, "register_group");
    cbor_encode_text_stringz(&map, "params");
    const bool with_owner = (has_owner && brk != BREAK_OWNER_MISSING) || brk == BREAK_OWNER_ON_MULTISIG;
    cbor_encoder_create_map(&map, &params, 7 + (with_owner ? 1 : 0) + (brk != BREAK_PATH_MISSING ? 1 : 0));

    cbor_encode_text_stringz(&params, "network");
    cbor_encode_text_stringz(&params, "testnet");
    cbor_encode_text_stringz(&params, "group_name");
    cbor_encode_text_stringz(&params,
        brk == BREAK_NAME_SPACE      ? "my group"
            : brk == BREAK_NAME_LONG ? "group0123456789x"
                                     : "group1");
    cbor_encode_text_stringz(&params, "label");
    cbor_encode_text_stringz(&params,
        brk == BREAK_LABEL_NONPRINT  ? "Family\tsavings"
            : brk == BREAK_LABEL_LONG ? "A label that is longer than forty letters"
                                      : "Family savings");
    cbor_encode_text_stringz(&params, "type");
    cbor_encode_text_stringz(&params, brk == BREAK_TYPE ? "musig" : TYPES[type]);
    cbor_encode_text_stringz(&params, "threshold");
    cbor_encode_uint(&params, k);

    /* participant numbers: the owner is participant 15 (unless it is this Ruby), signers 1..n */
    if (with_owner) {
        cbor_encode_text_stringz(&params, "owner");
        if (we_own)
            encode_chains(&params, our_xpub[0], our_xpub[1]);
        else
            encode_chains(&params, participant_xpub[15][0], participant_xpub[15][1]);
    }
    cbor_encode_text_stringz(&params, "signers");
    cbor_encoder_create_array(&params, &signers, n);
    for (size_t i = 0; i < n; ++i) {
        const bool is_us = !we_own && i == our_pos && brk != BREAK_NOT_PARTICIPANT;
        const char *rec = participant_xpub[1 + i][0], *chg = participant_xpub[1 + i][1];
        if (is_us) {
            rec = our_xpub[0];
            chg = our_xpub[1];
        } else if (brk == BREAK_REPEATED_SIGNER && i == (our_pos + 1) % n) {
            const size_t other = (our_pos + 2) % n; /* the same participant as signer 'other' */
            const bool other_is_us = !we_own && other == our_pos;
            rec = other_is_us ? our_xpub[0] : participant_xpub[1 + other][0];
            chg = other_is_us ? our_xpub[1] : participant_xpub[1 + other][1];
        } else if (brk == BREAK_OWNER_IS_SIGNER && i == (our_pos + 1) % n) {
            rec = we_own ? our_xpub[0] : participant_xpub[15][0];
            chg = we_own ? our_xpub[1] : participant_xpub[15][1];
        } else if (brk == BREAK_MAINNET_XPUB && i == (our_pos + 1) % n) {
            rec = participant_xpub_main[0];
            chg = participant_xpub_main[1];
        } else if (brk == BREAK_GARBAGE_XPUB && i == (our_pos + 1) % n) {
            rec = "tpubNotAnXpub";
        }
        encode_chains(&signers, rec, chg);
    }
    cbor_encoder_close_container(&params, &signers);
    encode_path(&params, "receiving_path", OUR_PATH[0], 4);
    if (brk != BREAK_PATH_MISSING)
        encode_path(&params, "change_path", OUR_PATH[1], 4);
    cbor_encoder_close_container(&map, &params);
    if (cbor_encoder_close_container(&root, &map) != CborNoError)
        abort(); /* the test request does not fit */
    const size_t msg_len = cbor_encoder_get_buffer_size(&root, msg);

    CborParser parser;
    CborValue message, p;
    SETUP_OK(fuzz_rpc_params(msg, msg_len, &parser, &message, &p));
    char group_name[NVS_KEY_NAME_MAX_SIZE];
    group_data_t* group = calloc(1, sizeof(group_data_t));
    SETUP_OK(group);
    const bool ok = parse(&p, group_name, group);
    if (ok != (brk == BREAK_NONE)) {
        fprintf(stderr, "type %d break %d: Ruby %s it\n", type, brk, ok ? "ACCEPTED" : "refused");
        abort();
    }
    if (ok) {
        if (group->we_are_owner != we_own || group->num_signers != n || group->threshold != k
            || group->type != type + 1)
            abort();
        check_group(group, &r);
    }
    if (getenv("FUZZ_TRACE"))
        fprintf(stderr, "type %d n %zu k %zu owner %d break %d: %s as expected\n", type, n, k, we_own, brk,
            ok ? "accepted" : "refused");
    free(group);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!size)
        return 0;
    if (data[0] & 1)
        fuzz_structured(data + 1, size - 1);
    else
        fuzz_raw(data + 1, size - 1);
    return 0;
}
