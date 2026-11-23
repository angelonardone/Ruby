/*
 * What Ruby accepts to sign in a Taproot input (main/utils/psbt.c key_iter_is_supported_taproot() and the MuSig2
 * check of main/musig2.c): the key path of an output that also has scripts (Delegated owner), script-path spends of
 * multi_a leaves (Delegated member, Multi Signature) and of the Time Encrypted Vault bounty leaf, and MuSig2 inputs
 * (BIP373 fields 0x1a, key path or script path). All of it reads host data: the psbt. The real firmware files are
 * compiled here as in the firmware (fw_amalgam.h); the key iterator is set up as key_iter_init() does, without the
 * keychain (the key derivation after this check is not part of it).
 *
 * The first input byte picks the mode:
 *
 * even: RAW. The rest is a psbt, parsed as Ruby does (deserialise_psbt(): STRICT | COMPLETE, and it must serialise
 *       back). Every Taproot input and output goes through the check; for every MuSig2 participants field the
 *       MuSig2 input is also loaded with each participant and each Taproot key as "ours". Checked: memory safety, the
 *       sensitive stack, and on an accepted MuSig2 key path that the coin's key is the aggregate tweaked as BIP341
 *       says (libsecp256k1's MuSig2 tweak against libwally's BIP341 tweak).
 *
 * odd:  STRUCTURED. The harness builds a valid psbt input of one kind (key path with scripts, multi_a leaf, TEV
 *       bounty leaf, MuSig2 key path, MuSig2 leaf) from input-chosen keys, thresholds, dates, tree depth and
 *       merkle paths, then maybe applies ONE input-chosen break (wrong coin, wrong parity, script not committed,
 *       our key missing, k > n, repeated participant, wrong aggregate, non-default sighash, ...). The psbt goes
 *       through serialisation and Ruby's parse; Ruby must accept it exactly when there is no break.
 */
#include "fw_amalgam.h"

#include "../../main/musig2.c"
#include "../../main/utils/psbt.c"

#include "firmware_stubs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint32_t RUBY_PSBT_FLAGS = WALLY_PSBT_PARSE_FLAG_STRICT | WALLY_PSBT_PARSE_FLAG_COMPLETE;

#define SETUP_OK(expr)                                                                                                    \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            fprintf(stderr, "harness setup failed: %s (line %d)\n", #expr, __LINE__);                                  \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

/* ---- Ruby's parse (deserialise_psbt) ---- */

static struct wally_psbt* ruby_parse(const uint8_t* bytes, const size_t len)
{
    struct wally_psbt* psbt = NULL;
    if (wally_psbt_from_bytes(bytes, len, RUBY_PSBT_FLAGS, &psbt) != WALLY_OK || !psbt)
        return NULL;
    size_t out_len = 0;
    if (wally_psbt_get_length(psbt, 0, &out_len) != WALLY_OK || !out_len) {
        wally_psbt_free(psbt); /* finding F2: Ruby refuses what it cannot send back */
        return NULL;
    }
    return psbt;
}

/* key_iter_init() of utils/psbt.c, then its first-iteration Taproot check */
static bool taproot_check(const struct wally_psbt* psbt, const size_t index, const bool is_input)
{
    key_iter iter;
    memset(&iter, 0, sizeof(iter));
    iter.psbt = psbt;
    iter.index = index;
    iter.is_input = is_input;
    iter.is_valid = true;
    const struct wally_map* keypaths
        = is_input ? &psbt->inputs[index].taproot_leaf_paths : &psbt->outputs[index].taproot_leaf_paths;
    if (!keypaths->num_items)
        return false; /* not a Taproot key iterator: not this check */
    iter.is_taproot = true;
    const bool ok = key_iter_is_supported_taproot(&iter, keypaths);
    if (fuzz_sensitive_depth())
        abort();
    return ok;
}

/* ---- RAW mode ---- */

static void check_musig2_load(const struct wally_psbt* psbt, const size_t index, const uint8_t* ours, const size_t len)
{
    musig2_input_t mi;
    const char* errmsg = NULL;
    const bool ok = musig2_input_load(psbt, index, ours, len, &mi, &errmsg);
    if (fuzz_sensitive_depth())
        abort();
    if (!ok) {
        if (!errmsg)
            abort(); /* refused without a reason */
        return;
    }
    if (mi.num_participants < 2 || mi.num_participants > MUSIG2_MAX_PARTICIPANTS || mi.our_index >= mi.num_participants)
        abort();
    const uint8_t* p = mi.participants + mi.our_index * MUSIG2_KEY_LEN;
    if (len == MUSIG2_KEY_LEN ? memcmp(p, ours, len) : memcmp(p + 1, ours, len))
        abort(); /* "our" participant is not our key */
    const struct wally_psbt_input* input = &psbt->inputs[index];
    const struct wally_tx_output* utxo = NULL;
    if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK || !utxo || utxo->script_len != 34)
        abort();
    if (mi.has_leaf) {
        if (mi.leaf_script_len != 34 || mi.leaf_script[0] != 32 || memcmp(mi.leaf_script + 1, mi.agg + 1, 32)
            || mi.leaf_script[33] != OP_CHECKSIG)
            abort(); /* the leaf is not <aggregate> CHECKSIG */
    } else {
        /* key path: the coin's key must be the aggregate tweaked with the merkle root (BIP341), per libwally */
        const struct wally_map_item* merkle = wally_map_get_integer(&input->psbt_fields, PSBT_IN_TAP_MERKLE_ROOT_FIELD);
        uint8_t tweaked[EC_PUBLIC_KEY_LEN];
        if (wally_ec_public_key_bip341_tweak(mi.agg + 1, 32, merkle ? merkle->value : NULL, merkle ? SHA256_LEN : 0, 0,
                tweaked, sizeof(tweaked))
                != WALLY_OK
            || memcmp(tweaked + 1, utxo->script + 2, 32))
            abort(); /* MuSig2 tweak and BIP341 tweak disagree */
    }
}

static void fuzz_raw(const uint8_t* data, const size_t size)
{
    struct wally_psbt* psbt = ruby_parse(data, size);
    if (!psbt)
        return;
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        taproot_check(psbt, i, true);
        const struct wally_psbt_input* input = &psbt->inputs[i];
        if (!musig2_input_present(input))
            continue;
        for (size_t u = 0; u < input->unknowns.num_items; ++u) {
            const struct wally_map_item* it = &input->unknowns.items[u];
            if (!it->key_len || it->key[0] != PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS || !it->value)
                continue;
            for (size_t off = 0; off + MUSIG2_KEY_LEN <= it->value_len && off < 8 * MUSIG2_KEY_LEN;
                 off += MUSIG2_KEY_LEN)
                check_musig2_load(psbt, i, it->value + off, MUSIG2_KEY_LEN);
        }
        for (size_t k = 0; k < input->taproot_leaf_paths.num_items && k < 8; ++k) {
            const struct wally_map_item* it = &input->taproot_leaf_paths.items[k];
            if (it->key && it->key_len == 32)
                check_musig2_load(psbt, i, it->key, 32);
        }
    }
    for (size_t i = 0; i < psbt->num_outputs; ++i)
        taproot_check(psbt, i, false);
    wally_psbt_free(psbt);
}

/* ---- STRUCTURED mode ---- */

#define NUM_TEST_KEYS 20
static uint8_t key_priv[NUM_TEST_KEYS][32];
static uint8_t key_pub[NUM_TEST_KEYS][33];

static void init_keys(void)
{
    static bool done;
    if (done)
        return;
    for (int i = 0; i < NUM_TEST_KEYS; ++i) {
        uint8_t msg[17] = "ruby taproot key";
        msg[16] = (uint8_t)i;
        SETUP_OK(wally_sha256(msg, sizeof(msg), key_priv[i], 32) == WALLY_OK);
        SETUP_OK(wally_ec_public_key_from_private_key(key_priv[i], 32, key_pub[i], 33) == WALLY_OK);
    }
    done = true;
}

typedef struct {
    const uint8_t* p;
    size_t len, pos;
} reader_t;

static uint8_t next_byte(reader_t* r) { return r->pos < r->len ? r->p[r->pos++] : 0; }

static void next_bytes(reader_t* r, uint8_t* out, const size_t n)
{
    for (size_t i = 0; i < n; ++i)
        out[i] = next_byte(r);
}

enum { KIND_KEYPATH_SCRIPTS, KIND_MULTI_A, KIND_BOUNTY, KIND_MUSIG2_KEYPATH, KIND_MUSIG2_LEAF, NUM_KINDS };

/* Breaks: each one makes the input something Ruby must refuse */
enum {
    BREAK_NONE,
    BREAK_UTXO, /* the coin pays to another key */
    BREAK_SECOND_KEY, /* two Taproot keys for the input */
    BREAK_LEAF_HASH_ON_KEYPATH, /* key path with scripts, but our key names a leaf */
    BREAK_PARITY, /* control block with the wrong output-key parity */
    BREAK_LEAF_VERSION, /* leaf version 0xc2 (control block and script) */
    BREAK_NOT_OUR_KEY, /* the leaf / participants do not hold our key */
    BREAK_THRESHOLD, /* multi_a with k > n */
    BREAK_NEGATIVE_DATE, /* bounty leaf with a negative lock time */
    BREAK_REPEATED, /* a MuSig2 participant twice */
    BREAK_WRONG_AGG, /* the participants field names another aggregate key */
    BREAK_SIGHASH, /* SIGHASH_ALL on a MuSig2 input */
    BREAK_SECOND_PARTICIPANTS, /* two participants fields */
    BREAK_ONE_PARTICIPANT, /* MuSig2 of one key */
    BREAK_WRONG_INTERNAL, /* MuSig2 key path whose internal key is not the aggregate */
    NUM_BREAKS
};

static bool break_applies(const int kind, const int brk)
{
    switch (brk) {
    case BREAK_NONE:
    case BREAK_UTXO:
    case BREAK_SECOND_KEY:
        return true;
    case BREAK_LEAF_HASH_ON_KEYPATH:
        return kind == KIND_KEYPATH_SCRIPTS;
    case BREAK_PARITY:
    case BREAK_LEAF_VERSION:
        return kind == KIND_MULTI_A || kind == KIND_BOUNTY || kind == KIND_MUSIG2_LEAF;
    case BREAK_NOT_OUR_KEY:
        return kind != KIND_KEYPATH_SCRIPTS;
    case BREAK_THRESHOLD:
        return kind == KIND_MULTI_A;
    case BREAK_NEGATIVE_DATE:
        return kind == KIND_BOUNTY;
    case BREAK_REPEATED:
    case BREAK_WRONG_AGG:
    case BREAK_SIGHASH:
    case BREAK_SECOND_PARTICIPANTS:
    case BREAK_ONE_PARTICIPANT:
        return kind == KIND_MUSIG2_KEYPATH || kind == KIND_MUSIG2_LEAF;
    case BREAK_WRONG_INTERNAL:
        return kind == KIND_MUSIG2_KEYPATH;
    default:
        return false;
    }
}

static void tagged(const char* tag, const uint8_t* data, const size_t len, uint8_t* out)
{
    SETUP_OK(wally_bip340_tagged_hash(data, len, tag, out, 32) == WALLY_OK);
}

static void leaf_hash_of(const uint8_t version, const uint8_t* script, const size_t len, uint8_t* out)
{
    uint8_t buf[4 + 1200];
    SETUP_OK(len < 0xfd && len + 2 <= sizeof(buf));
    buf[0] = version;
    buf[1] = (uint8_t)len;
    memcpy(buf + 2, script, len);
    tagged("TapLeaf", buf, len + 2, out);
}

/* KeyAgg (BIP327) of compressed keys in the order given; the aggregate compressed into agg33 */
static void key_agg(const uint8_t (*keys)[33], const size_t n, uint8_t* agg33)
{
    const secp256k1_context* ctx = (const secp256k1_context*)wally_get_secp_context();
    secp256k1_pubkey pk[8];
    const secp256k1_pubkey* ptrs[8];
    SETUP_OK(n <= 8);
    for (size_t i = 0; i < n; ++i) {
        SETUP_OK(secp256k1_ec_pubkey_parse(ctx, &pk[i], keys[i], 33));
        ptrs[i] = &pk[i];
    }
    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey xonly;
    secp256k1_pubkey full;
    size_t len = 33;
    SETUP_OK(secp256k1_musig_pubkey_agg(ctx, &xonly, &cache, ptrs, n));
    SETUP_OK(secp256k1_musig_pubkey_get(ctx, &full, &cache));
    SETUP_OK(secp256k1_ec_pubkey_serialize(ctx, agg33, &len, &full, SECP256K1_EC_COMPRESSED));
}

static void fuzz_structured(const uint8_t* data, const size_t size)
{
    init_keys();
    reader_t r = { data, size, 0 };
    const int kind = next_byte(&r) % NUM_KINDS;
    int brk = next_byte(&r) % NUM_BREAKS;
    if (!break_applies(kind, brk))
        brk = BREAK_NONE;
    const size_t ours = next_byte(&r) % 8; /* our key: test key 0..7 */
    const uint8_t* ours_x = key_pub[ours] + 1;
    const uint32_t path[] = { 86 | 0x80000000, 1 | 0x80000000, 0x80000000, 0, (uint32_t)next_byte(&r) };
    const uint8_t fingerprint[4] = { 0x12, 0x34, 0x56, 0x78 };

    /* the leaf script (script kinds) */
    uint8_t script[1100];
    size_t script_len = 0;
    uint8_t leaf_version = brk == BREAK_LEAF_VERSION ? 0xc2 : 0xc0;
    /* MuSig2 participants */
    uint8_t parts[9][33];
    size_t num_parts = 0;
    uint8_t agg33[33];

    if (kind == KIND_MULTI_A) {
        const size_t n = 1 + next_byte(&r) % 6;
        size_t k = 1 + next_byte(&r) % n;
        if (brk == BREAK_THRESHOLD)
            k = n + 1;
        const size_t our_pos = next_byte(&r) % n;
        for (size_t i = 0; i < n; ++i) {
            /* keys 8.. are never ours; our key at our_pos (or not at all) */
            const size_t key = i == our_pos && brk != BREAK_NOT_OUR_KEY ? ours : 8 + i;
            script[script_len++] = 32;
            memcpy(script + script_len, key_pub[key] + 1, 32);
            script_len += 32;
            script[script_len++] = i ? OP_CHECKSIGADD : OP_CHECKSIG;
        }
        if (k <= 16) {
            script[script_len++] = (uint8_t)(OP_1 + k - 1);
        } else {
            script[script_len++] = 1;
            script[script_len++] = (uint8_t)k;
        }
        script[script_len++] = OP_NUMEQUAL;
    } else if (kind == KIND_BOUNTY) {
        const size_t date_len = 1 + next_byte(&r) % 5;
        script[script_len++] = (uint8_t)date_len;
        next_bytes(&r, script + script_len, date_len);
        if (brk == BREAK_NEGATIVE_DATE)
            script[script_len + date_len - 1] |= 0x80;
        else
            script[script_len + date_len - 1] = (uint8_t)((script[script_len + date_len - 1] & 0x7f) | 0x01);
        script_len += date_len;
        script[script_len++] = OP_CHECKLOCKTIMEVERIFY;
        script[script_len++] = OP_DROP;
        script[script_len++] = OP_HASH256;
        script[script_len++] = 32;
        next_bytes(&r, script + script_len, 32);
        script_len += 32;
        script[script_len++] = OP_EQUALVERIFY;
        script[script_len++] = 32;
        memcpy(script + script_len, key_pub[brk == BREAK_NOT_OUR_KEY ? 9 : ours] + 1, 32);
        script_len += 32;
        script[script_len++] = OP_CHECKSIG;
    } else if (kind == KIND_MUSIG2_KEYPATH || kind == KIND_MUSIG2_LEAF) {
        const size_t n = brk == BREAK_ONE_PARTICIPANT ? 1 : 2 + next_byte(&r) % 5;
        const size_t our_pos = next_byte(&r) % n;
        for (size_t i = 0; i < n; ++i) {
            const size_t key = i == our_pos && brk != BREAK_NOT_OUR_KEY ? ours : 8 + i;
            memcpy(parts[num_parts++], key_pub[key], 33);
        }
        if (brk == BREAK_REPEATED)
            memcpy(parts[num_parts++], parts[0], 33);
        key_agg(parts, num_parts, agg33);
        if (kind == KIND_MUSIG2_LEAF) {
            script[script_len++] = 32;
            memcpy(script + script_len, agg33 + 1, 32);
            script_len += 32;
            script[script_len++] = OP_CHECKSIG;
        }
    }

    /* the tree: our leaf with 0..3 input-chosen siblings, internal key test key 19 (or the aggregate / our key) */
    uint8_t leaf_hash[32], node[32], control[1 + 32 + 3 * 32];
    size_t control_len = 0;
    uint8_t merkle_root[32];
    bool has_merkle = false;
    const uint8_t* internal_x = key_pub[19] + 1;
    if (script_len) {
        leaf_hash_of(leaf_version, script, script_len, leaf_hash);
        memcpy(node, leaf_hash, 32);
        const size_t depth = next_byte(&r) % 4;
        control_len = 1 + 32 + depth * 32;
        for (size_t d = 0; d < depth; ++d) {
            uint8_t* sibling = control + 1 + 32 + d * 32;
            next_bytes(&r, sibling, 32);
            uint8_t branch[64];
            if (memcmp(node, sibling, 32) < 0) {
                memcpy(branch, node, 32);
                memcpy(branch + 32, sibling, 32);
            } else {
                memcpy(branch, sibling, 32);
                memcpy(branch + 32, node, 32);
            }
            tagged("TapBranch", branch, 64, node);
        }
        memcpy(merkle_root, node, 32);
        has_merkle = true;
    } else if (kind == KIND_KEYPATH_SCRIPTS) {
        next_bytes(&r, merkle_root, 32);
        has_merkle = true;
        internal_x = ours_x;
    } else { /* MuSig2 key path: merkle root optional */
        has_merkle = next_byte(&r) & 1;
        if (has_merkle)
            next_bytes(&r, merkle_root, 32);
    }
    if (kind == KIND_MUSIG2_KEYPATH)
        internal_x = agg33 + 1;

    /* the coin: P2TR of the internal key tweaked with the merkle root */
    uint8_t output_key[33];
    SETUP_OK(wally_ec_public_key_bip341_tweak(
              internal_x, 32, has_merkle ? merkle_root : NULL, has_merkle ? 32 : 0, 0, output_key, 33)
        == WALLY_OK);
    uint8_t spk[34] = { OP_1, 32 };
    memcpy(spk + 2, output_key + 1, 32);
    if (brk == BREAK_UTXO)
        spk[2 + next_byte(&r) % 32] ^= (uint8_t)(1 + next_byte(&r) % 255);
    if (script_len) {
        const bool odd = output_key[0] == 0x03;
        control[0] = (uint8_t)(leaf_version | ((odd ^ (brk == BREAK_PARITY)) ? 1 : 0));
        memcpy(control + 1, internal_x, 32);
    }

    /* the psbt: one input spending that coin, one output */
    struct wally_tx* tx = NULL;
    struct wally_psbt* psbt = NULL;
    struct wally_tx_output* utxo = NULL;
    uint8_t txid[32];
    next_bytes(&r, txid, 32);
    SETUP_OK(wally_tx_init_alloc(2, 0, 1, 1, &tx) == WALLY_OK);
    SETUP_OK(wally_tx_add_raw_input(tx, txid, 32, 0, 0xfffffffd, NULL, 0, NULL, 0) == WALLY_OK);
    SETUP_OK(wally_tx_add_raw_output(tx, 90000, spk, sizeof(spk), 0) == WALLY_OK);
    SETUP_OK(wally_psbt_init_alloc(0, 1, 1, 0, 0, &psbt) == WALLY_OK);
    SETUP_OK(wally_psbt_set_global_tx(psbt, tx) == WALLY_OK);
    SETUP_OK(wally_tx_output_init_alloc(100000, spk, sizeof(spk), &utxo) == WALLY_OK);
    struct wally_psbt_input* in = &psbt->inputs[0];
    SETUP_OK(wally_psbt_input_set_witness_utxo(in, utxo) == WALLY_OK);

    /* our key, naming our leaf (script kinds) */
    const bool names_leaf = script_len || brk == BREAK_LEAF_HASH_ON_KEYPATH;
    uint8_t named[32];
    memcpy(named, script_len ? leaf_hash : merkle_root, 32);
    SETUP_OK(wally_psbt_input_taproot_keypath_add(in, ours_x, 32, names_leaf ? named : NULL, names_leaf ? 32 : 0,
              fingerprint, 4, path, 5)
        == WALLY_OK);
    if (brk == BREAK_SECOND_KEY)
        SETUP_OK(wally_psbt_input_taproot_keypath_add(in, key_pub[(ours + 1) % 8] + 1, 32, NULL, 0, fingerprint, 4, path, 5)
            == WALLY_OK);
    if (script_len) {
        uint8_t value[1101];
        memcpy(value, script, script_len);
        value[script_len] = leaf_version;
        SETUP_OK(wally_map_add(&in->taproot_leaf_scripts, control, control_len, value, script_len + 1) == WALLY_OK);
    }
    if (has_merkle && (kind == KIND_KEYPATH_SCRIPTS || kind == KIND_MUSIG2_KEYPATH))
        SETUP_OK(wally_map_add_integer(&in->psbt_fields, PSBT_IN_TAP_MERKLE_ROOT_FIELD, merkle_root, 32) == WALLY_OK);
    if (kind == KIND_MUSIG2_KEYPATH)
        SETUP_OK(wally_psbt_input_set_taproot_internal_key(in, brk == BREAK_WRONG_INTERNAL ? key_pub[18] + 1 : agg33 + 1, 32)
            == WALLY_OK);
    if (num_parts) {
        uint8_t key[34] = { PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS };
        memcpy(key + 1, brk == BREAK_WRONG_AGG ? key_pub[17] : agg33, 33);
        SETUP_OK(wally_map_add(&in->unknowns, key, sizeof(key), &parts[0][0], num_parts * 33) == WALLY_OK);
        if (brk == BREAK_SECOND_PARTICIPANTS) {
            key[1] ^= 1; /* 02 <-> 03: another (valid-looking) aggregate */
            SETUP_OK(wally_map_add(&in->unknowns, key, sizeof(key), &parts[0][0], num_parts * 33) == WALLY_OK);
        }
        if (brk == BREAK_SIGHASH)
            SETUP_OK(wally_psbt_input_set_sighash(in, WALLY_SIGHASH_ALL) == WALLY_OK);
    }

    /* as Ruby receives it */
    size_t len = 0, written = 0;
    SETUP_OK(wally_psbt_get_length(psbt, 0, &len) == WALLY_OK);
    uint8_t* bytes = malloc(len);
    SETUP_OK(bytes && wally_psbt_to_bytes(psbt, 0, bytes, len, &written) == WALLY_OK && written == len);
    struct wally_psbt* parsed = ruby_parse(bytes, len);
    SETUP_OK(parsed); /* libwally refuses the test psbt: a harness bug */

    const bool ok = taproot_check(parsed, 0, true);
    if (ok != (brk == BREAK_NONE)) {
        fprintf(stderr, "kind %d break %d: Ruby %s it\n", kind, brk, ok ? "ACCEPTED" : "refused");
        abort();
    }
    if (getenv("FUZZ_TRACE"))
        fprintf(stderr, "kind %d break %d: %s as expected\n", kind, brk, ok ? "accepted" : "refused");

    wally_psbt_free(parsed);
    free(bytes);
    wally_tx_output_free(utxo);
    wally_psbt_free(psbt);
    wally_tx_free(tx);
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
