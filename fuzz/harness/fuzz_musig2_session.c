/*
 * MuSig2 signing sessions (main/musig2.c, BIP327, RUBY-GROUPS.md 2.4): round 1 (musig2_create_nonces, the RPC
 * 'musig2_nonces') and round 2 (musig2_sign_input, called by sign_psbt for every MuSig2 input after the user
 * accepted) in input-chosen sequences. "This Ruby" is a test wallet (keychain_get below); the other participants
 * are the harness's cosigners, which make real nonces and partial signatures with libsecp256k1. The real firmware
 * files are compiled as in the firmware (fw_amalgam.h); the clock is the harness's (fuzz_ticks_*), and may start
 * just before the 32-bit tick count wraps.
 *
 * The input picks a payment (1-4 inputs: MuSig2 key path, MuSig2 leaf, a MuSig2 input of other wallets, a plain
 * Taproot input of ours; 2-5 participants, our position, our key, merkle root / tree, amounts, outputs) and then up
 * to 16 operations:
 *   NONCES      round 1 on the payment, or on a variant of it (another output amount, another amount of a coin
 *               spent, lock time, sequence, an extra field, one input less, one output more);
 *   SIGN        round 2 of one input on a variant, with every participant's public nonce, maybe ONE tamper (our
 *               nonce swapped or missing, a cosigner's nonce missing / of the wrong length / not a point / a copy
 *               of ours / chosen so the aggregate nonce is the point at infinity);
 *   SIGN_PSBT   round 2 of every MuSig2 input as sign_psbt does (stops at the first failure), then musig2_clear();
 *   FLOW        NONCES then SIGN_PSBT;
 *   SIGN_BYTES  round 2 of one input on a correct round-2 psbt with 1-4 changed bytes (parsed as Ruby does);
 *   CLEAR       musig2_clear() (a payment declined, the wallet locked);
 *   TIME        the clock moves (to just inside / just outside the lifetime of the nonces, or less).
 *
 * The harness keeps its own model of what Ruby holds, and checks after every operation:
 *   - Ruby succeeds exactly when the model says so: round 1 when the payment has no plain input of ours and at
 *     least one MuSig2 input of ours; round 2 when Ruby holds an unused nonce of this input from a round 1 that
 *     is not cleared, replaced or expired, for the same number of inputs and the same BIP341 message, and the
 *     psbt carries every participant's nonce with ours unchanged;
 *   - A SECRET NONCE NEVER SIGNS TWICE (two partial signatures with one nonce reveal the private key), and once
 *     round 2 of an input ran (whatever its result) Ruby's copy of that nonce is all zeroes; musig2_clear() and a
 *     failed round 1 leave no nonce at all;
 *   - round 1: one nonce per MuSig2 input of ours and none for any other input, every nonce new, and the message
 *     Ruby keeps is the input's BIP341 sighash (computed here with libwally's own API);
 *   - round 2: Ruby adds exactly one field, its partial signature, which verifies (BIP327 PartialSigVerify) with
 *     the nonces in the psbt; with honest cosigners the aggregate of all partial signatures is a valid BIP340
 *     signature for the coin's key (key path: the aggregate tweaked with the merkle root; leaf: the aggregate);
 *     the psbt still serialises and parses as Ruby does (it is sent back);
 *   - SIGN_BYTES: whatever Ruby signs is the message of round 1, with the nonce of round 1, and verifies;
 *   - memory safety, and the sensitive stack is empty after every call.
 */
#include "fw_amalgam.h"

#include "../../main/musig2.c"
#include "../../main/utils/psbt.c"

#include "firmware_stubs.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IN 4
#define MAX_OUT 3
#define MAX_PARTS 5
#define NUM_COSIGNERS 8
#define MAX_OPS 16
#define NONCE_LEN MUSIG2_PUBNONCE_LEN
#define LIFETIME ((uint32_t)pdMS_TO_TICKS(MUSIG2_NONCES_LIFETIME_MS))

static const uint32_t RUBY_PSBT_FLAGS = WALLY_PSBT_PARSE_FLAG_STRICT | WALLY_PSBT_PARSE_FLAG_COMPLETE;

#define SETUP_OK(expr)                                                                                                 \
    do {                                                                                                               \
        if (!(expr)) {                                                                                                 \
            fprintf(stderr, "harness setup failed: %s (line %d)\n", #expr, __LINE__);                                  \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

static bool tracing;

static void trace(const char* fmt, ...)
{
    if (!tracing)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

__attribute__((noreturn)) static void fail(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "MUSIG2 SESSION CHECK FAILED: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    abort();
}

static void check_sensitive(const char* where)
{
    if (fuzz_sensitive_depth())
        fail("%s left %u item(s) on the sensitive stack", where, (unsigned)fuzz_sensitive_depth());
}

static const secp256k1_context* sctx(void) { return (const secp256k1_context*)wally_get_secp_context(); }

/* ---- "this Ruby" (test wallet) and the cosigners ---- */

static keychain_t test_keychain;

const keychain_t* keychain_get(void) { return &test_keychain; }

static uint8_t our_fingerprint[4];
static const uint8_t OTHER_FINGERPRINT[4] = { 0xde, 0xad, 0xbe, 0xef };
static uint8_t cos_priv[NUM_COSIGNERS][32];
static uint8_t cos_pub[NUM_COSIGNERS][33];
static uint8_t nums_x[32]; /* internal key of the leaf trees */
static uint8_t pay_spk[34]; /* where the payment goes */
static struct ext_key our_key_cache[256];
static bool our_key_cached[256];

static void init_keys(void)
{
    static bool done;
    if (done)
        return;
    uint8_t seed[64];
    memset(seed, 0x4d, sizeof(seed)); /* 'M' */
    SETUP_OK(bip32_key_from_seed(seed, sizeof(seed), BIP32_VER_TEST_PRIVATE, 0, &test_keychain.xpriv) == WALLY_OK);
    SETUP_OK(bip32_key_get_fingerprint(&test_keychain.xpriv, our_fingerprint, 4) == WALLY_OK);
    for (int i = 0; i < NUM_COSIGNERS; ++i) {
        uint8_t msg[21] = "ruby musig2 cosigner";
        msg[20] = (uint8_t)i;
        SETUP_OK(wally_sha256(msg, sizeof(msg), cos_priv[i], 32) == WALLY_OK);
        SETUP_OK(wally_ec_public_key_from_private_key(cos_priv[i], 32, cos_pub[i], 33) == WALLY_OK);
    }
    uint8_t priv[32], pub[33];
    SETUP_OK(wally_sha256((const uint8_t*)"ruby musig2 internal", 20, priv, 32) == WALLY_OK);
    SETUP_OK(wally_ec_public_key_from_private_key(priv, 32, pub, 33) == WALLY_OK);
    memcpy(nums_x, pub + 1, 32);
    SETUP_OK(wally_sha256((const uint8_t*)"ruby musig2 payee", 17, priv, 32) == WALLY_OK);
    SETUP_OK(wally_ec_public_key_from_private_key(priv, 32, pub, 33) == WALLY_OK);
    pay_spk[0] = OP_1;
    pay_spk[1] = 32;
    memcpy(pay_spk + 2, pub + 1, 32);
    done = true;
}

static const uint32_t OUR_PATH_PREFIX[4] = { 0x80000056, 0x80000001, 0x80000000, 0 };

static const struct ext_key* our_key(const uint8_t child)
{
    if (!our_key_cached[child]) {
        uint32_t path[5] = { OUR_PATH_PREFIX[0], OUR_PATH_PREFIX[1], OUR_PATH_PREFIX[2], OUR_PATH_PREFIX[3], child };
        SETUP_OK(bip32_key_from_parent_path(&test_keychain.xpriv, path, 5, BIP32_FLAG_KEY_PRIVATE, &our_key_cache[child])
            == WALLY_OK);
        our_key_cached[child] = true;
    }
    return &our_key_cache[child];
}

/* the harness's randomness (cosigners' nonces, SIGN_BYTES): independent of get_random() */
static uint64_t h_state;

static uint64_t h_next(void)
{
    uint64_t z = (h_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void h_random(uint8_t* out, const size_t len)
{
    for (size_t i = 0; i < len; i += 8) {
        const uint64_t r = h_next();
        for (size_t b = 0; b < 8 && i + b < len; ++b)
            out[i + b] = (uint8_t)(r >> (8 * b));
    }
}

/* ---- the payment ---- */

enum { K_KEYPATH, K_LEAF, K_NOT_OURS, K_PLAIN_OURS };
static const char* const KIND_NAME[] = { "keypath", "leaf", "not-ours", "plain-ours" };

typedef struct {
    int kind;
    size_t n, our_pos;
    size_t cosigner[MAX_PARTS]; /* cosigner of each position (ours excepted) */
    uint8_t child;
    bool has_merkle;
    uint8_t merkle_seed;
    size_t depth;
    uint8_t depth_seed;
    uint64_t amount;
    uint8_t txid_seed;
    uint32_t vout, sequence;
} in_spec_t;

typedef struct {
    size_t num_in;
    in_spec_t in[MAX_IN];
    size_t num_out;
    uint64_t out_amount[2];
    uint32_t locktime;
} spec_t;

static bool is_musig_ours(const int kind) { return kind == K_KEYPATH || kind == K_LEAF; }

/* What the harness knows of one input it built */
typedef struct {
    const struct ext_key* our;
    size_t n, our_pos;
    uint8_t parts[MAX_PARTS][33];
    const uint8_t* part_priv[MAX_PARTS];
    uint8_t agg33[33];
    secp256k1_musig_keyagg_cache cache; /* KeyAgg, with the BIP341 tweak for the key path */
    bool has_leaf;
    uint8_t leaf_script[34];
    uint8_t leaf_hash[32];
    secp256k1_xonly_pubkey coin_key; /* what the final signature verifies against */
} in_info_t;

enum { V_SAME, V_OUT_AMOUNT, V_UTXO_AMOUNT, V_LOCKTIME, V_SEQUENCE, V_EXTRA_FIELD, V_DROP_INPUT, V_ADD_OUTPUT, NUM_V };
static const char* const V_NAME[]
    = { "same", "out-amount", "utxo-amount", "locktime", "sequence", "extra-field", "drop-input", "add-output" };

static void tagged(const char* tag, const uint8_t* data, const size_t len, uint8_t* out)
{
    SETUP_OK(wally_bip340_tagged_hash(data, len, tag, out, 32) == WALLY_OK);
}

static void seeded_hash(const char* what, const size_t i, const size_t j, const uint8_t seed, uint8_t* out)
{
    uint8_t buf[40];
    const size_t len = strlen(what);
    memcpy(buf, what, len);
    buf[len] = (uint8_t)i;
    buf[len + 1] = (uint8_t)j;
    buf[len + 2] = seed;
    SETUP_OK(wally_sha256(buf, len + 3, out, 32) == WALLY_OK);
}

static void build_input(const in_spec_t* s, const size_t i, const uint64_t amount, in_info_t* f,
    struct wally_psbt_input* in, struct wally_tx_output** utxo_out)
{
    const secp256k1_context* ctx = sctx();
    memset(f, 0, sizeof(*f));
    f->our = our_key(s->child);
    const uint32_t path[5] = { OUR_PATH_PREFIX[0], OUR_PATH_PREFIX[1], OUR_PATH_PREFIX[2], OUR_PATH_PREFIX[3], s->child };
    uint8_t internal_x[32], merkle[32], output33[33];
    bool has_merkle = false;
    uint8_t control[1 + 32 + 3 * 32];
    size_t control_len = 0;

    if (s->kind == K_PLAIN_OURS) {
        memcpy(internal_x, f->our->pub_key + 1, 32);
    } else {
        f->n = s->n;
        f->our_pos = s->our_pos;
        for (size_t p = 0; p < s->n; ++p) {
            if (p == s->our_pos && s->kind != K_NOT_OURS) {
                memcpy(f->parts[p], f->our->pub_key, 33);
                f->part_priv[p] = f->our->priv_key + 1;
            } else {
                memcpy(f->parts[p], cos_pub[s->cosigner[p]], 33);
                f->part_priv[p] = cos_priv[s->cosigner[p]];
            }
        }
        secp256k1_pubkey pk[MAX_PARTS];
        const secp256k1_pubkey* ptrs[MAX_PARTS];
        for (size_t p = 0; p < f->n; ++p) {
            SETUP_OK(secp256k1_ec_pubkey_parse(ctx, &pk[p], f->parts[p], 33));
            ptrs[p] = &pk[p];
        }
        secp256k1_xonly_pubkey agg_x;
        secp256k1_pubkey agg_full;
        size_t len = 33;
        SETUP_OK(secp256k1_musig_pubkey_agg(ctx, &agg_x, &f->cache, ptrs, f->n));
        SETUP_OK(secp256k1_musig_pubkey_get(ctx, &agg_full, &f->cache));
        SETUP_OK(secp256k1_ec_pubkey_serialize(ctx, f->agg33, &len, &agg_full, SECP256K1_EC_COMPRESSED));

        if (s->kind == K_LEAF) {
            f->has_leaf = true;
            f->leaf_script[0] = 32;
            memcpy(f->leaf_script + 1, f->agg33 + 1, 32);
            f->leaf_script[33] = OP_CHECKSIG;
            uint8_t buf[36] = { 0xc0, 34 };
            memcpy(buf + 2, f->leaf_script, 34);
            tagged("TapLeaf", buf, sizeof(buf), f->leaf_hash);
            uint8_t node[32];
            memcpy(node, f->leaf_hash, 32);
            for (size_t d = 0; d < s->depth; ++d) {
                uint8_t* sibling = control + 1 + 32 + d * 32;
                seeded_hash("sibling", i, d, s->depth_seed, sibling);
                uint8_t branch[64];
                const bool node_first = memcmp(node, sibling, 32) < 0;
                memcpy(branch, node_first ? node : sibling, 32);
                memcpy(branch + 32, node_first ? sibling : node, 32);
                tagged("TapBranch", branch, 64, node);
            }
            memcpy(merkle, node, 32);
            has_merkle = true;
            memcpy(internal_x, nums_x, 32);
            control_len = 1 + 32 + s->depth * 32;
            SETUP_OK(secp256k1_xonly_pubkey_parse(ctx, &f->coin_key, f->agg33 + 1));
        } else {
            /* key path (ours or not): the aggregate is the internal key */
            memcpy(internal_x, f->agg33 + 1, 32);
            has_merkle = s->has_merkle;
            if (has_merkle)
                seeded_hash("merkle", i, 0, s->merkle_seed, merkle);
            uint8_t tweak_data[64], tweak[32];
            memcpy(tweak_data, internal_x, 32);
            memcpy(tweak_data + 32, merkle, 32);
            tagged("TapTweak", tweak_data, has_merkle ? 64 : 32, tweak);
            SETUP_OK(secp256k1_musig_pubkey_xonly_tweak_add(ctx, NULL, &f->cache, tweak));
        }
    }

    SETUP_OK(wally_ec_public_key_bip341_tweak(internal_x, 32, has_merkle ? merkle : NULL, has_merkle ? 32 : 0, 0,
                 output33, sizeof(output33))
        == WALLY_OK);
    if (!f->has_leaf)
        SETUP_OK(secp256k1_xonly_pubkey_parse(ctx, &f->coin_key, output33 + 1));
    uint8_t spk[34] = { OP_1, 32 };
    memcpy(spk + 2, output33 + 1, 32);
    SETUP_OK(wally_tx_output_init_alloc(amount, spk, sizeof(spk), utxo_out) == WALLY_OK);
    SETUP_OK(wally_psbt_input_set_witness_utxo(in, *utxo_out) == WALLY_OK);

    if (s->kind == K_NOT_OURS) {
        SETUP_OK(wally_psbt_input_taproot_keypath_add(in, f->parts[0] + 1, 32, NULL, 0, OTHER_FINGERPRINT, 4, path, 5)
            == WALLY_OK);
    } else {
        SETUP_OK(wally_psbt_input_taproot_keypath_add(in, f->our->pub_key + 1, 32, f->has_leaf ? f->leaf_hash : NULL,
                     f->has_leaf ? 32 : 0, our_fingerprint, 4, path, 5)
            == WALLY_OK);
    }
    if (s->kind == K_PLAIN_OURS)
        return;
    if (f->has_leaf) {
        control[0] = (uint8_t)(0xc0 | (output33[0] == 0x03 ? 1 : 0));
        memcpy(control + 1, internal_x, 32);
        uint8_t value[35];
        memcpy(value, f->leaf_script, 34);
        value[34] = 0xc0;
        SETUP_OK(wally_map_add(&in->taproot_leaf_scripts, control, control_len, value, sizeof(value)) == WALLY_OK);
    } else {
        SETUP_OK(wally_psbt_input_set_taproot_internal_key(in, internal_x, 32) == WALLY_OK);
        if (has_merkle)
            SETUP_OK(wally_map_add_integer(&in->psbt_fields, PSBT_IN_TAP_MERKLE_ROOT_FIELD, merkle, 32) == WALLY_OK);
    }
    uint8_t key[34] = { PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS };
    memcpy(key + 1, f->agg33, 33);
    SETUP_OK(wally_map_add(&in->unknowns, key, sizeof(key), &f->parts[0][0], f->n * 33) == WALLY_OK);
}

/* The payment (a variant of it), as the host builds it; info[] for each input */
static struct wally_psbt* build(const spec_t* s, const int variant, in_info_t* info)
{
    const size_t num_in = variant == V_DROP_INPUT && s->num_in > 1 ? s->num_in - 1 : s->num_in;
    const size_t num_out = s->num_out + (variant == V_ADD_OUTPUT ? 1 : 0);
    struct wally_tx* tx = NULL;
    SETUP_OK(wally_tx_init_alloc(2, s->locktime + (variant == V_LOCKTIME ? 1 : 0), num_in, num_out, &tx) == WALLY_OK);
    for (size_t i = 0; i < num_in; ++i) {
        uint8_t txid[32];
        seeded_hash("txid", i, 0, s->in[i].txid_seed, txid);
        const uint32_t seq = s->in[i].sequence ^ (variant == V_SEQUENCE && i == num_in - 1 ? 1 : 0);
        SETUP_OK(wally_tx_add_raw_input(tx, txid, 32, s->in[i].vout, seq, NULL, 0, NULL, 0) == WALLY_OK);
    }
    for (size_t o = 0; o < num_out; ++o) {
        const uint64_t amount = o < s->num_out ? s->out_amount[o] + (variant == V_OUT_AMOUNT && !o ? 1 : 0) : 546;
        SETUP_OK(wally_tx_add_raw_output(tx, amount, pay_spk, sizeof(pay_spk), 0) == WALLY_OK);
    }
    struct wally_psbt* psbt = NULL;
    SETUP_OK(wally_psbt_init_alloc(0, num_in, num_out, 0, 0, &psbt) == WALLY_OK);
    SETUP_OK(wally_psbt_set_global_tx(psbt, tx) == WALLY_OK);
    wally_tx_free(tx);
    for (size_t i = 0; i < num_in; ++i) {
        struct wally_tx_output* utxo = NULL;
        const uint64_t amount = s->in[i].amount + (variant == V_UTXO_AMOUNT && !i ? 1 : 0);
        build_input(&s->in[i], i, amount, &info[i], &psbt->inputs[i], &utxo);
        wally_tx_output_free(utxo);
    }
    if (variant == V_EXTRA_FIELD) {
        const uint8_t key[] = { 0xfc, 4, 'r', 'u', 'b', 'y', 0 };
        const uint8_t value[] = { 1, 2, 3 };
        SETUP_OK(wally_map_add(&psbt->inputs[0].unknowns, key, sizeof(key), value, sizeof(value)) == WALLY_OK);
    }
    return psbt;
}

static uint8_t* to_bytes(const struct wally_psbt* psbt, size_t* len)
{
    size_t written = 0;
    SETUP_OK(wally_psbt_get_length(psbt, 0, len) == WALLY_OK);
    uint8_t* bytes = malloc(*len);
    SETUP_OK(bytes && wally_psbt_to_bytes(psbt, 0, bytes, *len, &written) == WALLY_OK && written == *len);
    return bytes;
}

/* deserialise_psbt() of the firmware */
static struct wally_psbt* ruby_parse(const uint8_t* bytes, const size_t len)
{
    struct wally_psbt* psbt = NULL;
    if (wally_psbt_from_bytes(bytes, len, RUBY_PSBT_FLAGS, &psbt) != WALLY_OK || !psbt)
        return NULL;
    size_t out_len = 0;
    if (wally_psbt_get_length(psbt, 0, &out_len) != WALLY_OK || !out_len) {
        wally_psbt_free(psbt);
        return NULL;
    }
    return psbt;
}

/* The psbt as Ruby receives it */
static struct wally_psbt* as_received(const struct wally_psbt* psbt)
{
    size_t len = 0;
    uint8_t* bytes = to_bytes(psbt, &len);
    struct wally_psbt* parsed = ruby_parse(bytes, len);
    SETUP_OK(parsed); /* libwally refuses the test psbt: a harness bug */
    free(bytes);
    return parsed;
}

/* The input's BIP341 message, with libwally's own taproot API */
static void harness_msg(const struct wally_psbt* psbt, const size_t index, const in_info_t* f, uint8_t* msg)
{
    struct wally_map scripts;
    uint64_t values[MAX_IN + 1];
    SETUP_OK(psbt->num_inputs <= MAX_IN + 1);
    SETUP_OK(wally_map_init(psbt->num_inputs, NULL, &scripts) == WALLY_OK);
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_tx_output* utxo = psbt->inputs[i].witness_utxo;
        SETUP_OK(utxo && wally_map_add_integer(&scripts, i, utxo->script, utxo->script_len) == WALLY_OK);
        values[i] = utxo->satoshi;
    }
    SETUP_OK(wally_tx_get_btc_taproot_signature_hash(psbt->tx, index, &scripts, values, psbt->num_inputs,
                 f->has_leaf ? f->leaf_script : NULL, f->has_leaf ? 34 : 0, 0, WALLY_NO_CODESEPARATOR, NULL, 0,
                 WALLY_SIGHASH_DEFAULT, 0, msg, 32)
        == WALLY_OK);
    wally_map_clear(&scripts);
}

static size_t field_key(const uint8_t type, const uint8_t* participant, const in_info_t* f, uint8_t* key)
{
    key[0] = type;
    memcpy(key + 1, participant, 33);
    memcpy(key + 34, f->agg33, 33);
    if (f->has_leaf) {
        memcpy(key + 67, f->leaf_hash, 32);
        return 99;
    }
    return 67;
}

/* ---- the model of what Ruby holds ---- */

static struct {
    bool kept;
    size_t num_in;
    uint32_t created;
    bool valid[MAX_IN + 1];
    uint8_t pubnonce[MAX_IN + 1][NONCE_LEN];
    uint8_t msg[MAX_IN + 1][32];
} model;

static uint32_t now; /* mirror of the stub's clock */
static uint8_t made[MAX_OPS * MAX_IN][NONCE_LEN]; /* every nonce Ruby made (this input) */
static size_t num_made;
static uint8_t used[MAX_OPS * MAX_IN][NONCE_LEN]; /* every nonce of Ruby that signed */
static size_t num_used;

static bool expired(void) { return (uint32_t)(now - model.created) > LIFETIME; }

static void check_no_nonces(const char* where)
{
    if (kept_nonces)
        fail("%s: Ruby still holds nonces", where);
}

/* ---- round 1 ---- */

static void op_nonces(const spec_t* s, const int variant)
{
    in_info_t info[MAX_IN];
    struct wally_psbt* built = build(s, variant, info);
    struct wally_psbt* psbt = as_received(built);
    bool plain = false;
    size_t ours = 0;
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        plain = plain || s->in[i].kind == K_PLAIN_OURS;
        ours += is_musig_ours(s->in[i].kind);
    }
    const bool expect_ok = !plain && ours;

    uint8_t pubnonces[MAX_IN][NONCE_LEN];
    bool has_nonce[MAX_IN];
    const char* errmsg = NULL;
    const bool ok = musig2_create_nonces(psbt, psbt->tx, pubnonces, has_nonce, &errmsg);
    check_sensitive("musig2_create_nonces");
    trace("NONCES %s: %s%s%s\n", V_NAME[variant], ok ? "ok" : "refused", errmsg ? ": " : "", errmsg ? errmsg : "");
    if (ok != expect_ok)
        fail("round 1 (%s): Ruby %s it, expected %s (%s)", V_NAME[variant], ok ? "accepted" : "refused",
            expect_ok ? "accepted" : "refused", errmsg ? errmsg : "-");
    memset(&model, 0, sizeof(model));
    if (!ok) {
        if (!errmsg)
            fail("round 1 refused without a reason");
        check_no_nonces("a failed round 1");
    } else {
        if (!kept_nonces || kept_num_inputs != psbt->num_inputs)
            fail("round 1: Ruby keeps no nonces or for %u inputs", (unsigned)kept_num_inputs);
        model.kept = true;
        model.num_in = psbt->num_inputs;
        model.created = now;
        for (size_t i = 0; i < psbt->num_inputs; ++i) {
            if (has_nonce[i] != is_musig_ours(s->in[i].kind) || kept_nonces[i].present != has_nonce[i])
                fail("round 1: input %u (%s) %s a nonce", (unsigned)i, KIND_NAME[s->in[i].kind],
                    has_nonce[i] ? "has" : "has no");
            if (!has_nonce[i])
                continue;
            secp256k1_musig_pubnonce pn;
            if (!secp256k1_musig_pubnonce_parse(sctx(), &pn, pubnonces[i]))
                fail("round 1: Ruby's nonce of input %u does not parse", (unsigned)i);
            if (memcmp(pubnonces[i], kept_nonces[i].pubnonce, NONCE_LEN))
                fail("round 1: Ruby replies a nonce it does not keep");
            for (size_t m = 0; m < num_made; ++m)
                if (!memcmp(made[m], pubnonces[i], NONCE_LEN))
                    fail("round 1: Ruby made the same nonce twice");
            memcpy(made[num_made++], pubnonces[i], NONCE_LEN);
            uint8_t msg[32];
            harness_msg(psbt, i, &info[i], msg);
            if (memcmp(msg, kept_nonces[i].msg, 32))
                fail("round 1: the message Ruby keeps for input %u is not its BIP341 sighash", (unsigned)i);
            model.valid[i] = true;
            memcpy(model.pubnonce[i], pubnonces[i], NONCE_LEN);
            memcpy(model.msg[i], msg, 32);
        }
    }
    wally_psbt_free(psbt);
    wally_psbt_free(built);
}

/* ---- round 2 ---- */

enum {
    T_NONE,
    T_OUR_SWAPPED, /* our slot holds a nonce Ruby did not make */
    T_OUR_MISSING,
    T_OTHER_MISSING,
    T_OTHER_BADLEN,
    T_OTHER_INVALID, /* 66 bytes that are not two points */
    T_OTHER_COPIES_OURS, /* a cosigner "uses" our nonce */
    T_INFINITY, /* a cosigner's nonce cancels everybody else's: the aggregate nonce is the point at infinity */
    NUM_T
};
static const char* const T_NAME[]
    = { "none", "our-swapped", "our-missing", "other-missing", "other-badlen", "other-invalid", "other-copies-ours",
          "infinity" };

static bool tamper_ok(const int t) { return t == T_NONE || t == T_OTHER_COPIES_OURS || t == T_INFINITY; }

static void fresh_nonce(const uint8_t* priv, const uint8_t* pub33, const uint8_t* msg, const in_info_t* f,
    secp256k1_musig_secnonce* sec, uint8_t* out)
{
    const secp256k1_context* ctx = sctx();
    secp256k1_pubkey pk;
    secp256k1_musig_pubnonce pn;
    uint8_t secrand[32];
    h_random(secrand, sizeof(secrand));
    SETUP_OK(secp256k1_ec_pubkey_parse(ctx, &pk, pub33, 33));
    SETUP_OK(secp256k1_musig_nonce_gen(ctx, sec, &pn, secrand, priv, &pk, msg, &f->cache, NULL));
    SETUP_OK(secp256k1_musig_pubnonce_serialize(ctx, out, &pn));
}

/* value_q := -(sum of every other nonce), point by point */
static void cancelling_nonce(uint8_t (*values)[NONCE_LEN], const size_t n, const size_t q)
{
    const secp256k1_context* ctx = sctx();
    for (size_t k = 0; k < 2; ++k) {
        secp256k1_pubkey pts[MAX_PARTS];
        const secp256k1_pubkey* ptrs[MAX_PARTS];
        size_t m = 0;
        for (size_t p = 0; p < n; ++p) {
            if (p == q)
                continue;
            SETUP_OK(secp256k1_ec_pubkey_parse(ctx, &pts[m], values[p] + 33 * k, 33));
            ptrs[m] = &pts[m];
            ++m;
        }
        secp256k1_pubkey sum;
        size_t len = 33;
        SETUP_OK(secp256k1_ec_pubkey_combine(ctx, &sum, ptrs, m));
        SETUP_OK(secp256k1_ec_pubkey_negate(ctx, &sum));
        SETUP_OK(secp256k1_ec_pubkey_serialize(ctx, values[q] + 33 * k, &len, &sum, SECP256K1_EC_COMPRESSED));
    }
}

/* Ruby signed input 'index' of 'psbt' (as Ruby holds it now) with the nonce 'ours' for message 'msg': check it */
static void check_partial_sig(const struct wally_psbt* psbt, const size_t index, const in_info_t* f,
    const uint8_t* msg, const uint8_t* ours, const size_t unknowns_before, secp256k1_musig_secnonce* cosigner_sec)
{
    const secp256k1_context* ctx = sctx();
    const struct wally_psbt_input* in = &psbt->inputs[index];
    uint8_t key[99];
    size_t key_len = field_key(PSBT_IN_MUSIG2_PARTIAL_SIG, f->our->pub_key, f, key);
    size_t found = 0;
    if (wally_map_find(&in->unknowns, key, key_len, &found) != WALLY_OK || !found
        || in->unknowns.items[found - 1].value_len != MUSIG2_PARTIAL_SIG_LEN)
        fail("round 2 ok but no partial signature of ours in input %u", (unsigned)index);
    if (in->unknowns.num_items != unknowns_before + 1)
        fail("round 2 changed %d other fields", (int)in->unknowns.num_items - (int)unknowns_before - 1);

    /* no secret nonce signs twice */
    for (size_t u = 0; u < num_used; ++u)
        if (!memcmp(used[u], ours, NONCE_LEN))
            fail("A SECRET NONCE SIGNED TWICE (input %u): the private key can be computed", (unsigned)index);
    memcpy(used[num_used++], ours, NONCE_LEN);

    /* BIP327 PartialSigVerify with the nonces in the psbt */
    secp256k1_musig_pubnonce pubnonces[MAX_PARTS];
    const secp256k1_musig_pubnonce* ptrs[MAX_PARTS];
    for (size_t p = 0; p < f->n; ++p) {
        key_len = field_key(PSBT_IN_MUSIG2_PUB_NONCE, f->parts[p], f, key);
        if (wally_map_find(&in->unknowns, key, key_len, &found) != WALLY_OK || !found
            || in->unknowns.items[found - 1].value_len != NONCE_LEN
            || !secp256k1_musig_pubnonce_parse(ctx, &pubnonces[p], in->unknowns.items[found - 1].value))
            fail("round 2 ok without a valid nonce of participant %u", (unsigned)p);
        if (p == f->our_pos && memcmp(in->unknowns.items[found - 1].value, ours, NONCE_LEN))
            fail("round 2 ok with our slot holding another nonce");
        ptrs[p] = &pubnonces[p];
    }
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig partial;
    secp256k1_pubkey our_pk;
    SETUP_OK(secp256k1_musig_nonce_agg(ctx, &aggnonce, ptrs, f->n));
    SETUP_OK(secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg, &f->cache, NULL));
    SETUP_OK(secp256k1_ec_pubkey_parse(ctx, &our_pk, f->our->pub_key, 33));
    key_len = field_key(PSBT_IN_MUSIG2_PARTIAL_SIG, f->our->pub_key, f, key);
    SETUP_OK(wally_map_find(&in->unknowns, key, key_len, &found) == WALLY_OK && found);
    if (!secp256k1_musig_partial_sig_parse(ctx, &partial, in->unknowns.items[found - 1].value))
        fail("Ruby's partial signature of input %u does not parse", (unsigned)index);
    if (!secp256k1_musig_partial_sig_verify(ctx, &partial, &pubnonces[f->our_pos], &our_pk, &f->cache, &session))
        fail("Ruby's partial signature of input %u does not verify", (unsigned)index);

    /* honest cosigners: the aggregate signature is valid for the coin */
    if (!cosigner_sec)
        return;
    secp256k1_musig_partial_sig sigs[MAX_PARTS];
    const secp256k1_musig_partial_sig* sig_ptrs[MAX_PARTS];
    for (size_t p = 0; p < f->n; ++p) {
        if (p == f->our_pos) {
            sigs[p] = partial;
        } else {
            secp256k1_keypair kp;
            SETUP_OK(secp256k1_keypair_create(ctx, &kp, f->part_priv[p]));
            SETUP_OK(secp256k1_musig_partial_sign(ctx, &sigs[p], &cosigner_sec[p], &kp, &f->cache, &session));
        }
        sig_ptrs[p] = &sigs[p];
    }
    uint8_t sig64[64];
    SETUP_OK(secp256k1_musig_partial_sig_agg(ctx, sig64, &session, sig_ptrs, f->n));
    if (!secp256k1_schnorrsig_verify(ctx, sig64, msg, 32, &f->coin_key))
        fail("the MuSig2 signature of input %u (%s) is not valid for the coin", (unsigned)index,
            f->has_leaf ? "leaf" : "key path");
}

/* Round 2 of input 'index' on a variant, with one tamper. Returns -1 if sign_psbt would not call it, else ok. */
static int op_sign(const spec_t* s, const size_t index, const int variant, const int tamper)
{
    in_info_t info[MAX_IN];
    struct wally_psbt* built = build(s, variant, info);
    if (index >= built->num_inputs || !is_musig_ours(s->in[index].kind)) {
        wally_psbt_free(built);
        return -1;
    }
    const in_info_t* f = &info[index];
    uint8_t msg[32];
    harness_msg(built, index, f, msg);

    /* every participant's nonce, as the host puts them in the psbt */
    uint8_t values[MAX_PARTS][NONCE_LEN];
    size_t value_len[MAX_PARTS];
    secp256k1_musig_secnonce cosigner_sec[MAX_PARTS];
    secp256k1_musig_secnonce dummy_sec;
    const bool ruby_has = model.kept && index < model.num_in && model.valid[index];
    size_t q = f->our_pos ? 0 : 1; /* the cosigner that tampers */
    for (size_t p = 0; p < f->n; ++p) {
        value_len[p] = NONCE_LEN;
        if (p == f->our_pos) {
            if (ruby_has && tamper != T_OUR_SWAPPED)
                memcpy(values[p], model.pubnonce[index], NONCE_LEN);
            else
                fresh_nonce(cos_priv[7], cos_pub[7], msg, f, &dummy_sec, values[p]); /* not Ruby's */
        } else {
            fresh_nonce(f->part_priv[p], f->parts[p], msg, f, &cosigner_sec[p], values[p]);
        }
    }
    switch (tamper) {
    case T_OUR_MISSING:
        value_len[f->our_pos] = 0;
        break;
    case T_OTHER_MISSING:
        value_len[q] = 0;
        break;
    case T_OTHER_BADLEN:
        value_len[q] = NONCE_LEN - 1;
        break;
    case T_OTHER_INVALID:
        values[q][0] = 0x05;
        break;
    case T_OTHER_COPIES_OURS:
        memcpy(values[q], values[f->our_pos], NONCE_LEN);
        break;
    case T_INFINITY:
        cancelling_nonce(values, f->n, q);
        break;
    }
    struct wally_psbt_input* in = &built->inputs[index];
    for (size_t p = 0; p < f->n; ++p) {
        if (!value_len[p])
            continue;
        uint8_t key[99];
        const size_t key_len = field_key(PSBT_IN_MUSIG2_PUB_NONCE, f->parts[p], f, key);
        SETUP_OK(wally_map_add(&in->unknowns, key, key_len, values[p], value_len[p]) == WALLY_OK);
    }
    struct wally_psbt* psbt = as_received(built);

    /* sign_psbt: our key from the key iterator, then musig2_sign_input */
    key_iter iter;
    key_iter_input_begin(psbt, index, &iter);
    check_sensitive("key_iter_input_begin");
    SETUP_OK(iter.is_valid && !memcmp(iter.hdkey.pub_key, f->our->pub_key, 33));
    const bool early = !model.kept || index >= model.num_in || model.num_in != psbt->num_inputs || expired();
    const bool expect_ok
        = !early && model.valid[index] && !memcmp(msg, model.msg[index], 32) && tamper_ok(tamper);
    const size_t unknowns_before = psbt->inputs[index].unknowns.num_items;
    const char* errmsg = NULL;
    const bool ok = musig2_sign_input(psbt, index, psbt->tx, &iter.hdkey, &errmsg);
    wally_bzero(&iter, sizeof(iter));
    check_sensitive("musig2_sign_input");
    trace("SIGN %u %s %s: %s%s%s\n", (unsigned)index, V_NAME[variant], T_NAME[tamper], ok ? "ok" : "refused",
        errmsg ? ": " : "", errmsg ? errmsg : "");
    if (ok != expect_ok)
        fail("round 2 of input %u (%s, variant %s, tamper %s, Ruby %s a nonce%s): Ruby %s it, expected %s (%s)",
            (unsigned)index, KIND_NAME[s->in[index].kind], V_NAME[variant], T_NAME[tamper],
            ruby_has ? "holds" : "has no", early ? ", round 2 not allowed" : "", ok ? "SIGNED" : "refused",
            expect_ok ? "a signature" : "a refusal", errmsg ? errmsg : "-");
    if (!ok && !errmsg)
        fail("round 2 refused without a reason");
    if (!early) {
        model.valid[index] = false;
        if (!kept_nonces)
            fail("round 2 dropped every nonce");
        const uint8_t* b = (const uint8_t*)&kept_nonces[index];
        for (size_t k = 0; k < sizeof(musig2_nonce_t); ++k)
            if (b[k])
                fail("after round 2 of input %u Ruby's nonce is not wiped", (unsigned)index);
    }
    if (ok) {
        check_partial_sig(psbt, index, f, msg, values[f->our_pos], unknowns_before,
            tamper == T_NONE ? cosigner_sec : NULL);
        wally_psbt_free(as_received(psbt)); /* Ruby sends it back */
    }
    wally_psbt_free(psbt);
    wally_psbt_free(built);
    return ok;
}

/* sign_psbt: every MuSig2 input in order, stops at the first failure; then musig2_clear() */
static void op_sign_psbt(const spec_t* s, const int variant, const int tamper)
{
    const size_t num_in = variant == V_DROP_INPUT && s->num_in > 1 ? s->num_in - 1 : s->num_in;
    for (size_t i = 0; i < num_in; ++i)
        if (op_sign(s, i, variant, tamper) == 0)
            break;
    musig2_clear();
    memset(&model, 0, sizeof(model));
    check_no_nonces("sign_psbt's cleanup");
}

/* Round 2 of input 'index' on a correct round-2 psbt with changed bytes (only safety can be checked) */
static void op_sign_bytes(const spec_t* s, const size_t index, const size_t nmut, const uint8_t seed)
{
    in_info_t info[MAX_IN];
    struct wally_psbt* built = build(s, V_SAME, info);
    if (index >= built->num_inputs || !is_musig_ours(s->in[index].kind)) {
        wally_psbt_free(built);
        return;
    }
    const in_info_t* f = &info[index];
    uint8_t msg[32];
    harness_msg(built, index, f, msg);
    struct wally_psbt_input* in = &built->inputs[index];
    secp256k1_musig_secnonce sec;
    for (size_t p = 0; p < f->n; ++p) {
        uint8_t value[NONCE_LEN];
        if (p == f->our_pos && model.kept && index < model.num_in && model.valid[index])
            memcpy(value, model.pubnonce[index], NONCE_LEN);
        else
            fresh_nonce(f->part_priv[p], f->parts[p], msg, f, &sec, value);
        uint8_t key[99];
        const size_t key_len = field_key(PSBT_IN_MUSIG2_PUB_NONCE, f->parts[p], f, key);
        SETUP_OK(wally_map_add(&in->unknowns, key, key_len, value, NONCE_LEN) == WALLY_OK);
    }
    size_t len = 0;
    uint8_t* bytes = to_bytes(built, &len);
    h_state ^= (uint64_t)seed << 32 | index;
    for (size_t m = 0; m < nmut; ++m) {
        const uint64_t r = h_next();
        bytes[r % len] ^= (uint8_t)(1 + (r >> 32) % 255);
    }
    struct wally_psbt* psbt = ruby_parse(bytes, len);
    free(bytes);
    wally_psbt_free(built);
    if (!psbt)
        return;
    if (index >= psbt->num_inputs || !musig2_input_present(&psbt->inputs[index])) {
        wally_psbt_free(psbt);
        return;
    }
    key_iter iter;
    key_iter_input_begin(psbt, index, &iter);
    check_sensitive("key_iter_input_begin");
    if (!iter.is_valid) {
        wally_psbt_free(psbt);
        return; /* sign_psbt: "Failed to generate signature" */
    }
    const bool early = !model.kept || index >= model.num_in || model.num_in != psbt->num_inputs || expired();
    const bool had = !early && model.valid[index];
    uint8_t ours[NONCE_LEN], kept_msg[32];
    memcpy(ours, model.pubnonce[index], NONCE_LEN);
    memcpy(kept_msg, model.msg[index], 32);
    const size_t unknowns_before = psbt->inputs[index].unknowns.num_items;
    const bool same_key = !memcmp(iter.hdkey.pub_key, f->our->pub_key, 33);
    const char* errmsg = NULL;
    const bool ok = musig2_sign_input(psbt, index, psbt->tx, &iter.hdkey, &errmsg);
    wally_bzero(&iter, sizeof(iter));
    check_sensitive("musig2_sign_input");
    trace("SIGN_BYTES %u x%u: %s%s%s\n", (unsigned)index, (unsigned)nmut, ok ? "ok" : "refused", errmsg ? ": " : "",
        errmsg ? errmsg : "");
    if (!early)
        model.valid[index] = false;
    if (!ok)
        return (void)wally_psbt_free(psbt);
    if (!had)
        fail("round 2 (changed bytes) SIGNED input %u without a nonce of round 1", (unsigned)index);
    if (!same_key)
        fail("round 2 (changed bytes) signed input %u with another key", (unsigned)index);
    uint8_t now_msg[32];
    harness_msg(psbt, index, f, now_msg);
    if (memcmp(now_msg, kept_msg, 32))
        fail("round 2 (changed bytes) signed input %u for another message than round 1", (unsigned)index);
    check_partial_sig(psbt, index, f, kept_msg, ours, unknowns_before, NULL);
    wally_psbt_free(as_received(psbt));
    wally_psbt_free(psbt);
}

static void op_clear(void)
{
    musig2_clear();
    check_sensitive("musig2_clear");
    memset(&model, 0, sizeof(model));
    check_no_nonces("musig2_clear");
    trace("CLEAR\n");
}

static void op_time(const uint8_t mode, const uint8_t amount)
{
    const uint32_t elapsed = now - model.created;
    uint32_t d;
    switch (mode % 4) {
    case 0:
        d = 1 + amount * 37u;
        break;
    case 1: /* to the last tick of the lifetime */
        d = model.kept && elapsed < LIFETIME ? LIFETIME - elapsed : 1;
        break;
    case 2: /* to the first tick after it */
        d = model.kept && elapsed <= LIFETIME ? LIFETIME - elapsed + 1 : 1;
        break;
    default:
        d = LIFETIME / 2 + amount;
        break;
    }
    fuzz_ticks_advance(d);
    now += d;
    trace("TIME +%u (%u since round 1)\n", (unsigned)d, (unsigned)(now - model.created));
}

/* ---- the input ---- */

typedef struct {
    const uint8_t* p;
    size_t len, pos;
} reader_t;

static uint8_t next_byte(reader_t* r) { return r->pos < r->len ? r->p[r->pos++] : 0; }

static void read_spec(reader_t* r, spec_t* s)
{
    memset(s, 0, sizeof(*s));
    s->num_in = 1 + next_byte(r) % MAX_IN;
    for (size_t i = 0; i < s->num_in; ++i) {
        in_spec_t* in = &s->in[i];
        const uint8_t k = next_byte(r) % 10;
        in->kind = k < 5 ? K_KEYPATH : k < 8 ? K_LEAF : k == 8 ? K_NOT_OURS : K_PLAIN_OURS;
        in->n = 2 + next_byte(r) % (MAX_PARTS - 1);
        in->our_pos = next_byte(r) % in->n;
        const size_t start = next_byte(r) % NUM_COSIGNERS;
        for (size_t p = 0; p < in->n; ++p)
            in->cosigner[p] = (start + p) % (NUM_COSIGNERS - 1); /* cosigner 7 never: it makes "not Ruby's" nonces */
        in->child = next_byte(r);
        const uint8_t m = next_byte(r);
        in->has_merkle = m & 1;
        in->merkle_seed = m >> 1;
        const uint8_t d = next_byte(r);
        in->depth = d % 4;
        in->depth_seed = d >> 2;
        in->amount = 10000 + ((uint64_t)next_byte(r) << 8) + next_byte(r);
        in->txid_seed = next_byte(r);
        in->vout = next_byte(r) % 4;
        in->sequence = 0xfffffffd ^ (next_byte(r) & 1);
    }
    s->num_out = 1 + next_byte(r) % 2;
    for (size_t o = 0; o < 2; ++o)
        s->out_amount[o] = 1000 + ((uint64_t)next_byte(r) << 8) + next_byte(r);
    s->locktime = ((uint32_t)next_byte(r) << 8) | next_byte(r);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    init_keys();
    tracing = getenv("FUZZ_TRACE") != NULL;
    fuzz_random_set(data, size);
    h_state = 0x5275627900000000ULL ^ size;
    musig2_clear();
    memset(&model, 0, sizeof(model));
    num_made = num_used = 0;

    reader_t r = { data, size, 0 };
    const uint8_t t = next_byte(&r);
    now = t & 1 ? 0xffffffffu - (uint32_t)(t >> 1) * 4000u : (uint32_t)t * 12345u; /* odd: about to wrap */
    fuzz_ticks_set(now);
    spec_t spec;
    read_spec(&r, &spec);
    if (tracing) {
        fprintf(stderr, "payment: %u input(s):", (unsigned)spec.num_in);
        for (size_t i = 0; i < spec.num_in; ++i)
            fprintf(stderr, " %s/%u", KIND_NAME[spec.in[i].kind], (unsigned)spec.in[i].n);
        fprintf(stderr, ", clock %u\n", (unsigned)now);
    }

    for (size_t n = 0; n < MAX_OPS && r.pos < r.len; ++n) {
        const uint8_t op = next_byte(&r), a = next_byte(&r), b = next_byte(&r), c = next_byte(&r);
        switch (op % 8) {
        case 0:
            op_nonces(&spec, a % NUM_V);
            break;
        case 1:
        case 2:
            op_sign(&spec, a % MAX_IN, b % NUM_V, c % (NUM_T + 4) < NUM_T ? c % (NUM_T + 4) : T_NONE);
            break;
        case 3:
            op_sign_psbt(&spec, a % NUM_V, b % (NUM_T + 4) < NUM_T ? b % (NUM_T + 4) : T_NONE);
            break;
        case 4:
            op_nonces(&spec, a % NUM_V);
            op_sign_psbt(&spec, b % NUM_V, T_NONE);
            break;
        case 5:
            op_sign_bytes(&spec, a % MAX_IN, 1 + b % 4, c);
            break;
        case 6:
            op_clear();
            break;
        default:
            op_time(a, b);
            break;
        }
    }
    musig2_clear();
    return 0;
}
