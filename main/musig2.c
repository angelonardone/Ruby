#ifndef AMALGAMATED_BUILD
#include "musig2.h"
#include "jade_assert.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "random.h"
#include "sensitive.h"
#include "utils/malloc_ext.h"
#include "utils/psbt.h"
#include "utils/temporary_stack.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <sodium/utils.h>
#include <string.h>

#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>

// Ruby: MuSig2 (BIP327) signing for the DistributedCryptography MuSig2 groups (see musig2.h and RUBY-GROUPS.md 2.4)

#define MUSIG2_XONLY_LEN EC_XONLY_PUBLIC_KEY_LEN
#define MUSIG2_KEY_LEN EC_PUBLIC_KEY_LEN
// The work of one input runs on a temporary stack (as group.c): KeyAgg, the sighash, NonceGen, the partial signature
// and its verification need more than the few KB the main task has left inside an RPC
#define MUSIG2_STACK_SIZE (12 * 1024)

// psbt input fields kept by libwally in psbt_fields (BIP371)
#define PSBT_IN_TAP_INTERNAL_KEY_FIELD 0x17
#define PSBT_IN_TAP_MERKLE_ROOT_FIELD 0x18

// One MuSig2 input, read from the psbt and checked
typedef struct {
    uint8_t agg[MUSIG2_KEY_LEN]; // the plain aggregate key (KeyAgg), compressed
    const uint8_t* participants; // num_participants * 33 bytes, in the psbt
    size_t num_participants;
    size_t our_index; // our position among the participants
    bool has_leaf;
    uint8_t leaf_hash[SHA256_LEN];
    const uint8_t* leaf_script; // without its leaf version (script path)
    size_t leaf_script_len;
    secp256k1_musig_keyagg_cache cache; // KeyAgg, plus the BIP341 tweak for the key path
} musig2_input_t;

// Our secret nonce of one input, between round 1 and round 2, with what it was made for
typedef struct {
    bool present;
    uint8_t pubkey[MUSIG2_KEY_LEN];
    uint8_t agg[MUSIG2_KEY_LEN];
    bool has_leaf;
    uint8_t leaf_hash[SHA256_LEN];
    uint8_t msg[SHA256_LEN];
    secp256k1_musig_secnonce secnonce;
    uint8_t pubnonce[MUSIG2_PUBNONCE_LEN];
} musig2_nonce_t;

// The nonces of ONE payment (one per input; never written to storage)
static musig2_nonce_t* kept_nonces = NULL;
static size_t kept_num_inputs = 0;
static TickType_t kept_expires = 0;

void musig2_clear(void)
{
    if (kept_nonces) {
        JADE_WALLY_VERIFY(wally_bzero(kept_nonces, MUSIG2_MAX_INPUTS * sizeof(musig2_nonce_t)));
        free(kept_nonces);
        kept_nonces = NULL;
    }
    kept_num_inputs = 0;
}

static const secp256k1_context* musig2_ctx(void)
{
    const secp256k1_context* ctx = (const secp256k1_context*)wally_get_secp_context();
    JADE_ASSERT(ctx);
    return ctx;
}

// The input's PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS fields (the first one in 'item', how many there are as the result)
static size_t find_participants(const struct wally_psbt_input* input, const struct wally_map_item** item)
{
    size_t count = 0;
    *item = NULL;
    for (size_t i = 0; i < input->unknowns.num_items; ++i) {
        const struct wally_map_item* it = &input->unknowns.items[i];
        if (it->key && it->key_len && it->key[0] == PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS) {
            if (!count) {
                *item = it;
            }
            ++count;
        }
    }
    return count;
}

bool musig2_input_present(const struct wally_psbt_input* input)
{
    JADE_ASSERT(input);
    const struct wally_map_item* item = NULL;
    return find_participants(input, &item) != 0;
}

static bool p2tr_utxo(const struct wally_psbt* psbt, const size_t index, const struct wally_tx_output** utxo)
{
    *utxo = NULL;
    return wally_psbt_get_input_best_utxo(psbt, index, utxo) == WALLY_OK && *utxo && (*utxo)->script
        && (*utxo)->script_len == 2 + MUSIG2_XONLY_LEN && (*utxo)->script[0] == OP_1
        && (*utxo)->script[1] == MUSIG2_XONLY_LEN;
}

// Reads and checks a MuSig2 input. 'ours' is our compressed key (33 bytes) or, before our key is derived (the key
// iterator), our x-only key (32 bytes).
static bool musig2_input_load(const struct wally_psbt* psbt, const size_t index, const uint8_t* ours,
    const size_t ours_len, musig2_input_t* mi, const char** errmsg)
{
    JADE_ASSERT(psbt && index < psbt->num_inputs);
    JADE_ASSERT(ours && (ours_len == MUSIG2_KEY_LEN || ours_len == MUSIG2_XONLY_LEN));
    JADE_ASSERT(mi);
    const struct wally_psbt_input* input = &psbt->inputs[index];
    memset(mi, 0, sizeof(*mi));

    // The participants, the aggregate key they name, and us among them (once)
    const struct wally_map_item* item = NULL;
    if (find_participants(input, &item) != 1 || item->key_len != 1 + MUSIG2_KEY_LEN || !item->value
        || !item->value_len || item->value_len % MUSIG2_KEY_LEN) {
        *errmsg = "Invalid MuSig2 participants";
        return false;
    }
    mi->participants = item->value;
    mi->num_participants = item->value_len / MUSIG2_KEY_LEN;
    if (mi->num_participants < 2 || mi->num_participants > MUSIG2_MAX_PARTICIPANTS) {
        *errmsg = "Invalid number of MuSig2 participants";
        return false;
    }
    size_t found = 0;
    for (size_t i = 0; i < mi->num_participants; ++i) {
        const uint8_t* p = mi->participants + i * MUSIG2_KEY_LEN;
        for (size_t j = i + 1; j < mi->num_participants; ++j) {
            if (!memcmp(p, mi->participants + j * MUSIG2_KEY_LEN, MUSIG2_KEY_LEN)) {
                *errmsg = "A MuSig2 participant is repeated";
                return false;
            }
        }
        const bool match = ours_len == MUSIG2_KEY_LEN ? !memcmp(p, ours, MUSIG2_KEY_LEN)
                                                      : !memcmp(p + 1, ours, MUSIG2_XONLY_LEN);
        if (match) {
            mi->our_index = i;
            ++found;
        }
    }
    if (found != 1) {
        *errmsg = "This Ruby is not a MuSig2 participant of the input";
        return false;
    }

    // KeyAgg in the order given: it must be the aggregate key named
    const secp256k1_context* ctx = musig2_ctx();
    secp256k1_pubkey* const pubkeys = JADE_MALLOC(mi->num_participants * sizeof(secp256k1_pubkey));
    const secp256k1_pubkey** const pointers = JADE_MALLOC(mi->num_participants * sizeof(secp256k1_pubkey*));
    bool ok = true;
    for (size_t i = 0; i < mi->num_participants && ok; ++i) {
        ok = secp256k1_ec_pubkey_parse(ctx, &pubkeys[i], mi->participants + i * MUSIG2_KEY_LEN, MUSIG2_KEY_LEN);
        pointers[i] = &pubkeys[i];
    }
    secp256k1_xonly_pubkey agg_xonly;
    secp256k1_pubkey agg_full;
    size_t agg_len = sizeof(mi->agg);
    ok = ok && secp256k1_musig_pubkey_agg(ctx, &agg_xonly, &mi->cache, pointers, mi->num_participants)
        && secp256k1_musig_pubkey_get(ctx, &agg_full, &mi->cache)
        && secp256k1_ec_pubkey_serialize(ctx, mi->agg, &agg_len, &agg_full, SECP256K1_EC_COMPRESSED)
        && agg_len == sizeof(mi->agg) && !memcmp(mi->agg, item->key + 1, MUSIG2_KEY_LEN);
    free(pointers);
    free(pubkeys);
    if (!ok) {
        *errmsg = "The MuSig2 participants do not aggregate to the key named";
        return false;
    }
    uint8_t agg_x[MUSIG2_XONLY_LEN];
    if (!secp256k1_xonly_pubkey_serialize(ctx, agg_x, &agg_xonly)) {
        *errmsg = "Invalid MuSig2 aggregate key";
        return false;
    }

    // Only the default sighash (BIP341 SIGHASH_DEFAULT: the library's)
    if (input->sighash && input->sighash != WALLY_SIGHASH_DEFAULT) {
        *errmsg = "Unsupported sighash for a MuSig2 input";
        return false;
    }

    const struct wally_tx_output* utxo = NULL;
    if (!p2tr_utxo(psbt, index, &utxo)) {
        *errmsg = "A MuSig2 input must spend a Taproot coin";
        return false;
    }

    // Our key's leaf hashes: one (script path) or none (key path)
    const uint8_t* const ours_x = ours_len == MUSIG2_KEY_LEN ? ours + 1 : ours;
    size_t hashes_found = 0;
    const struct wally_map_item* hashes = NULL;
    if (wally_map_find(&input->taproot_leaf_hashes, ours_x, MUSIG2_XONLY_LEN, &hashes_found) == WALLY_OK
        && hashes_found) {
        hashes = &input->taproot_leaf_hashes.items[hashes_found - 1];
    }

    if (input->taproot_leaf_scripts.num_items) {
        // Script path: ONE leaf <x-only aggregate> OP_CHECKSIG, committed in the coin spent (its control block)
        if (!hashes || hashes->value_len != SHA256_LEN) {
            *errmsg = "A MuSig2 script path needs exactly one leaf";
            return false;
        }
        const struct wally_map_item* leaf = psbt_find_taproot_leaf_script(input, hashes->value, utxo);
        if (!leaf || leaf->value_len - 1 != 1 + MUSIG2_XONLY_LEN + 1 || leaf->value[0] != MUSIG2_XONLY_LEN
            || memcmp(leaf->value + 1, agg_x, MUSIG2_XONLY_LEN) || leaf->value[1 + MUSIG2_XONLY_LEN] != OP_CHECKSIG) {
            *errmsg = "The MuSig2 leaf is not the aggregate key of its participants in the coin spent";
            return false;
        }
        mi->has_leaf = true;
        memcpy(mi->leaf_hash, hashes->value, SHA256_LEN);
        mi->leaf_script = leaf->value;
        mi->leaf_script_len = leaf->value_len - 1;
        return true;
    }

    // Key path: the aggregate is the internal key; with the merkle root (if any) it is the coin's output key
    if (hashes && hashes->value_len) {
        *errmsg = "A MuSig2 key path has no leaf";
        return false;
    }
    const struct wally_map_item* internal = wally_map_get_integer(&input->psbt_fields, PSBT_IN_TAP_INTERNAL_KEY_FIELD);
    const struct wally_map_item* merkle = wally_map_get_integer(&input->psbt_fields, PSBT_IN_TAP_MERKLE_ROOT_FIELD);
    if (!internal || internal->value_len != MUSIG2_XONLY_LEN || memcmp(internal->value, agg_x, MUSIG2_XONLY_LEN)
        || (merkle && merkle->value_len != SHA256_LEN)) {
        *errmsg = "The MuSig2 internal key is not the aggregate key of its participants";
        return false;
    }
    // BIP341 tweak = TapTweak(internal key || merkle root), applied to the aggregate (BIP327 xonly tweak)
    uint8_t tweak_data[MUSIG2_XONLY_LEN + SHA256_LEN];
    memcpy(tweak_data, agg_x, MUSIG2_XONLY_LEN);
    if (merkle) {
        memcpy(tweak_data + MUSIG2_XONLY_LEN, merkle->value, SHA256_LEN);
    }
    uint8_t tweak[SHA256_LEN];
    secp256k1_pubkey output_full;
    secp256k1_xonly_pubkey output_xonly;
    uint8_t output_x[MUSIG2_XONLY_LEN];
    if (wally_bip340_tagged_hash(tweak_data, MUSIG2_XONLY_LEN + (merkle ? SHA256_LEN : 0), "TapTweak", tweak,
            sizeof(tweak))
            != WALLY_OK
        || !secp256k1_musig_pubkey_xonly_tweak_add(ctx, &output_full, &mi->cache, tweak)
        || !secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xonly, NULL, &output_full)
        || !secp256k1_xonly_pubkey_serialize(ctx, output_x, &output_xonly)
        || memcmp(output_x, utxo->script + 2, MUSIG2_XONLY_LEN)) {
        *errmsg = "The MuSig2 key path is not the coin spent";
        return false;
    }
    return true;
}

// The BIP341 sighash (SIGHASH_DEFAULT) of the input: the leaf's (script path) or the key path's
static bool musig2_sighash(const struct wally_psbt* psbt, const size_t index, const struct wally_tx* tx,
    const musig2_input_t* mi, uint8_t* msg)
{
    struct wally_map scripts, values;
    JADE_WALLY_VERIFY(wally_map_init(psbt->num_inputs, NULL, &scripts));
    JADE_WALLY_VERIFY(wally_map_init(psbt->num_inputs, NULL, &values));
    bool ok = true;
    for (size_t i = 0; i < psbt->num_inputs && ok; ++i) {
        const struct wally_tx_output* spent = NULL;
        ok = wally_psbt_get_input_best_utxo(psbt, i, &spent) == WALLY_OK && spent && spent->script
            && wally_map_add_integer(&scripts, i, spent->script, spent->script_len) == WALLY_OK
            && wally_map_add_integer(&values, i, (const unsigned char*)&spent->satoshi, sizeof(spent->satoshi))
                == WALLY_OK;
    }
    ok = ok
        && wally_tx_get_input_signature_hash(tx, index, &scripts, NULL, &values, mi->has_leaf ? mi->leaf_script : NULL,
               mi->has_leaf ? mi->leaf_script_len : 0, 0, WALLY_NO_CODESEPARATOR, NULL, 0, NULL, 0,
               WALLY_SIGHASH_DEFAULT, WALLY_SIGTYPE_SW_V1, NULL, msg, SHA256_LEN)
            == WALLY_OK;
    JADE_WALLY_VERIFY(wally_map_clear(&scripts));
    JADE_WALLY_VERIFY(wally_map_clear(&values));
    return ok;
}

// ---------------------------------------------------------------------------------------------------------------
// The key iterator's check
// ---------------------------------------------------------------------------------------------------------------

typedef struct {
    const struct wally_psbt* psbt;
    size_t index;
    const uint8_t* xonly;
} musig2_check_args_t;

bool musig2_check_task(void* ctx)
{
    const musig2_check_args_t* args = (const musig2_check_args_t*)ctx;
    musig2_input_t* const mi = JADE_MALLOC(sizeof(musig2_input_t));
    const char* errmsg = NULL;
    const bool ok = musig2_input_load(args->psbt, args->index, args->xonly, MUSIG2_XONLY_LEN, mi, &errmsg);
    if (!ok) {
        JADE_LOGW("MuSig2 input %u refused: %s", args->index, errmsg);
    }
    free(mi);
    return ok;
}

bool musig2_input_check(const struct wally_psbt* psbt, const size_t index, const uint8_t* xonly)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(xonly);
    musig2_check_args_t args = { .psbt = psbt, .index = index, .xonly = xonly };
    return run_in_temporary_task(MUSIG2_STACK_SIZE, musig2_check_task, &args);
}

// ---------------------------------------------------------------------------------------------------------------
// Round 1: the nonces
// ---------------------------------------------------------------------------------------------------------------

typedef struct {
    const struct wally_psbt* psbt;
    size_t index;
    const struct wally_tx* tx;
    const struct ext_key* hdkey;
    musig2_nonce_t* nonce;
    const char* errmsg;
} musig2_nonce_args_t;

bool musig2_nonce_task(void* ctx)
{
    musig2_nonce_args_t* args = (musig2_nonce_args_t*)ctx;
    musig2_input_t* const mi = JADE_MALLOC(sizeof(musig2_input_t));
    const secp256k1_context* sctx = musig2_ctx();
    musig2_nonce_t* const n = args->nonce;
    bool ok = musig2_input_load(args->psbt, args->index, args->hdkey->pub_key, MUSIG2_KEY_LEN, mi, &args->errmsg);
    if (ok && !musig2_sighash(args->psbt, args->index, args->tx, mi, n->msg)) {
        args->errmsg = "Failed to calculate the MuSig2 sighash";
        ok = false;
    }
    if (ok) {
        secp256k1_pubkey pubkey;
        secp256k1_musig_pubnonce pubnonce;
        uint8_t secrand[32];
        get_random(secrand, sizeof(secrand));
        // BIP327 NonceGen: fresh randomness, and also our secret key, the message and the aggregate key
        ok = secp256k1_ec_pubkey_parse(sctx, &pubkey, args->hdkey->pub_key, MUSIG2_KEY_LEN)
            && secp256k1_musig_nonce_gen(sctx, &n->secnonce, &pubnonce, secrand, args->hdkey->priv_key + 1, &pubkey,
                n->msg, &mi->cache, NULL)
            && secp256k1_musig_pubnonce_serialize(sctx, n->pubnonce, &pubnonce);
        JADE_WALLY_VERIFY(wally_bzero(secrand, sizeof(secrand)));
        if (!ok) {
            args->errmsg = "Failed to make the MuSig2 nonces";
        }
    }
    if (ok) {
        memcpy(n->pubkey, args->hdkey->pub_key, MUSIG2_KEY_LEN);
        memcpy(n->agg, mi->agg, MUSIG2_KEY_LEN);
        n->has_leaf = mi->has_leaf;
        memcpy(n->leaf_hash, mi->leaf_hash, SHA256_LEN);
        n->present = true;
    } else {
        JADE_WALLY_VERIFY(wally_bzero(n, sizeof(*n)));
    }
    JADE_LOGI("MuSig2 nonce of input %u: %u bytes of stack left", (unsigned)args->index,
        (unsigned)uxTaskGetStackHighWaterMark(NULL));
    free(mi);
    return ok;
}

bool musig2_create_nonces(const struct wally_psbt* psbt, const struct wally_tx* tx,
    uint8_t (*pubnonces)[MUSIG2_PUBNONCE_LEN], bool* has_nonce, const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(tx);
    JADE_ASSERT(pubnonces);
    JADE_ASSERT(has_nonce);
    JADE_INIT_OUT_PPTR(errmsg);

    // A new payment replaces the nonces of any earlier one
    musig2_clear();
    if (!psbt->num_inputs || psbt->num_inputs > MUSIG2_MAX_INPUTS) {
        *errmsg = "Too many inputs for a MuSig2 payment";
        return false;
    }
    musig2_nonce_t* const nonces = JADE_CALLOC(MUSIG2_MAX_INPUTS, sizeof(musig2_nonce_t));

    key_iter iter;
    SENSITIVE_PUSH(&iter, sizeof(iter));
    size_t num_signed = 0;
    bool ok = true;
    for (size_t index = 0; index < psbt->num_inputs && ok; ++index) {
        has_nonce[index] = false;
        const bool present = musig2_input_present(&psbt->inputs[index]);
        // our key, checked as a MuSig2 input by the key iterator (musig2_input_check)
        if (!key_iter_input_begin(psbt, index, &iter)) {
            if (present) {
                JADE_LOGW("MuSig2 input %u is not ours or not valid", index);
            }
            continue;
        }
        if (!present) {
            *errmsg = "Only MuSig2 inputs can be in a MuSig2 payment";
            ok = false;
            break;
        }
        musig2_nonce_args_t args
            = { .psbt = psbt, .index = index, .tx = tx, .hdkey = &iter.hdkey, .nonce = &nonces[index], NULL };
        if (!run_in_temporary_task(MUSIG2_STACK_SIZE, musig2_nonce_task, &args)) {
            *errmsg = args.errmsg ? args.errmsg : "Failed to make the MuSig2 nonces";
            ok = false;
            break;
        }
        memcpy(pubnonces[index], nonces[index].pubnonce, MUSIG2_PUBNONCE_LEN);
        has_nonce[index] = true;
        ++num_signed;
    }
    SENSITIVE_POP(&iter);

    if (ok && !num_signed) {
        *errmsg = "No MuSig2 input of this Ruby in the payment";
        ok = false;
    }
    if (!ok) {
        JADE_WALLY_VERIFY(wally_bzero(nonces, MUSIG2_MAX_INPUTS * sizeof(musig2_nonce_t)));
        free(nonces);
        return false;
    }
    kept_nonces = nonces;
    kept_num_inputs = psbt->num_inputs;
    kept_expires = xTaskGetTickCount() + pdMS_TO_TICKS(MUSIG2_NONCES_LIFETIME_MS);
    JADE_LOGI("MuSig2 nonces made for %u input(s)", num_signed);
    return true;
}

// ---------------------------------------------------------------------------------------------------------------
// Round 2: the partial signature of one input
// ---------------------------------------------------------------------------------------------------------------

typedef struct {
    struct wally_psbt* psbt;
    size_t index;
    const struct wally_tx* tx;
    const struct ext_key* hdkey;
    musig2_nonce_t* nonce;
    const char* errmsg;
} musig2_sign_args_t;

// key of a PSBT_IN_MUSIG2_PUB_NONCE / PARTIAL_SIG field: type || participant || aggregate [|| leaf hash]
static size_t musig2_field_key(const uint8_t type, const uint8_t* participant, const musig2_input_t* mi, uint8_t* key)
{
    key[0] = type;
    memcpy(key + 1, participant, MUSIG2_KEY_LEN);
    memcpy(key + 1 + MUSIG2_KEY_LEN, mi->agg, MUSIG2_KEY_LEN);
    if (mi->has_leaf) {
        memcpy(key + 1 + 2 * MUSIG2_KEY_LEN, mi->leaf_hash, SHA256_LEN);
        return 1 + 2 * MUSIG2_KEY_LEN + SHA256_LEN;
    }
    return 1 + 2 * MUSIG2_KEY_LEN;
}

bool musig2_sign_task(void* ctx)
{
    musig2_sign_args_t* args = (musig2_sign_args_t*)ctx;
    musig2_nonce_t* const n = args->nonce;
    const secp256k1_context* sctx = musig2_ctx();
    musig2_input_t* const mi = JADE_MALLOC(sizeof(musig2_input_t));
    const struct wally_psbt_input* const input = &args->psbt->inputs[args->index];
    secp256k1_musig_pubnonce* pubnonces = NULL;
    const secp256k1_musig_pubnonce** pointers = NULL;
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig partial;
    secp256k1_pubkey pubkey;
    secp256k1_keypair keypair;
    uint8_t msg[SHA256_LEN];
    uint8_t key[1 + 2 * MUSIG2_KEY_LEN + SHA256_LEN];
    uint8_t partial_bytes[MUSIG2_PARTIAL_SIG_LEN];
    size_t key_len = 0;
    int signed_ok = 0;
    bool ok = false;
    memset(&keypair, 0, sizeof(keypair));

    if (!musig2_input_load(args->psbt, args->index, args->hdkey->pub_key, MUSIG2_KEY_LEN, mi, &args->errmsg)) {
        goto cleanup;
    }
    if (!musig2_sighash(args->psbt, args->index, args->tx, mi, msg)) {
        args->errmsg = "Failed to calculate the MuSig2 sighash";
        goto cleanup;
    }
    // The nonce of round 1 must be for exactly this: our key, the same aggregate and leaf, the same message
    if (!n->present || sodium_memcmp(n->pubkey, args->hdkey->pub_key, MUSIG2_KEY_LEN)
        || sodium_memcmp(n->agg, mi->agg, MUSIG2_KEY_LEN) || n->has_leaf != mi->has_leaf
        || (n->has_leaf && sodium_memcmp(n->leaf_hash, mi->leaf_hash, SHA256_LEN))
        || sodium_memcmp(n->msg, msg, SHA256_LEN)) {
        args->errmsg = "Ruby has no MuSig2 nonces for this payment: start the signing again";
        goto cleanup;
    }

    // Every participant's public nonce; ours must be the one Ruby made
    pubnonces = JADE_MALLOC(mi->num_participants * sizeof(secp256k1_musig_pubnonce));
    pointers = JADE_MALLOC(mi->num_participants * sizeof(secp256k1_musig_pubnonce*));
    for (size_t i = 0; i < mi->num_participants; ++i) {
        const uint8_t* participant = mi->participants + i * MUSIG2_KEY_LEN;
        key_len = musig2_field_key(PSBT_IN_MUSIG2_PUB_NONCE, participant, mi, key);
        size_t found = 0;
        if (wally_map_find(&input->unknowns, key, key_len, &found) != WALLY_OK || !found
            || input->unknowns.items[found - 1].value_len != MUSIG2_PUBNONCE_LEN) {
            args->errmsg = "A MuSig2 public nonce is missing";
            goto cleanup;
        }
        const uint8_t* value = input->unknowns.items[found - 1].value;
        if (i == mi->our_index && sodium_memcmp(value, n->pubnonce, MUSIG2_PUBNONCE_LEN)) {
            args->errmsg = "The payment does not carry the MuSig2 nonce this Ruby made";
            goto cleanup;
        }
        if (!secp256k1_musig_pubnonce_parse(sctx, &pubnonces[i], value)) {
            args->errmsg = "Invalid MuSig2 public nonce";
            goto cleanup;
        }
        pointers[i] = &pubnonces[i];
    }

    if (!secp256k1_musig_nonce_agg(sctx, &aggnonce, pointers, mi->num_participants)
        || !secp256k1_musig_nonce_process(sctx, &session, &aggnonce, msg, &mi->cache, NULL)
        || !secp256k1_keypair_create(sctx, &keypair, args->hdkey->priv_key + 1)) {
        args->errmsg = "Failed to prepare the MuSig2 signature";
        goto cleanup;
    }
    // Uses up the secret nonce (secp256k1 zeroes it): whatever happens next, round 1 must be done again
    signed_ok = secp256k1_musig_partial_sign(sctx, &partial, &n->secnonce, &keypair, &mi->cache, &session);
    n->present = false;
    if (!signed_ok || !secp256k1_ec_pubkey_parse(sctx, &pubkey, args->hdkey->pub_key, MUSIG2_KEY_LEN)
        || !secp256k1_musig_partial_sig_verify(sctx, &partial, &pubnonces[mi->our_index], &pubkey, &mi->cache, &session)
        || !secp256k1_musig_partial_sig_serialize(sctx, partial_bytes, &partial)) {
        args->errmsg = "Failed to make the MuSig2 partial signature";
        goto cleanup;
    }
    key_len = musig2_field_key(PSBT_IN_MUSIG2_PARTIAL_SIG, args->hdkey->pub_key, mi, key);
    if (wally_map_replace(&args->psbt->inputs[args->index].unknowns, key, key_len, partial_bytes, sizeof(partial_bytes))
        != WALLY_OK) {
        args->errmsg = "Failed to add the MuSig2 partial signature";
        goto cleanup;
    }
    ok = true;

cleanup:
    JADE_LOGI("MuSig2 partial signature of input %u: %u bytes of stack left", (unsigned)args->index,
        (unsigned)uxTaskGetStackHighWaterMark(NULL));
    JADE_WALLY_VERIFY(wally_bzero(&keypair, sizeof(keypair)));
    free(pointers);
    free(pubnonces);
    free(mi);
    return ok;
}

bool musig2_sign_input(struct wally_psbt* psbt, const size_t index, const struct wally_tx* tx,
    const struct ext_key* hdkey, const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(tx);
    JADE_ASSERT(hdkey);
    JADE_INIT_OUT_PPTR(errmsg);
    if (!kept_nonces || index >= kept_num_inputs || kept_num_inputs != psbt->num_inputs
        || (int32_t)(xTaskGetTickCount() - kept_expires) > 0) {
        *errmsg = "Ruby has no MuSig2 nonces for this payment: start the signing again";
        return false;
    }
    musig2_sign_args_t args
        = { .psbt = psbt, .index = index, .tx = tx, .hdkey = hdkey, .nonce = &kept_nonces[index], NULL };
    const bool ok = run_in_temporary_task(MUSIG2_STACK_SIZE, musig2_sign_task, &args);
    // the secret nonce of this input can never be used again
    JADE_WALLY_VERIFY(wally_bzero(&kept_nonces[index], sizeof(musig2_nonce_t)));
    if (!ok) {
        *errmsg = args.errmsg ? args.errmsg : "Failed to make the MuSig2 partial signature";
    }
    return ok;
}
#endif // AMALGAMATED_BUILD
