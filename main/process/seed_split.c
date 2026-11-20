#ifndef AMALGAMATED_BUILD
// Ruby: RPC 'seed_split' - Wallet Backup / Time Encrypted Vault of a Ruby wallet (see seed_split.h).
//
// Request params:
//   mode       "backup" | "vault"
//   threshold  k, 2..9 (codex32)
//   contacts   [ { name: text, pubkey: bytes(33), shares: uint }, ... ]   1..31 contacts, 1..31 shares in total
// After the user accepts the split and every contact on the screen, the reply 'result' is the CBOR encoding of
//   { "contacts": [ { "key": bytes(117), "text": bytes }, ... ]   (same order as the request)
//     "masked":   bytes(seed length)                              (vault only) }
// sent as bytes, over several messages when it is bigger than one ('seqnum' / 'seqlen', the next part asked with
// 'get_extended_data', as sign_psbt does). The shares and the pad never leave Ruby in clear and are wiped here.
#include "../aes.h"
#include "../codex32.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../random.h"
#include "../seed_split.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../utils/util.h"

#include "process_utils.h"

#include <ctype.h>
#include <mbedtls/gcm.h>
#include <secp256k1.h>
#include <string.h>
#include <wally_core.h>
#include <wally_crypto.h>

#define SEED_SPLIT_CHUNK_SIZE (MAX_OUTPUT_MSG_SIZE - 64)

// EncryptionService (AES-256-GCM): nonce | ciphertext | tag; the key travels as its base64 string
#define GCM_KEY_LEN 32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define GCM_KEY_B64_LEN 44

// NBitcoin PubKey.Encrypt ("BIE1", Electrum ECIES) of the 44-char base64 key
#define BIE1_MAGIC_LEN 4
#define BIE1_CIPHER_LEN AES_PADDED_LEN(GCM_KEY_B64_LEN)
#define BIE1_LEN (BIE1_MAGIC_LEN + EC_PUBLIC_KEY_LEN + BIE1_CIPHER_LEN + HMAC_SHA256_LEN)

static void seed_split_random(uint8_t* buf, const size_t len) { get_random(buf, len); }

// NBitcoin PubKey.Encrypt: shared = SHA512(compressed ECDH point of an ephemeral key and 'pubkey');
// iv = shared[0..16], AES-128-CBC (PKCS#7) key = shared[16..32], HMAC-SHA256 key = shared[32..64];
// output "BIE1" | ephemeral pubkey | ciphertext | HMAC of everything before it.
static bool bie1_encrypt(const uint8_t* pubkey, const uint8_t* msg, const size_t msg_len, uint8_t* out,
    const size_t out_len)
{
    JADE_ASSERT(pubkey);
    JADE_ASSERT(msg);
    JADE_ASSERT(msg_len == GCM_KEY_B64_LEN);
    JADE_ASSERT(out);
    JADE_ASSERT(out_len == BIE1_LEN);

    uint8_t eph_privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(eph_privkey, sizeof(eph_privkey));
    uint8_t shared_point[EC_PUBLIC_KEY_LEN];
    SENSITIVE_PUSH(shared_point, sizeof(shared_point));
    uint8_t keys[SHA512_LEN];
    SENSITIVE_PUSH(keys, sizeof(keys));
    secp256k1_pubkey point;
    SENSITIVE_PUSH(&point, sizeof(point));

    bool retval = false;
    const secp256k1_context* ctx = (const secp256k1_context*)wally_get_secp_context();
    if (!keychain_get_new_privatekey(eph_privkey, sizeof(eph_privkey))
        || !secp256k1_ec_pubkey_parse(ctx, &point, pubkey, EC_PUBLIC_KEY_LEN)
        || !secp256k1_ec_pubkey_tweak_mul(ctx, &point, eph_privkey)) {
        goto cleanup;
    }
    size_t point_len = sizeof(shared_point);
    if (!secp256k1_ec_pubkey_serialize(ctx, shared_point, &point_len, &point, SECP256K1_EC_COMPRESSED)
        || point_len != sizeof(shared_point)) {
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_sha512(shared_point, sizeof(shared_point), keys, sizeof(keys)));

    memcpy(out, "BIE1", BIE1_MAGIC_LEN);
    JADE_WALLY_VERIFY(wally_ec_public_key_from_private_key(
        eph_privkey, sizeof(eph_privkey), out + BIE1_MAGIC_LEN, EC_PUBLIC_KEY_LEN));
    size_t written = 0;
    uint8_t* const cipher = out + BIE1_MAGIC_LEN + EC_PUBLIC_KEY_LEN;
    if (wally_aes_cbc(keys + 16, 16, keys, 16, msg, msg_len, AES_FLAG_ENCRYPT, cipher, BIE1_CIPHER_LEN, &written)
            != WALLY_OK
        || written != BIE1_CIPHER_LEN) {
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_hmac_sha256(keys + 32, 32, out, BIE1_LEN - HMAC_SHA256_LEN, out + BIE1_LEN - HMAC_SHA256_LEN,
        HMAC_SHA256_LEN));
    retval = true;

cleanup:
    SENSITIVE_POP(&point);
    SENSITIVE_POP(keys);
    SENSITIVE_POP(shared_point);
    SENSITIVE_POP(eph_privkey);
    return retval;
}

// EncryptionService.Encrypt with a new random key: 'text' = nonce | AES-256-GCM(plaintext) | tag (plaintext_len +
// 28 bytes); 'key' = BIE1 of the key's base64 string to 'pubkey'.
static bool encrypt_json_to(const uint8_t* pubkey, const uint8_t* plaintext, const size_t plaintext_len, uint8_t* text,
    const size_t text_len, uint8_t* key, const size_t key_len)
{
    JADE_ASSERT(text_len == GCM_NONCE_LEN + plaintext_len + GCM_TAG_LEN);

    uint8_t gcm_key[GCM_KEY_LEN];
    SENSITIVE_PUSH(gcm_key, sizeof(gcm_key));
    char* gcm_key_b64 = NULL;
    bool retval = false;

    get_random(gcm_key, sizeof(gcm_key));
    get_random(text, GCM_NONCE_LEN);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    const bool encrypted = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, gcm_key, GCM_KEY_LEN * 8) == 0
        && mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, text, GCM_NONCE_LEN, NULL, 0, plaintext,
               text + GCM_NONCE_LEN, GCM_TAG_LEN, text + GCM_NONCE_LEN + plaintext_len)
            == 0;
    mbedtls_gcm_free(&gcm);
    if (!encrypted) {
        goto cleanup;
    }

    if (wally_base64_from_bytes(gcm_key, sizeof(gcm_key), 0, &gcm_key_b64) != WALLY_OK || !gcm_key_b64
        || strlen(gcm_key_b64) != GCM_KEY_B64_LEN) {
        goto cleanup;
    }
    retval = bie1_encrypt(pubkey, (const uint8_t*)gcm_key_b64, GCM_KEY_B64_LEN, key, key_len);

cleanup:
    if (gcm_key_b64) {
        wally_bzero(gcm_key_b64, strlen(gcm_key_b64));
        JADE_WALLY_VERIFY(wally_free_string(gcm_key_b64));
    }
    SENSITIVE_POP(gcm_key);
    return retval;
}

// The JSON array of 'num' codex32 strings, as GeneXus Collection.ToJson(): ["ms1...","ms1..."]
static size_t shares_json(char (*shares)[CODEX32_STRING_BUFLEN], const size_t num, char* json, const size_t json_len)
{
    size_t pos = 0;
    json[pos++] = '[';
    for (size_t i = 0; i < num; ++i) {
        const size_t len = strlen(shares[i]);
        JADE_ASSERT(pos + len + 4 <= json_len);
        if (i) {
            json[pos++] = ',';
        }
        json[pos++] = '"';
        memcpy(json + pos, shares[i], len);
        pos += len;
        json[pos++] = '"';
    }
    JADE_ASSERT(pos < json_len);
    json[pos++] = ']';
    return pos;
}

static bool seed_split_parse(const CborValue* params, bool* vault, size_t* threshold, seed_split_contact_t* contacts,
    size_t* num_contacts, size_t* total_shares, const char** errmsg)
{
    char mode[8];
    size_t written = 0;
    rpc_get_string("mode", sizeof(mode), params, mode, &written);
    if (written && !strcmp(mode, "backup")) {
        *vault = false;
    } else if (written && !strcmp(mode, "vault")) {
        *vault = true;
    } else {
        *errmsg = "Invalid mode (backup or vault)";
        return false;
    }

    uint32_t k = 0;
    if (!rpc_get_uint32("threshold", params, &k) || k < CODEX32_MIN_THRESHOLD || k > CODEX32_MAX_THRESHOLD) {
        *errmsg = "Invalid threshold (2 to 9)";
        return false;
    }
    *threshold = k;

    CborValue array;
    size_t num = 0;
    if (!rpc_get_array("contacts", params, &array, &num) || !num || num > SEED_SPLIT_MAX_CONTACTS) {
        *errmsg = "Invalid contacts (1 to 31)";
        return false;
    }
    CborValue item;
    if (cbor_value_enter_container(&array, &item) != CborNoError) {
        *errmsg = "Invalid contacts";
        return false;
    }
    size_t total = 0;
    for (size_t i = 0; i < num; ++i) {
        seed_split_contact_t* const contact = &contacts[i];
        if (!cbor_value_is_map(&item)) {
            *errmsg = "Invalid contact";
            return false;
        }

        const char* name = NULL;
        size_t name_len = 0;
        rpc_get_string_ptr("name", &item, &name, &name_len);
        if (!name || !name_len) {
            *errmsg = "Missing contact name";
            return false;
        }
        // Only shown on the screen: long names cut, anything but printable ASCII shown as '?'
        const size_t shown = name_len < SEED_SPLIT_MAX_NAME_LEN ? name_len : SEED_SPLIT_MAX_NAME_LEN;
        for (size_t c = 0; c < shown; ++c) {
            const unsigned char ch = (unsigned char)name[c];
            contact->name[c] = ch < 0x80 && isprint(ch) ? (char)ch : '?';
        }
        contact->name[shown] = '\0';

        if (!rpc_get_n_bytes("pubkey", &item, EC_PUBLIC_KEY_LEN, contact->pubkey)
            || wally_ec_public_key_verify(contact->pubkey, EC_PUBLIC_KEY_LEN) != WALLY_OK) {
            *errmsg = "Invalid contact pubkey";
            return false;
        }
        for (size_t j = 0; j < i; ++j) {
            if (!memcmp(contacts[j].pubkey, contact->pubkey, EC_PUBLIC_KEY_LEN)) {
                *errmsg = "Two contacts have the same pubkey";
                return false;
            }
        }

        uint32_t shares = 0;
        if (!rpc_get_uint32("shares", &item, &shares) || !shares || shares > CODEX32_MAX_SHARES) {
            *errmsg = "Invalid number of shares of a contact";
            return false;
        }
        contact->num_shares = shares;
        total += shares;

        if (cbor_value_advance(&item) != CborNoError) {
            *errmsg = "Invalid contacts";
            return false;
        }
    }
    if (total < *threshold || total > CODEX32_MAX_SHARES) {
        *errmsg = "The shares must be at least the threshold and at most 31";
        return false;
    }
    *num_contacts = num;
    *total_shares = total;
    return true;
}

// Splits 'secret' and encodes the reply (see top of file) into a new buffer
static bool seed_split_build(const uint8_t* secret, const size_t secret_len, const uint8_t* masked, const size_t threshold,
    const seed_split_contact_t* contacts, const size_t num_contacts, const size_t total_shares, uint8_t** out,
    size_t* out_len, const char** errmsg)
{
    const size_t string_len = codex32_string_len(secret_len);
    JADE_ASSERT(string_len);

    // Every share string, and one contact's JSON at a time
    const size_t shares_size = total_shares * CODEX32_STRING_BUFLEN;
    char(*shares)[CODEX32_STRING_BUFLEN] = JADE_MALLOC(shares_size);
    SENSITIVE_PUSH(shares, shares_size);
    const size_t json_size = 2 + total_shares * (string_len + 3);
    char* const json = JADE_MALLOC(json_size);
    SENSITIVE_PUSH(json, json_size);

    // Reply size: per contact the key, the text (json + 28) and a little CBOR framing
    size_t reply_size = 64 + (masked ? secret_len + 16 : 0);
    for (size_t i = 0; i < num_contacts; ++i) {
        reply_size += 32 + BIE1_LEN + GCM_NONCE_LEN + GCM_TAG_LEN + 2 + contacts[i].num_shares * (string_len + 3);
    }
    uint8_t* const reply = JADE_MALLOC(reply_size);
    uint8_t* text = NULL;

    bool retval = false;
    if (!codex32_split_seed(secret, secret_len, threshold, total_shares, NULL, seed_split_random, shares)) {
        *errmsg = "Failed to split the seed";
        goto cleanup;
    }

    CborEncoder root;
    cbor_encoder_init(&root, reply, reply_size, 0);
    CborEncoder map;
    CborError cberr = cbor_encoder_create_map(&root, &map, masked ? 2 : 1);
    JADE_ASSERT(cberr == CborNoError);

    cberr = cbor_encode_text_stringz(&map, "contacts");
    JADE_ASSERT(cberr == CborNoError);
    CborEncoder array;
    cberr = cbor_encoder_create_array(&map, &array, num_contacts);
    JADE_ASSERT(cberr == CborNoError);

    size_t next_share = 0;
    for (size_t i = 0; i < num_contacts; ++i) {
        const size_t json_len = shares_json(&shares[next_share], contacts[i].num_shares, json, json_size);
        next_share += contacts[i].num_shares;

        const size_t text_len = GCM_NONCE_LEN + json_len + GCM_TAG_LEN;
        text = JADE_MALLOC(text_len);
        uint8_t key[BIE1_LEN];
        if (!encrypt_json_to(contacts[i].pubkey, (const uint8_t*)json, json_len, text, text_len, key, sizeof(key))) {
            *errmsg = "Failed to encrypt the shares of a contact";
            goto cleanup;
        }
        wally_bzero(json, json_size);

        CborEncoder contact_map;
        cberr = cbor_encoder_create_map(&array, &contact_map, 2);
        JADE_ASSERT(cberr == CborNoError);
        add_bytes_to_map(&contact_map, "key", key, sizeof(key));
        add_bytes_to_map(&contact_map, "text", text, text_len);
        cberr = cbor_encoder_close_container(&array, &contact_map);
        JADE_ASSERT(cberr == CborNoError);
        free(text);
        text = NULL;
    }
    JADE_ASSERT(next_share == total_shares);
    cberr = cbor_encoder_close_container(&map, &array);
    JADE_ASSERT(cberr == CborNoError);

    if (masked) {
        add_bytes_to_map(&map, "masked", masked, secret_len);
    }
    cberr = cbor_encoder_close_container(&root, &map);
    JADE_ASSERT(cberr == CborNoError);

    *out_len = cbor_encoder_get_buffer_size(&root, reply);
    *out = reply;
    retval = true;

cleanup:
    free(text);
    if (!retval) {
        free(reply);
    }
    SENSITIVE_POP(json);
    free(json);
    SENSITIVE_POP(shares);
    free(shares);
    return retval;
}

void seed_split_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "seed_split");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);

    seed_split_contact_t* const contacts = JADE_MALLOC(SEED_SPLIT_MAX_CONTACTS * sizeof(seed_split_contact_t));
    jade_process_free_on_exit(process, contacts);

    bool vault = false;
    size_t threshold = 0;
    size_t num_contacts = 0;
    size_t total_shares = 0;
    const char* errmsg = NULL;
    if (!seed_split_parse(&params, &vault, &threshold, contacts, &num_contacts, &total_shares, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        goto cleanup;
    }

    // The seed Ruby stores since 2026-11-20 (keychain.c); a Ruby set up before only has the xpriv
    const keychain_t* const keychain = keychain_get();
    JADE_ASSERT(keychain);
    if (!keychain->seed_len || !codex32_string_len(keychain->seed_len)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR,
            "This Ruby has no seed: set up the wallet again from its recovery words");
        goto cleanup;
    }

    if (!show_seed_split_activity(vault, threshold, total_shares, contacts, num_contacts)) {
        JADE_LOGW("User declined the seed split");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined the split");
        goto cleanup;
    }
    display_processing_message_activity();

    // backup: the seed itself; vault: a random pad (masked = seed XOR pad goes back to the wallet)
    const size_t secret_len = keychain->seed_len;
    uint8_t secret[CODEX32_MAX_SEED_LEN];
    SENSITIVE_PUSH(secret, sizeof(secret));
    uint8_t masked[CODEX32_MAX_SEED_LEN];
    if (vault) {
        get_random(secret, secret_len);
        for (size_t i = 0; i < secret_len; ++i) {
            masked[i] = keychain->seed[i] ^ secret[i];
        }
    } else {
        memcpy(secret, keychain->seed, secret_len);
    }

    uint8_t* reply = NULL;
    size_t reply_len = 0;
    const bool built = seed_split_build(secret, secret_len, vault ? masked : NULL, threshold, contacts, num_contacts,
        total_shares, &reply, &reply_len, &errmsg);
    SENSITIVE_POP(secret);
    if (!built) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, errmsg);
        goto cleanup;
    }
    jade_process_free_on_exit(process, reply);

    // Send as cbor bytes - maybe split over N messages if the result is large
    char original_id[MAXLEN_ID + 1];
    size_t original_id_len = 0;
    rpc_get_id(&process->ctx.value, original_id, sizeof(original_id), &original_id_len);

    const size_t nmsgs = ((reply_len - 1) / SEED_SPLIT_CHUNK_SIZE) + 1;
    uint8_t* const msgbuf = JADE_MALLOC(MAX_OUTPUT_MSG_SIZE);
    jade_process_free_on_exit(process, msgbuf);
    const uint8_t* chunk = reply;
    for (size_t imsg = 0; imsg < nmsgs; ++imsg) {
        const size_t remaining = reply + reply_len - chunk;
        const size_t chunk_len = remaining < SEED_SPLIT_CHUNK_SIZE ? remaining : SEED_SPLIT_CHUNK_SIZE;
        const size_t seqnum = imsg + 1;
        jade_process_reply_to_message_bytes_sequence(
            &process->ctx, seqnum, nmsgs, chunk, chunk_len, msgbuf, MAX_OUTPUT_MSG_SIZE);
        chunk += chunk_len;

        if (seqnum < nmsgs) {
            // Await a 'get_extended_data' message
            jade_process_load_in_message(process, true);
            if (!IS_CURRENT_MESSAGE(process, "get_extended_data")) {
                jade_process_reject_message(
                    process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'get_extended_data'");
                goto cleanup;
            }
            GET_MSG_PARAMS(process);
            if (!check_extended_data_fields(&params, original_id, "seed_split", seqnum + 1, nmsgs)) {
                jade_process_reject_message(
                    process, CBOR_RPC_PROTOCOL_ERROR, "Mismatched fields in 'get_extended_data' message");
                goto cleanup;
            }
        }
    }
    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
