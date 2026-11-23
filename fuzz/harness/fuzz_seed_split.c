/*
 * RPC 'seed_split' (main/process/seed_split.c): Wallet Backup / Time Encrypted Vault of a Ruby wallet. The host
 * sends the contacts (name, public key, number of shares); Ruby splits the seed with codex32 and returns every
 * contact's shares encrypted to that contact (EncryptJsonTo: AES-256-GCM text + BIE1-encrypted key). The real
 * firmware file is compiled here (fuzz/README.md, "Firmware code on the host"); the process function itself
 * (screens, keychain, USB) is not run: the harness calls its two steps, seed_split_parse() and seed_split_build(),
 * and does the vault masking as the process does.
 *
 * The first input byte picks the mode:
 *
 * even: RAW. The rest is a whole RPC request (CBOR), filtered as Ruby does (fw_rpc.h), then its params go to
 *       seed_split_parse(). Checked: memory safety; an accepted request has 2 <= k <= 9, 1 to 31 contacts with
 *       printable NUL-terminated names, valid and distinct public keys, at least 1 share each, k <= shares <= 31;
 *       then seed_split_build() on a test seed gives a reply with one well-formed entry per contact (key of 117
 *       bytes, text of 28 + JSON bytes) and 'masked' exactly in vault mode. The sensitive stack is empty after
 *       each step.
 *
 * odd:  STRUCTURED. The input describes a request (mode, k, contacts with names, key choice among test keys whose
 *       private keys the harness knows, shares; including invalid values). The harness encodes it, checks that
 *       Ruby accepts it exactly when the rules above say it should, and on acceptance checks the whole result as
 *       a contact would: decrypts every contact's key (BIE1) and text (AES-256-GCM), reads the JSON array of
 *       codex32 strings, checks each contact got its number of shares, and that the shares combine (all of them,
 *       and an input-chosen k of them) to the seed (backup) or to the pad that, XOR 'masked', is the seed (vault).
 */
#include "fw_amalgam.h"

#include "../../main/codex32.c"
#include "../../main/process/seed_split.c"

#include "firmware_stubs.h"
#include "fw_rpc.h"

#include <mbedtls/gcm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TEST_KEYS 40

/* ---- test keys: private key i = SHA256("ruby fuzz key" | i) ---- */

static uint8_t test_priv[MAX_TEST_KEYS][EC_PRIVATE_KEY_LEN];
static uint8_t test_pub[MAX_TEST_KEYS][EC_PUBLIC_KEY_LEN];

static void init_test_keys(void)
{
    static bool done;
    if (done)
        return;
    for (int i = 0; i < MAX_TEST_KEYS; ++i) {
        uint8_t msg[14] = "ruby fuzz key";
        msg[13] = (uint8_t)i;
        if (wally_sha256(msg, sizeof(msg), test_priv[i], EC_PRIVATE_KEY_LEN) != WALLY_OK
            || wally_ec_private_key_verify(test_priv[i], EC_PRIVATE_KEY_LEN) != WALLY_OK
            || wally_ec_public_key_from_private_key(test_priv[i], EC_PRIVATE_KEY_LEN, test_pub[i], EC_PUBLIC_KEY_LEN)
                != WALLY_OK)
            abort();
    }
    done = true;
}

/* ---- input reader ---- */

typedef struct {
    const uint8_t* p;
    size_t len, pos;
} reader_t;

static uint8_t next_byte(reader_t* r) { return r->pos < r->len ? r->p[r->pos++] : 0; }

/* ---- parse + build, as seed_split_process() does ---- */

typedef struct {
    bool vault;
    size_t threshold, num_contacts, total_shares;
    seed_split_contact_t contacts[SEED_SPLIT_MAX_CONTACTS];
} parsed_t;

static bool parse(const CborValue* params, parsed_t* p)
{
    const char* errmsg = NULL;
    memset(p, 0, sizeof(*p));
    const bool ok = seed_split_parse(
        params, &p->vault, &p->threshold, p->contacts, &p->num_contacts, &p->total_shares, &errmsg);
    if (fuzz_sensitive_depth())
        abort();
    if (!ok && !errmsg)
        abort(); /* refused without a message for the host */
    return ok;
}

static void check_parsed(const parsed_t* p)
{
    if (p->threshold < CODEX32_MIN_THRESHOLD || p->threshold > CODEX32_MAX_THRESHOLD)
        abort();
    if (!p->num_contacts || p->num_contacts > SEED_SPLIT_MAX_CONTACTS)
        abort();
    size_t total = 0;
    for (size_t i = 0; i < p->num_contacts; ++i) {
        const seed_split_contact_t* c = &p->contacts[i];
        const size_t name_len = strnlen(c->name, sizeof(c->name));
        if (!name_len || name_len > SEED_SPLIT_MAX_NAME_LEN)
            abort(); /* empty, or not NUL-terminated */
        for (size_t j = 0; j < name_len; ++j)
            if (c->name[j] < 0x20 || c->name[j] > 0x7e)
                abort(); /* a character the screen should not get */
        if (wally_ec_public_key_verify(c->pubkey, EC_PUBLIC_KEY_LEN) != WALLY_OK)
            abort();
        for (size_t j = 0; j < i; ++j)
            if (!memcmp(p->contacts[j].pubkey, c->pubkey, EC_PUBLIC_KEY_LEN))
                abort();
        if (!c->num_shares || c->num_shares > CODEX32_MAX_SHARES)
            abort();
        total += c->num_shares;
    }
    if (total != p->total_shares || total < p->threshold || total > CODEX32_MAX_SHARES)
        abort();
}

/* seed_split_process(): backup splits the seed; vault splits a random pad and returns masked = seed XOR pad */
static bool build(const parsed_t* p, const uint8_t* seed, const size_t seed_len, uint8_t** reply, size_t* reply_len,
    uint8_t* secret_out)
{
    uint8_t secret[CODEX32_MAX_SEED_LEN];
    uint8_t masked[CODEX32_MAX_SEED_LEN];
    if (p->vault) {
        get_random(secret, seed_len);
        for (size_t i = 0; i < seed_len; ++i)
            masked[i] = seed[i] ^ secret[i];
    } else {
        memcpy(secret, seed, seed_len);
    }
    const char* errmsg = NULL;
    const bool ok = seed_split_build(secret, seed_len, p->vault ? masked : NULL, p->threshold, p->contacts,
        p->num_contacts, p->total_shares, reply, reply_len, &errmsg);
    if (fuzz_sensitive_depth())
        abort();
    if (!ok && getenv("FUZZ_TRACE"))
        fprintf(stderr, "seed_split_build refused: %s\n", errmsg ? errmsg : "(no message)");
    if (secret_out)
        memcpy(secret_out, secret, seed_len);
    return ok;
}

/* ---- reading the reply ---- */

#define MAX_TEXT_LEN (GCM_NONCE_LEN + 2 + CODEX32_MAX_SHARES * (CODEX32_MAX_STRING_LEN + 3) + GCM_TAG_LEN)

typedef struct {
    uint8_t key[BIE1_LEN];
    uint8_t text[MAX_TEXT_LEN];
    size_t text_len;
} reply_contact_t;

static void copy_bytes(CborValue* v, uint8_t* out, const size_t out_max, size_t* out_len)
{
    size_t len = 0;
    if (!cbor_value_is_byte_string(v) || cbor_value_calculate_string_length(v, &len) != CborNoError || len > out_max)
        abort();
    *out_len = out_max;
    if (cbor_value_copy_byte_string(v, out, out_len, NULL) != CborNoError || *out_len != len)
        abort();
}

/* The reply map: contacts[] (key, text) and, in vault mode only, masked. Aborts on any other shape. */
static void read_reply(const parsed_t* p, const uint8_t* reply, const size_t reply_len, const size_t seed_len,
    reply_contact_t* out, uint8_t* masked, bool* has_masked)
{
    CborParser parser;
    CborValue root, contacts, item, v;
    size_t n = 0, num_fields = 0, len = 0;
    if (cbor_parser_init(reply, reply_len, 0, &parser, &root) != CborNoError || !cbor_value_is_map(&root)
        || cbor_value_get_map_length(&root, &num_fields) != CborNoError || num_fields != (p->vault ? 2u : 1u))
        abort();
    CborValue tmp = root;
    if (cbor_value_advance(&tmp) != CborNoError || (size_t)(tmp.source.ptr - reply) != reply_len)
        abort(); /* trailing bytes, or not one complete value */
    if (cbor_value_map_find_value(&root, "contacts", &contacts) != CborNoError || !cbor_value_is_array(&contacts)
        || cbor_value_get_array_length(&contacts, &n) != CborNoError || n != p->num_contacts)
        abort();
    if (cbor_value_enter_container(&contacts, &item) != CborNoError)
        abort();
    for (size_t i = 0; i < n; ++i) {
        if (!cbor_value_is_map(&item))
            abort();
        if (cbor_value_map_find_value(&item, "key", &v) != CborNoError)
            abort();
        copy_bytes(&v, out[i].key, sizeof(out[i].key), &len);
        if (len != BIE1_LEN)
            abort();
        if (cbor_value_map_find_value(&item, "text", &v) != CborNoError)
            abort();
        copy_bytes(&v, out[i].text, sizeof(out[i].text), &out[i].text_len);
        const size_t json_len = 2 + p->contacts[i].num_shares * (codex32_string_len(seed_len) + 3) - 1;
        if (out[i].text_len != GCM_NONCE_LEN + json_len + GCM_TAG_LEN)
            abort();
        if (cbor_value_advance(&item) != CborNoError)
            abort();
    }
    if (cbor_value_map_find_value(&root, "masked", &v) != CborNoError)
        abort();
    *has_masked = cbor_value_is_valid(&v);
    if (*has_masked != p->vault)
        abort(); /* 'masked' missing in a vault reply, or present in a backup one */
    if (p->vault) {
        copy_bytes(&v, masked, CODEX32_MAX_SEED_LEN, &len);
        if (len != seed_len)
            abort();
    }
}

/* What a contact does (DecryptJsonFor): BIE1-decrypt the key with its private key, base64-decode it, then
 * AES-256-GCM-decrypt the text. Returns the JSON length written into 'json'. */
static size_t contact_decrypt(const uint8_t* priv, const reply_contact_t* c, char* json, const size_t json_max)
{
    uint8_t keys[SHA512_LEN], mac[HMAC_SHA256_LEN];
    if (memcmp(c->key, "BIE1", 4) || !bie1_shared_keys(priv, c->key + 4, keys, sizeof(keys)))
        abort();
    if (wally_hmac_sha256(keys + 32, 32, c->key, BIE1_LEN - HMAC_SHA256_LEN, mac, sizeof(mac)) != WALLY_OK
        || memcmp(mac, c->key + BIE1_LEN - HMAC_SHA256_LEN, sizeof(mac)))
        abort(); /* the contact's key does not authenticate */
    uint8_t b64[BIE1_CIPHER_LEN + 1];
    size_t written = 0;
    if (wally_aes_cbc(keys + 16, 16, keys, 16, c->key + 4 + EC_PUBLIC_KEY_LEN, BIE1_CIPHER_LEN, AES_FLAG_DECRYPT,
            b64, sizeof(b64), &written)
            != WALLY_OK
        || written != GCM_KEY_B64_LEN)
        abort();
    b64[written] = '\0';
    uint8_t gcm_key[GCM_KEY_LEN + 2];
    if (wally_base64_to_bytes((const char*)b64, 0, gcm_key, sizeof(gcm_key), &written) != WALLY_OK
        || written != GCM_KEY_LEN)
        abort();

    const size_t json_len = c->text_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    if (json_len >= json_max)
        abort();
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, gcm_key, GCM_KEY_LEN * 8)
        || mbedtls_gcm_auth_decrypt(&gcm, json_len, c->text, GCM_NONCE_LEN, NULL, 0,
            c->text + c->text_len - GCM_TAG_LEN, GCM_TAG_LEN, c->text + GCM_NONCE_LEN, (unsigned char*)json))
        abort(); /* the text does not decrypt or authenticate */
    mbedtls_gcm_free(&gcm);
    json[json_len] = '\0';
    return json_len;
}

/* ["ms1...","ms1..."] exactly (GeneXus Collection.ToJson); the strings go to 'all' from index *count */
static void read_json(const char* json, const size_t json_len, const size_t expected, const size_t string_len,
    char (*all)[CODEX32_STRING_BUFLEN], size_t* count)
{
    if (json_len != 2 + expected * (string_len + 3) - 1 || json[0] != '[' || json[json_len - 1] != ']')
        abort();
    const char* s = json + 1;
    for (size_t i = 0; i < expected; ++i) {
        if (i && *s++ != ',')
            abort();
        if (*s++ != '"' || s[string_len] != '"')
            abort();
        if (*count >= CODEX32_MAX_SHARES)
            abort();
        memcpy(all[*count], s, string_len);
        all[*count][string_len] = '\0';
        ++*count;
        s += string_len + 1;
    }
}

static void check_shares(const parsed_t* p, const reply_contact_t* rc, const int* key_index, const uint8_t* seed,
    const size_t seed_len, const uint8_t* secret, const uint8_t* masked, reader_t* r)
{
    static char all[CODEX32_MAX_SHARES][CODEX32_STRING_BUFLEN];
    static char json[2 + CODEX32_MAX_SHARES * (CODEX32_MAX_STRING_LEN + 3)];
    const size_t string_len = codex32_string_len(seed_len);
    size_t count = 0;
    for (size_t i = 0; i < p->num_contacts; ++i) {
        const size_t json_len = contact_decrypt(test_priv[key_index[i]], &rc[i], json, sizeof(json));
        read_json(json, json_len, p->contacts[i].num_shares, string_len, all, &count);
    }
    if (count != p->total_shares)
        abort();

    const char* ptrs[CODEX32_MAX_SHARES];
    uint8_t out[CODEX32_MAX_SEED_LEN];
    size_t out_len = 0;
    for (size_t i = 0; i < count; ++i)
        ptrs[i] = all[i];
    if (!codex32_combine_seed(ptrs, count, out, sizeof(out), &out_len) || out_len != seed_len
        || memcmp(out, secret, seed_len))
        abort(); /* all the shares together do not give the secret back */

    /* an input-chosen k of them */
    for (size_t i = 0; i < p->threshold; ++i) {
        const size_t j = i + next_byte(r) % (count - i);
        const char* t = ptrs[i];
        ptrs[i] = ptrs[j];
        ptrs[j] = t;
    }
    if (!codex32_combine_seed(ptrs, p->threshold, out, sizeof(out), &out_len) || out_len != seed_len
        || memcmp(out, secret, seed_len))
        abort();

    if (p->vault) {
        for (size_t i = 0; i < seed_len; ++i)
            if ((uint8_t)(out[i] ^ masked[i]) != seed[i])
                abort(); /* pad XOR masked is not the seed */
    }
}

/* ---- RAW mode ---- */

static const uint8_t TEST_SEED[CODEX32_MAX_SEED_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

static void fuzz_raw(const uint8_t* data, const size_t size)
{
    CborParser parser;
    CborValue message, params;
    if (!fuzz_rpc_params(data, size, &parser, &message, &params))
        return;
    static parsed_t p;
    if (!parse(&params, &p))
        return;
    check_parsed(&p);

    uint8_t* reply = NULL;
    size_t reply_len = 0;
    if (!build(&p, TEST_SEED, 32, &reply, &reply_len, NULL))
        abort(); /* accepted request, but no reply */
    static reply_contact_t rc[SEED_SPLIT_MAX_CONTACTS];
    uint8_t masked[CODEX32_MAX_SEED_LEN];
    bool has_masked = false;
    read_reply(&p, reply, reply_len, 32, rc, masked, &has_masked);
    free(reply);
}

/* ---- STRUCTURED mode ---- */

static void fuzz_structured(const uint8_t* data, const size_t size)
{
    static const size_t SEED_LENS[] = { 16, 20, 24, 28, 32, 64 };
    static const char* const MODES[] = { "backup", "vault", "Backup", "" };
    static uint8_t msg[16384];
    reader_t r = { data, size, 0 };
    init_test_keys();

    const uint8_t mode_byte = next_byte(&r);
    const char* mode = MODES[mode_byte % 4];
    const size_t k = next_byte(&r) % 12;
    const size_t n = next_byte(&r) % 35;
    const size_t seed_len = SEED_LENS[next_byte(&r) % 6];
    uint8_t seed[CODEX32_MAX_SEED_LEN];
    for (size_t i = 0; i < seed_len; ++i)
        seed[i] = next_byte(&r);

    CborEncoder root, map, array, contact;
    cbor_encoder_init(&root, msg, sizeof(msg), 0);
    cbor_encoder_create_map(&root, &map, 3);
    cbor_encode_text_stringz(&map, "id");
    cbor_encode_text_stringz(&map, "1");
    cbor_encode_text_stringz(&map, "method");
    cbor_encode_text_stringz(&map, "seed_split");
    cbor_encode_text_stringz(&map, "params");
    CborEncoder params_enc;
    cbor_encoder_create_map(&map, &params_enc, 3);
    cbor_encode_text_stringz(&params_enc, "mode");
    cbor_encode_text_stringz(&params_enc, mode);
    cbor_encode_text_stringz(&params_enc, "threshold");
    cbor_encode_uint(&params_enc, k);
    cbor_encode_text_stringz(&params_enc, "contacts");
    cbor_encoder_create_array(&params_enc, &array, n);

    bool expect = (mode_byte % 4) < 2 && k >= CODEX32_MIN_THRESHOLD && k <= CODEX32_MAX_THRESHOLD && n >= 1
        && n <= SEED_SPLIT_MAX_CONTACTS;
    int key_index[34];
    bool used[MAX_TEST_KEYS] = { false };
    size_t total = 0;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t name_len = next_byte(&r) % 41;
        char name[41];
        for (size_t c = 0; c < name_len; ++c)
            name[c] = (char)next_byte(&r);
        const uint8_t key_byte = next_byte(&r);
        const bool bad_key = key_byte >= 250;
        key_index[i] = key_byte % MAX_TEST_KEYS;
        const size_t shares = next_byte(&r) % 34;

        cbor_encoder_create_map(&array, &contact, 3);
        cbor_encode_text_stringz(&contact, "name");
        cbor_encode_text_string(&contact, name, name_len);
        cbor_encode_text_stringz(&contact, "pubkey");
        uint8_t pubkey[EC_PUBLIC_KEY_LEN];
        memcpy(pubkey, test_pub[key_index[i]], sizeof(pubkey));
        if (bad_key)
            pubkey[0] = 0x05; /* not a public key */
        cbor_encode_byte_string(&contact, pubkey, sizeof(pubkey));
        cbor_encode_text_stringz(&contact, "shares");
        cbor_encode_uint(&contact, shares);
        cbor_encoder_close_container(&array, &contact);

        if (!name_len || bad_key || used[key_index[i]] || !shares || shares > CODEX32_MAX_SHARES)
            expect = false;
        used[key_index[i]] = true;
        total += shares;
    }
    if (total < k || total > CODEX32_MAX_SHARES)
        expect = false;
    cbor_encoder_close_container(&params_enc, &array);
    cbor_encoder_close_container(&map, &params_enc);
    if (cbor_encoder_close_container(&root, &map) != CborNoError)
        abort(); /* the test request does not fit: make msg bigger */
    const size_t msg_len = cbor_encoder_get_buffer_size(&root, msg);

    CborParser parser;
    CborValue message, params;
    if (!fuzz_rpc_params(msg, msg_len, &parser, &message, &params))
        abort(); /* Ruby would not even take the test request */
    static parsed_t p;
    const bool ok = parse(&params, &p);
    if (ok != expect)
        abort(); /* accepted something invalid, or refused something valid */
    if (!ok)
        return;
    check_parsed(&p);
    if (p.vault != ((mode_byte % 4) == 1) || p.threshold != k || p.num_contacts != n || p.total_shares != total)
        abort();

    fuzz_random_set(r.p + r.pos, r.len - r.pos);
    uint8_t* reply = NULL;
    size_t reply_len = 0;
    uint8_t secret[CODEX32_MAX_SEED_LEN];
    if (!build(&p, seed, seed_len, &reply, &reply_len, secret))
        abort();
    static reply_contact_t rc[SEED_SPLIT_MAX_CONTACTS];
    uint8_t masked[CODEX32_MAX_SEED_LEN];
    bool has_masked = false;
    read_reply(&p, reply, reply_len, seed_len, rc, masked, &has_masked);
    check_shares(&p, rc, key_index, seed, seed_len, secret, masked, &r);
    if (getenv("FUZZ_TRACE"))
        fprintf(stderr, "accepted and checked: %s k=%zu contacts=%zu shares=%zu seed=%zu bytes\n",
            p.vault ? "vault" : "backup", p.threshold, p.num_contacts, p.total_shares, seed_len);
    free(reply);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!size)
        return 0;
    fuzz_random_set(NULL, 0);
    if (data[0] & 1)
        fuzz_structured(data + 1, size - 1);
    else
        fuzz_raw(data + 1, size - 1);
    return 0;
}
