#ifndef AMALGAMATED_BUILD
// Ruby: export the DistributedCryptography wallet 'utility keys', encrypted to the host.
//
// The DistributedCryptography wallet derives, from its BIP86 account m/86'/c'/0', some hardened
// 'utility' keys used for things other than spending: login, chat, groups, local file encryption,
// file exchange and its software HSM. With Ruby the seed and every spending key stay on the device;
// only these hardened children are handed to the wallet (automatically, once the PIN has unlocked Ruby),
// so the wallet works exactly as a software wallet restored from the same mnemonic.
//
// A hardened child private key reveals neither its parent nor its siblings, so these keys can not be
// used to derive the account key or any spending key. The list of paths is fixed here: this call can
// never export the master, the account or a spending (non-hardened) key.
//
// The keys are returned as BIP32 serialized extended private keys (78 bytes each, version for the
// network), concatenated in the order of UTILITY_KEY_PATHS, AES encrypted with an ECDH shared key
// between a device ephemeral key and the host ephemeral pubkey - as get_bip85_bip39_entropy.
#include <inttypes.h>

#include "../aes.h"
#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../random.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"
#include "../utils/util.h"
#include "../wallet.h"

#include "process_utils.h"

#include <wally_bip32.h>

// Label used to derive the AES/HMAC keys from the ECDH shared secret
static const unsigned char HMAC_UTILITY_KEYS_MESSAGE[]
    = { 'r', 'u', 'b', 'y', '_', 'u', 't', 'i', 'l', 'i', 't', 'y', '_', 'k', 'e', 'y', 's' };

// The utility key paths, relative to the BIP86 account m/86'/c'/0' (all hardened).
// Order matters: it is the order of the keys in the returned (decrypted) buffer.
#define UTILITY_KEY_MAX_PATH_LEN 2
typedef struct {
    uint32_t path[UTILITY_KEY_MAX_PATH_LEN];
    size_t path_len;
} utility_key_path_t;

static const utility_key_path_t UTILITY_KEY_PATHS[] = {
    { { 0x80000000 + 1000, 0x80000000 }, 2 }, // 1000'/0' login (DistributedCryptography server, Nostr, files)
    { { 0x80000000 + 2000, 0x80000000 }, 2 }, // 2000'/0' chat
    { { 0x80000000 + 3000, 0x80000000 }, 2 }, // 3000'/0' groups
    { { 0x80000000 + 4000, 0x80000000 }, 2 }, // 4000'/0' local json files
    { { 0x80000000 + 5000, 0x80000000 }, 2 }, // 5000'/0' file encryption
    { { 0x80000000 + 6000 }, 1 }, // 6000' software HSM root (the wallet derives 6000'/i')
};
#define NUM_UTILITY_KEYS (sizeof(UTILITY_KEY_PATHS) / sizeof(UTILITY_KEY_PATHS[0]))
#define UTILITY_KEYS_PLAINTEXT_LEN (NUM_UTILITY_KEYS * BIP32_SERIALIZED_LEN)

typedef struct {
    uint8_t encrypted[AES_ENCRYPTED_LEN(UTILITY_KEYS_PLAINTEXT_LEN) + HMAC_SHA256_LEN];
    uint8_t pubkey[EC_PUBLIC_KEY_LEN];
    size_t encrypted_len;
} utility_keys_data_t;

void reply_utility_keys(const void* ctx, CborEncoder* container)
{
    const utility_keys_data_t* const data = (const utility_keys_data_t*)ctx;
    JADE_ASSERT(data);
    JADE_ASSERT(container);
    JADE_ASSERT(data->encrypted_len);

    CborEncoder map_encoder;
    CborError cberr = cbor_encoder_create_map(container, &map_encoder, 2);
    JADE_ASSERT(cberr == CborNoError);

    add_bytes_to_map(&map_encoder, "pubkey", data->pubkey, sizeof(data->pubkey));
    add_bytes_to_map(&map_encoder, "encrypted", data->encrypted, data->encrypted_len);

    cberr = cbor_encoder_close_container(container, &map_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

// Derive the utility keys and encrypt them to the passed host pubkey
static bool get_encrypted_utility_keys(const network_t network_id, const uint8_t* pubkey, const size_t pubkey_len,
    utility_keys_data_t* data, const char** errmsg)
{
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(pubkey);
    JADE_ASSERT(pubkey_len == EC_PUBLIC_KEY_LEN);
    JADE_ASSERT(data);
    JADE_INIT_OUT_PPTR(errmsg);

    uint8_t eph_privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(eph_privkey, sizeof(eph_privkey));
    uint8_t plaintext[UTILITY_KEYS_PLAINTEXT_LEN];
    SENSITIVE_PUSH(plaintext, sizeof(plaintext));
    struct ext_key account;
    SENSITIVE_PUSH(&account, sizeof(account));
    struct ext_key derived;
    SENSITIVE_PUSH(&derived, sizeof(derived));

    bool retval = false;

    // New ephemeral key - its pubkey goes in the reply
    if (!keychain_get_new_privatekey(eph_privkey, sizeof(eph_privkey))) {
        *errmsg = "Failed to generate new ephemeral key";
        goto cleanup;
    }
    JADE_WALLY_VERIFY(
        wally_ec_public_key_from_private_key(eph_privkey, sizeof(eph_privkey), data->pubkey, sizeof(data->pubkey)));

    // The BIP86 account m/86'/c'/0' - coin type 0' for mainnet, 1' for testnet/regtest.
    // NOTE: we do not SKIP_HASH, as the parent fingerprint is part of the serialized keys
    const uint32_t coin = network_to_type(network_id) == NETWORK_TYPE_MAIN ? 0 : 1;
    const uint32_t account_path[] = { harden(86), harden(coin), harden(0) };
    if (!wallet_get_hdkey(account_path, sizeof(account_path) / sizeof(account_path[0]), BIP32_FLAG_KEY_PRIVATE,
            &account)) {
        *errmsg = "Failed to derive account key";
        goto cleanup;
    }

    // Each utility key, serialized with the version of the passed network
    const uint32_t version = network_to_bip32_version(network_id);
    for (size_t i = 0; i < NUM_UTILITY_KEYS; ++i) {
        const utility_key_path_t* const ukp = &UTILITY_KEY_PATHS[i];
        for (size_t j = 0; j < ukp->path_len; ++j) {
            JADE_ASSERT(ukp->path[j] & 0x80000000); // hardened only
        }
        JADE_WALLY_VERIFY(
            bip32_key_from_parent_path(&account, ukp->path, ukp->path_len, BIP32_FLAG_KEY_PRIVATE, &derived));
        derived.version = version;
        JADE_WALLY_VERIFY(bip32_key_serialize(&derived, BIP32_FLAG_KEY_PRIVATE, plaintext + i * BIP32_SERIALIZED_LEN,
            BIP32_SERIALIZED_LEN));
    }

    // Encrypt and hmac the keys with the ECDH shared secret
    uint8_t iv[AES_BLOCK_LEN];
    get_random(iv, sizeof(iv));
    if (wally_aes_cbc_with_ecdh_key(eph_privkey, sizeof(eph_privkey), iv, sizeof(iv), plaintext, sizeof(plaintext),
            pubkey, pubkey_len, HMAC_UTILITY_KEYS_MESSAGE, sizeof(HMAC_UTILITY_KEYS_MESSAGE), AES_FLAG_ENCRYPT,
            data->encrypted, sizeof(data->encrypted), &data->encrypted_len)
            != WALLY_OK
        || data->encrypted_len > sizeof(data->encrypted)) {
        *errmsg = "Failed to encrypt utility keys";
        goto cleanup;
    }

    retval = true;

cleanup:
    SENSITIVE_POP(&derived);
    SENSITIVE_POP(&account);
    SENSITIVE_POP(plaintext);
    SENSITIVE_POP(eph_privkey);
    return retval;
}

void get_utility_keys_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "get_utility_keys");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    const uint8_t* pubkey = NULL;
    size_t pubkey_len = 0;
    rpc_get_bytes_ptr("pubkey", &params, &pubkey, &pubkey_len);
    if (pubkey_len != EC_PUBLIC_KEY_LEN || wally_ec_public_key_verify(pubkey, pubkey_len) != WALLY_OK) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to fetch valid pubkey from message");
        goto cleanup;
    }

    // No confirmation on screen (Angelo, 2026-11-08): the keys go to the wallet automatically once the PIN
    // has unlocked Ruby for this same host (checked above). Typing the PIN is the user's approval; the keys
    // are only the fixed hardened utility children, never the account or a spending key.

    utility_keys_data_t data = { .encrypted_len = 0 };
    const char* errmsg = NULL;
    if (!get_encrypted_utility_keys(network_id, pubkey, pubkey_len, &data, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, errmsg);
        goto cleanup;
    }

    // Reply with the encrypted keys
    uint8_t buf[768];
    jade_process_reply_to_message_result(&process->ctx, buf, sizeof(buf), &data, reply_utility_keys);
    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
