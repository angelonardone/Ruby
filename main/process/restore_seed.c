#ifndef AMALGAMATED_BUILD
// Ruby: RPC 'restore_seed' - a wallet recovered by a Wallet Backup / Time Encrypted Vault group goes into a Ruby
// with no wallet (a new Ruby, or one reset). Ruby holds one wallet, so a Ruby with a PIN refuses it.
//
// 1. 'restore_seed' (no params): Ruby draws an ephemeral key and replies its public key (bytes, 33).
// 2. 'restore_seed_data' { seed: bytes }: the 64-byte BIP32 seed encrypted to that key exactly as NBitcoin
//    PubKey.Encrypt does it: "BIE1" | wallet ephemeral pubkey (33) | AES-128-CBC (80) | HMAC-SHA256 (32)
//    (see bie1_shared_keys in seed_split.h). The seed does not cross the USB cable in clear.
//    Ruby shows the fingerprint of the recovered wallet (the wallet shows the same one); if the user accepts, the
//    wallet is set in memory, NOT stored, and the reply is true.
// 3. The next 'auth_user' asks the new PIN (with the wallet oracle) and only then stores the seed (keychain_store),
//    as after the recovery words are entered on Ruby. Without it the wallet is gone at the next restart.
#include "../aes.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../process.h"
#include "../seed_split.h"
#include "../sensitive.h"
#include "../ui.h"
#include "../utils/cbor_rpc.h"

#include "process_utils.h"

#include <string.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

#define RESTORE_SEED_LEN BIP32_ENTROPY_LEN_512
#define RESTORE_SEED_CIPHER_LEN AES_PADDED_LEN(RESTORE_SEED_LEN)
#define RESTORE_SEED_BIE1_LEN (4 + EC_PUBLIC_KEY_LEN + RESTORE_SEED_CIPHER_LEN + HMAC_SHA256_LEN)

static bool restore_seed_same_mac(const uint8_t* a, const uint8_t* b, const size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// NBitcoin Key.Decrypt of 'enc' with Ruby's ephemeral key: the HMAC is checked before anything is decrypted
static bool restore_seed_decrypt(
    const uint8_t* privkey, const uint8_t* enc, const size_t enc_len, uint8_t* seed, const size_t seed_len)
{
    JADE_ASSERT(privkey);
    JADE_ASSERT(seed);
    JADE_ASSERT(seed_len >= RESTORE_SEED_CIPHER_LEN);

    if (!enc || enc_len != RESTORE_SEED_BIE1_LEN || memcmp(enc, "BIE1", 4)) {
        return false;
    }

    uint8_t keys[SHA512_LEN];
    SENSITIVE_PUSH(keys, sizeof(keys));
    uint8_t mac[HMAC_SHA256_LEN];
    bool retval = false;
    size_t written = 0;

    if (!bie1_shared_keys(privkey, enc + 4, keys, sizeof(keys))) {
        goto cleanup;
    }
    JADE_WALLY_VERIFY(wally_hmac_sha256(keys + 32, 32, enc, enc_len - HMAC_SHA256_LEN, mac, sizeof(mac)));
    if (!restore_seed_same_mac(mac, enc + enc_len - HMAC_SHA256_LEN, sizeof(mac))) {
        goto cleanup;
    }
    if (wally_aes_cbc(keys + 16, 16, keys, 16, enc + 4 + EC_PUBLIC_KEY_LEN, RESTORE_SEED_CIPHER_LEN, AES_FLAG_DECRYPT,
            seed, seed_len, &written)
            != WALLY_OK
        || written != RESTORE_SEED_LEN) {
        goto cleanup;
    }
    retval = true;

cleanup:
    SENSITIVE_POP(keys);
    return retval;
}

void restore_seed_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "restore_seed");

    uint8_t eph_privkey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(eph_privkey, sizeof(eph_privkey));
    uint8_t seed[RESTORE_SEED_CIPHER_LEN];
    SENSITIVE_PUSH(seed, sizeof(seed));
    keychain_t keydata = { 0 };
    SENSITIVE_PUSH(&keydata, sizeof(keydata));

    // One wallet per Ruby: never over a wallet with a PIN (nor over a temporary one)
    if (keychain_has_pin() || keychain_has_temporary()) {
        jade_process_reject_message(
            process, CBOR_RPC_HW_LOCKED, "This Ruby already has a wallet: connect a new Ruby or reset this one");
        goto cleanup;
    }

    // 1. Ruby's ephemeral key for this restore
    uint8_t eph_pubkey[EC_PUBLIC_KEY_LEN];
    if (!keychain_get_new_privatekey(eph_privkey, sizeof(eph_privkey))) {
        jade_process_reject_message(process, CBOR_RPC_INTERNAL_ERROR, "Failed to create a key");
        goto cleanup;
    }
    JADE_WALLY_VERIFY(
        wally_ec_public_key_from_private_key(eph_privkey, sizeof(eph_privkey), eph_pubkey, sizeof(eph_pubkey)));
    jade_process_reply_to_message_bytes(&process->ctx, eph_pubkey, sizeof(eph_pubkey));

    // 2. The encrypted seed
    jade_process_load_in_message(process, true);
    if (IS_CURRENT_MESSAGE(process, "cancel")) {
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "Restore cancelled");
        goto cleanup;
    }
    if (!IS_CURRENT_MESSAGE(process, "restore_seed_data")) {
        jade_process_reject_message(
            process, CBOR_RPC_PROTOCOL_ERROR, "Unexpected message, expecting 'restore_seed_data'");
        goto cleanup;
    }
    GET_MSG_PARAMS(process);
    const uint8_t* enc = NULL;
    size_t enc_len = 0;
    rpc_get_bytes_ptr("seed", &params, &enc, &enc_len);
    if (!restore_seed_decrypt(eph_privkey, enc, enc_len, seed, sizeof(seed))) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Invalid encrypted seed");
        goto cleanup;
    }
    keychain_derive_from_seed(seed, RESTORE_SEED_LEN, &keydata);

    // The user checks the fingerprint against the one the wallet shows
    if (!show_restore_seed_activity(keydata.xpriv.hash160, BIP32_KEY_FINGERPRINT_LEN)) {
        JADE_LOGW("User declined the restore");
        jade_process_reject_message(process, CBOR_RPC_USER_CANCELLED, "User declined the restore");
        goto cleanup;
    }

    // In memory only, not associated with any connection: nothing else works until 'auth_user' sets the PIN
    // and stores it (as after the recovery words, mnemonic.c)
    keychain_set(&keydata, SOURCE_NONE, false);
    keychain_clear_network_type_restriction();

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

cleanup:
    SENSITIVE_POP(&keydata);
    SENSITIVE_POP(seed);
    SENSITIVE_POP(eph_privkey);
}
#endif // AMALGAMATED_BUILD
