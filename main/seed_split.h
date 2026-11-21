#ifndef SEED_SPLIT_H_
#define SEED_SPLIT_H_

// Ruby: Wallet Backup and Time Encrypted Vault of a Ruby wallet (RPC 'seed_split', process/seed_split.c).
//
// The BIP32 seed Ruby stores is split ON Ruby with codex32 (BIP-93, codex32.h) among the contacts of the group,
// and each contact's shares leave Ruby already encrypted to that contact, in the format of the wallet's
// DistributedCryptographyLib.EncryptJsonTo:
//   text = AES-256-GCM of the JSON array of the contact's codex32 strings ["ms1...","ms1..."] with a random key:
//          nonce (12) | ciphertext | tag (16)                    (EncryptionService.Encrypt)
//   key  = that key, as its base64 string (44 chars), ECIES-encrypted to the contact's public key:
//          "BIE1" | ephemeral pubkey (33) | AES-128-CBC (48) | HMAC-SHA256 (32)   (NBitcoin PubKey.Encrypt)
// The wallet base64-encodes both and stores them as the contact's encryptedKey / encryptedText, so the members'
// restore (DecryptJsonFor + codex32 combine) is the same as for a software wallet. The computer sees neither
// the seed nor a share.
//
// mode "backup": the seed itself is split (Wallet Backup).
// mode "vault":  Ruby draws a random pad, returns masked = seed XOR pad and splits the pad (Time Encrypted Vault:
//                the wallet encrypts 'masked' with the vault KEY, as Codex32Processor.MaskSeed for a software
//                wallet). Neither 'masked' nor the pad says anything about the seed alone.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_crypto.h>

#include "codex32.h"

#define SEED_SPLIT_MAX_CONTACTS CODEX32_MAX_SHARES
#define SEED_SPLIT_MAX_NAME_LEN 32

typedef struct {
    char name[SEED_SPLIT_MAX_NAME_LEN + 1]; // shown on Ruby (non-printable characters shown as '?')
    uint8_t pubkey[EC_PUBLIC_KEY_LEN]; // the contact's key the shares are encrypted to
    size_t num_shares; // how many codex32 shares this contact gets (its votes)
} seed_split_contact_t;

// NBitcoin PubKey.Encrypt / Key.Decrypt ("BIE1"): SHA512 of the compressed ECDH point of 'privkey' and 'pubkey'
// (iv = [0..16], AES-128-CBC key = [16..32], HMAC-SHA256 key = [32..64])
bool bie1_shared_keys(const uint8_t* privkey, const uint8_t* pubkey, uint8_t* keys, size_t keys_len);

// Ruby: RPC 'restore_seed' (process/restore_seed.c) loads a seed recovered by a Wallet Backup / TEV group into a
// Ruby with no wallet. The screen shows the fingerprint of the recovered wallet; false if declined.
bool show_restore_seed_activity(const uint8_t* fingerprint, size_t fingerprint_len);

// The screens: the split (k of n, contacts), then every contact (name, shares, key); false if any is declined
bool show_seed_split_activity(
    bool vault, size_t threshold, size_t total_shares, const seed_split_contact_t* contacts, size_t num_contacts);

#endif /* SEED_SPLIT_H_ */
