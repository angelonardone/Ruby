/*
 * RPC 'restore_seed_data' (main/process/restore_seed.c): the wallet sends the 64-byte BIP32 seed encrypted to
 * Ruby's ephemeral key ("BIE1", NBitcoin PubKey.Encrypt). restore_seed_decrypt() is the only code that reads those
 * host bytes before the user sees anything. The real firmware file is compiled here (fuzz/README.md, "Firmware
 * code on the host"); Ruby's ephemeral key is a fixed test key.
 *
 * The first input byte picks the mode:
 *
 * even: RAW. The rest is the "seed" field as the host sends it. Checked: memory safety, the sensitive stack is
 *       empty afterwards, and a refused input leaves no output.
 *
 * odd:  VALID. The input gives the seed and the wallet's ephemeral key; the harness encrypts the seed as the
 *       wallet does (format of NBitcoin PubKey.Encrypt, written here from its definition) and checks that:
 *       - Ruby decrypts it to the same seed;
 *       - any changed byte (input-chosen position and value) is refused (the HMAC covers everything);
 *       - one byte more or less is refused;
 *       - another Ruby key cannot decrypt it.
 */
#include "fw_amalgam.h"

#include "../../main/codex32.c"
#include "../../main/process/seed_split.c"
#include "../../main/process/restore_seed.c"

#include "firmware_stubs.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t RUBY_PRIV[EC_PRIVATE_KEY_LEN] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11 };
static const uint8_t OTHER_PRIV[EC_PRIVATE_KEY_LEN] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22 };

static bool decrypt(const uint8_t* privkey, const uint8_t* enc, const size_t enc_len, uint8_t* seed)
{
    uint8_t out[RESTORE_SEED_CIPHER_LEN];
    memset(out, 0xa5, sizeof(out));
    const bool ok = restore_seed_decrypt(privkey, enc, enc_len, out, sizeof(out));
    if (fuzz_sensitive_depth())
        abort(); /* a SENSITIVE_PUSH was not popped */
    if (ok && seed)
        memcpy(seed, out, RESTORE_SEED_LEN);
    return ok;
}

/* NBitcoin PubKey.Encrypt of 'msg' to 'pubkey' with the ephemeral key 'eph': "BIE1" | eph pubkey |
 * AES-128-CBC (PKCS#7; iv = K[0..16], key = K[16..32]) | HMAC-SHA256 (key K[32..64]) of all before,
 * K = SHA512(compressed ECDH point). */
static size_t wallet_encrypt(const uint8_t* eph, const uint8_t* pubkey, const uint8_t* msg, const size_t msg_len,
    uint8_t* out, const size_t out_len)
{
    uint8_t keys[SHA512_LEN];
    if (!bie1_shared_keys(eph, pubkey, keys, sizeof(keys)))
        abort();
    memcpy(out, "BIE1", 4);
    if (wally_ec_public_key_from_private_key(eph, EC_PRIVATE_KEY_LEN, out + 4, EC_PUBLIC_KEY_LEN) != WALLY_OK)
        abort();
    size_t written = 0;
    const size_t cipher_len = AES_PADDED_LEN(msg_len);
    if (4 + EC_PUBLIC_KEY_LEN + cipher_len + HMAC_SHA256_LEN > out_len
        || wally_aes_cbc(keys + 16, 16, keys, 16, msg, msg_len, AES_FLAG_ENCRYPT, out + 4 + EC_PUBLIC_KEY_LEN,
               cipher_len, &written)
            != WALLY_OK
        || written != cipher_len)
        abort();
    const size_t len = 4 + EC_PUBLIC_KEY_LEN + cipher_len + HMAC_SHA256_LEN;
    if (wally_hmac_sha256(keys + 32, 32, out, len - HMAC_SHA256_LEN, out + len - HMAC_SHA256_LEN, HMAC_SHA256_LEN)
        != WALLY_OK)
        abort();
    return len;
}

static void fuzz_raw(const uint8_t* data, const size_t size)
{
    uint8_t seed[RESTORE_SEED_LEN];
    decrypt(RUBY_PRIV, size ? data : NULL, size, seed);
}

static void fuzz_valid(const uint8_t* data, const size_t size)
{
    uint8_t in[RESTORE_SEED_LEN + EC_PRIVATE_KEY_LEN + 4] = { 0 };
    memcpy(in, data, size < sizeof(in) ? size : sizeof(in));
    const uint8_t* seed = in;
    uint8_t eph[EC_PRIVATE_KEY_LEN];
    memcpy(eph, in + RESTORE_SEED_LEN, sizeof(eph));
    if (wally_ec_private_key_verify(eph, sizeof(eph)) != WALLY_OK)
        memcpy(eph, OTHER_PRIV, sizeof(eph)); /* any valid wallet key will do */
    const uint8_t* tamper = in + RESTORE_SEED_LEN + EC_PRIVATE_KEY_LEN;

    uint8_t ruby_pub[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_from_private_key(RUBY_PRIV, sizeof(RUBY_PRIV), ruby_pub, sizeof(ruby_pub)) != WALLY_OK)
        abort();

    uint8_t enc[RESTORE_SEED_BIE1_LEN + 1];
    const size_t enc_len = wallet_encrypt(eph, ruby_pub, seed, RESTORE_SEED_LEN, enc, sizeof(enc));
    if (enc_len != RESTORE_SEED_BIE1_LEN)
        abort();

    uint8_t out[RESTORE_SEED_LEN];
    if (!decrypt(RUBY_PRIV, enc, enc_len, out) || memcmp(out, seed, RESTORE_SEED_LEN))
        abort(); /* the wallet's encryption does not decrypt to the same seed */

    if (decrypt(OTHER_PRIV, enc, enc_len, NULL))
        abort(); /* decrypted with a key it was not encrypted to */

    if (decrypt(RUBY_PRIV, enc, enc_len - 1, NULL))
        abort(); /* one byte short */
    enc[enc_len] = tamper[2];
    if (decrypt(RUBY_PRIV, enc, enc_len + 1, NULL))
        abort(); /* one byte more */

    const size_t pos = ((size_t)tamper[0] << 8 | tamper[1]) % enc_len;
    const uint8_t flip = tamper[3] ? tamper[3] : 0x01;
    enc[pos] ^= flip;
    if (decrypt(RUBY_PRIV, enc, enc_len, NULL))
        abort(); /* a changed byte was accepted */
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!size)
        return 0;
    fuzz_random_set(NULL, 0);
    if (data[0] & 1)
        fuzz_valid(data + 1, size - 1);
    else
        fuzz_raw(data + 1, size - 1);
    return 0;
}
