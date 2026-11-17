#ifndef MUSIG2_H_
#define MUSIG2_H_

// Ruby: MuSig2 (BIP327) signing for the DistributedCryptography MuSig2 groups (Advanced Delegated Multi Signature and
// Advanced Multi Signature wallets), see RUBY-GROUPS.md section 2.4.
//
// A MuSig2 input of a psbt carries (BIP373, kept by libwally among the input's unknown fields):
//   PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a): key = 0x1a || plain aggregate key (33), value = the participants'
//       compressed keys (33 each) in KeyAgg order;
//   PSBT_IN_MUSIG2_PUB_NONCE (0x1b): key = 0x1b || participant (33) || aggregate (33) [|| leaf hash (32)],
//       value = the participant's public nonce (66);
//   PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c): same key with 0x1c, value = the participant's partial signature (32).
// plus our key with its origin (PSBT_IN_TAP_BIP32_DERIVATION) and either
//   - the script path: ONE leaf script <x-only aggregate> OP_CHECKSIG with its control block, our key naming its
//     leaf hash; or
//   - the key path: the aggregate as the Taproot internal key (PSBT_IN_TAP_INTERNAL_KEY) and the merkle root of the
//     scripts (PSBT_IN_TAP_MERKLE_ROOT); no leaf hash for our key.
//
// Round 1 ('musig2_nonces', no screen): Ruby checks every such input and makes its nonces (BIP327 NonceGen with
// fresh randomness, our secret key, the BIP341 sighash and the aggregate key). The SECRET nonces stay in Ruby's RAM
// only, for one payment at a time; the public nonces are returned.
// Round 2 ('sign_psbt' with every participant's public nonce): after the user accepts the payment, Ruby makes its
// partial signature of each MuSig2 input with the secret nonces of round 1, which are wiped whatever happens.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <wally_bip32.h>
#include <wally_psbt.h>

#define MUSIG2_MAX_PARTICIPANTS 32
#define MUSIG2_MAX_INPUTS 32
#define MUSIG2_PUBNONCE_LEN 66
#define MUSIG2_PARTIAL_SIG_LEN 32
// How long the secret nonces of a payment wait for round 2
#define MUSIG2_NONCES_LIFETIME_MS (10 * 60 * 1000)

#define PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS 0x1a
#define PSBT_IN_MUSIG2_PUB_NONCE 0x1b
#define PSBT_IN_MUSIG2_PARTIAL_SIG 0x1c

// True if the input carries MuSig2 participants (0x1a): it is then signed only as a MuSig2 input
bool musig2_input_present(const struct wally_psbt_input* input);

// The key iterator's check of a MuSig2 input for our x-only key (see above): the participants aggregate to the key
// they name, our key is one of them, and the leaf (script path) or the internal key + merkle root (key path) is
// what the coin spent pays to.
bool musig2_input_check(const struct wally_psbt* psbt, size_t index, const uint8_t* xonly);

// Round 1: our public nonces, one per input (has_nonce[i] false for an input we do not sign). Replaces the nonces of
// any earlier payment. Returns false with errmsg on error (no nonce is kept then).
bool musig2_create_nonces(const struct wally_psbt* psbt, const struct wally_tx* tx,
    uint8_t (*pubnonces)[MUSIG2_PUBNONCE_LEN], bool* has_nonce, const char** errmsg);

// Round 2, for one input, after the user accepted: our partial signature with the nonces of round 1, added to the
// input as PSBT_IN_MUSIG2_PARTIAL_SIG. Uses up (wipes) our secret nonce of that input.
bool musig2_sign_input(struct wally_psbt* psbt, size_t index, const struct wally_tx* tx, const struct ext_key* hdkey,
    const char** errmsg);

// Wipes every secret nonce kept (a payment signed, declined or abandoned; the wallet locked)
void musig2_clear(void);

#endif /* MUSIG2_H_ */
