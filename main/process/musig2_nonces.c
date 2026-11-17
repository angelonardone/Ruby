#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../keychain.h"
#include "../musig2.h"
#include "../process.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../utils/network.h"
#include "../wallet.h"

#include "process_utils.h"
#include "sign_utils.h"

#include <wally_psbt.h>

// Ruby: MuSig2 round 1 of a DistributedCryptography group payment (see musig2.h and RUBY-GROUPS.md 2.4).
//
// params: network, psbt (bytes): the unsigned payment with its MuSig2 inputs (participants, our key with its
//         origin, the leaf or the internal key + merkle root)
// result: an array with one entry per input: our 66-byte public nonce, or empty bytes for an input Ruby does not sign
//
// Nothing is shown: making nonces signs nothing. The secret nonces stay in Ruby's RAM for the 'sign_psbt' of the same
// payment (round 2, where the user accepts it), and are replaced by the next 'musig2_nonces'.

bool deserialise_psbt(const uint8_t* bytes, size_t bytes_len, struct wally_psbt** psbt_out);

typedef struct {
    const uint8_t (*pubnonces)[MUSIG2_PUBNONCE_LEN];
    const bool* has_nonce;
    size_t num_inputs;
} musig2_nonces_reply_t;

void reply_musig2_nonces(const void* ctx, CborEncoder* container)
{
    JADE_ASSERT(ctx);
    const musig2_nonces_reply_t* reply = (const musig2_nonces_reply_t*)ctx;

    CborEncoder array_encoder;
    CborError cberr = cbor_encoder_create_array(container, &array_encoder, reply->num_inputs);
    JADE_ASSERT(cberr == CborNoError);
    for (size_t i = 0; i < reply->num_inputs; ++i) {
        cberr = cbor_encode_byte_string(
            &array_encoder, reply->pubnonces[i], reply->has_nonce[i] ? MUSIG2_PUBNONCE_LEN : 0);
        JADE_ASSERT(cberr == CborNoError);
    }
    cberr = cbor_encoder_close_container(container, &array_encoder);
    JADE_ASSERT(cberr == CborNoError);
}

void musig2_nonces_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    struct wally_psbt* psbt = NULL;
    struct wally_tx* tx = NULL;
    uint8_t(*pubnonces)[MUSIG2_PUBNONCE_LEN] = NULL;
    bool* has_nonce = NULL;
    uint8_t* buf = NULL;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "musig2_nonces");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    const uint8_t* bytes = NULL;
    size_t bytes_len = 0;
    rpc_get_bytes_ptr("psbt", &params, &bytes, &bytes_len);
    if (!bytes || !bytes_len || !deserialise_psbt(bytes, bytes_len, &psbt)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract psbt from parameters");
        goto cleanup;
    }
    if (psbt->version == WALLY_PSBT_VERSION_0) {
        tx = psbt->tx;
    } else if (wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx) != WALLY_OK) {
        tx = NULL;
    }
    const char* errmsg = NULL;
    if (!tx || !params_txn_validate(tx, &errmsg)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, errmsg ? errmsg : "Failed to extract valid txn from passed psbt");
        goto cleanup;
    }
    if (psbt->num_inputs > MUSIG2_MAX_INPUTS) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, "Too many inputs for a MuSig2 payment");
        goto cleanup;
    }

    pubnonces = JADE_CALLOC(psbt->num_inputs, MUSIG2_PUBNONCE_LEN);
    has_nonce = JADE_CALLOC(psbt->num_inputs, sizeof(bool));
    if (!musig2_create_nonces(psbt, tx, pubnonces, has_nonce, &errmsg)) {
        jade_process_reject_message(process, CBOR_RPC_BAD_PARAMETERS, errmsg);
        goto cleanup;
    }

    const musig2_nonces_reply_t reply
        = { .pubnonces = (const uint8_t(*)[MUSIG2_PUBNONCE_LEN])pubnonces, .has_nonce = has_nonce, .num_inputs = psbt->num_inputs };
    const size_t buflen = 64 + psbt->num_inputs * (MUSIG2_PUBNONCE_LEN + 4);
    buf = JADE_MALLOC(buflen);
    jade_process_reply_to_message_result(&process->ctx, buf, buflen, &reply, reply_musig2_nonces);
    JADE_LOGI("Success");

cleanup:
    free(buf);
    free(has_nonce);
    free(pubnonces);
    if (tx && psbt && psbt->version != WALLY_PSBT_VERSION_0) {
        JADE_WALLY_VERIFY(wally_tx_free(tx));
    }
    if (psbt) {
        JADE_WALLY_VERIFY(wally_psbt_free(psbt));
    }
}
#endif // AMALGAMATED_BUILD
