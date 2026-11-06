#ifndef SIGN_UTILS_H_
#define SIGN_UTILS_H_

#include "../jade_assert.h"
#include "process_utils.h"

typedef struct _output_info {
    char message[128];
    uint8_t flags;
} output_info_t;

// Maximum number of inputs/outputs accepted
#define MAX_TX_INPUTS 256
#define MAX_TX_OUTPUTS 64

WARN_UNUSED_RESULT bool params_txn_validate(const struct wally_tx* const tx, const char** errmsg);

// Whether or not the sighash flags for a given signature type is supported
bool sighash_is_supported(uint32_t sig_type, uint32_t sighash);

bool show_btc_fee_confirmation_activity(network_t network_id, const struct wally_tx* tx, const output_info_t* outinfo,
    script_flavour_t aggregate_inputs_scripts_flavour, uint64_t input_amount, uint64_t output_amount);

#endif /* SIGN_UTILS_H_ */
