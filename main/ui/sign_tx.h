#ifndef UI_SIGN_TX_H_
#define UI_SIGN_TX_H_

#include "../ui.h"
#include "../utils/network.h"

typedef struct _output_info output_info_t;
struct wally_tx;

bool show_btc_transaction_outputs_activity(
    network_t network_id, const struct wally_tx* tx, const output_info_t* output_info);

bool show_btc_final_confirmation_activity(const network_t network_id, uint64_t fee, const char* warning_msg);

// Ruby (group payments with pre-signed fee levels): one screen for the same payment at several fees.
// fees[0] is the fee of the transaction being signed, fees[1..] the other fee options (at most 3).
bool show_btc_fee_options_confirmation_activity(const network_t network_id, const uint64_t* fees, size_t num_fees);

#endif /* UI_SIGN_TX_H_ */
