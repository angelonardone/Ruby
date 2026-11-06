#ifndef AMALGAMATED_BUILD
#include "sign_utils.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../ui/sign_tx.h"
#include "../utils/cbor_rpc.h"
#include "../utils/malloc_ext.h"
#include "../utils/util.h"

#include <sodium/utils.h>

#include "process_utils.h"

bool params_txn_validate(const struct wally_tx* const tx, const char** errmsg)
{
    JADE_ASSERT(tx);
    JADE_INIT_OUT_PPTR(errmsg);

    // Reject empty transactions. A tx must have at least one input and one
    // output - this also guarantees a non-zero output count for later processing.
    if (!tx->num_inputs || !tx->num_outputs) {
        *errmsg = "Transaction has no inputs or outputs";
        return false;
    }

    if (tx->num_inputs > MAX_TX_INPUTS) {
        *errmsg = "Too many transaction inputs";
        return false;
    }
    if (tx->num_outputs > MAX_TX_OUTPUTS) {
        *errmsg = "Too many transaction outputs";
        return false;
    }
    return true;
}

bool sighash_is_supported(const uint32_t sig_type, const uint32_t sighash)
{
    if (sig_type == WALLY_SIGTYPE_SW_V1) {
        // Taproot: must be ALL or DEFAULT
        return sighash == WALLY_SIGHASH_DEFAULT || sighash == WALLY_SIGHASH_ALL;
    }
    // All other cases must be ALL at present
    return sighash == WALLY_SIGHASH_ALL;
}

bool show_btc_fee_confirmation_activity(const network_t network_id, const struct wally_tx* tx,
    const output_info_t* outinfo, const script_flavour_t aggregate_inputs_scripts_flavour, const uint64_t input_amount,
    const uint64_t output_amount)
{
    JADE_ASSERT(tx);
    // outputinfo is optional
    JADE_ASSERT(input_amount);
    JADE_ASSERT(output_amount);

    JADE_ASSERT(input_amount >= output_amount);

    // User to agree fee amount
    // The fee amount is the shortfall between input and output amounts
    // The 'spend' amount is the total of the outputs not flagged as change
    const uint64_t fees = input_amount - output_amount;
    uint64_t spend_amount = output_amount;
    if (outinfo) {
        for (size_t i = 0; i < tx->num_outputs; ++i) {
            if (outinfo[i].flags & OUTPUT_FLAG_CHANGE) {
                // Deduct change output amount
                JADE_ASSERT(spend_amount >= tx->outputs[i].satoshi);
                spend_amount -= tx->outputs[i].satoshi;
            }
        }
    }

    char warnbuf[128]; // sufficient
    const char* warning_msg = NULL;
    const bool warn_fees = fees && fees >= spend_amount;
    const bool warn_scripts = aggregate_inputs_scripts_flavour == SCRIPT_FLAVOUR_MIXED;
    if (warn_fees && warn_scripts) {
        const int retval = snprintf(warnbuf, sizeof(warnbuf), "%s %s", WARN_MSG_HIGH_FEES, WARN_MSG_MIXED_INPUTS);
        JADE_ASSERT(retval > 0 && retval < sizeof(warnbuf));
        warning_msg = warnbuf;
    } else if (warn_scripts) {
        warning_msg = WARN_MSG_MIXED_INPUTS;
    } else if (warn_fees) {
        warning_msg = WARN_MSG_HIGH_FEES;
    }

    // Return whether the user accepts or declines
    return show_btc_final_confirmation_activity(network_id, fees, warning_msg);
}
#endif // AMALGAMATED_BUILD
