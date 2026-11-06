#ifndef AMALGAMATED_BUILD
#include <inttypes.h>
#include <wally_transaction.h>

#include "../button_events.h"
#include "../jade_assert.h"
#include "../jade_wally_verify.h"
#include "../process/sign_utils.h"
#include "../ui.h"
#include "../ui/sign_tx.h"
#include "../utils/address.h"
#include "../utils/event.h"
#include "../utils/util.h"

// from confirm_address
gui_activity_t* make_display_address_activities(const char* title, bool show_one_screen_tick, const char* address,
    bool default_selection, gui_activity_t** actaddr2);

// Note shown to highlight outputs to self (script/address verified)
static const char VERIFIED_WALLET_OUTPUT_MSG[] = "Verified wallet output";

static const char TICKER_BTC[] = "BTC";

// Don't display pre-validated (eg. change) outputs (if provided) unless they have an associated warning message.
static bool display_output(
    const struct wally_tx_output* outputs, const output_info_t* output_info, const size_t i, const bool show_scriptless)
{
    JADE_ASSERT(outputs);

    if (!show_scriptless && !outputs[i].script) {
        // Hide outputs with no script
        return false;
    }

    if (output_info) {
        if (output_info[i].message[0] != '\0') {
            // Show outputs that have an associated warning message
            return true;
        }

        if (output_info[i].flags & OUTPUT_FLAG_CHANGE) {
            // Hide change outputs which have already been internally validated
            JADE_ASSERT(output_info[i].flags & OUTPUT_FLAG_IS_OURS);
            return false;
        }
    }

    // No reason to hide this output
    return true;
}

static uint32_t displayable_outputs(
    const struct wally_tx* tx, const output_info_t* output_info, const bool show_scriptless)
{
    JADE_ASSERT(tx && tx->num_outputs <= UINT32_MAX);

    uint32_t nDisplayable = 0;
    for (size_t i = 0; i < tx->num_outputs; ++i) {
        if (display_output(tx->outputs, output_info, i, show_scriptless)) {
            ++nDisplayable;
        }
    }

    // If we would hide all outputs, then don't hide any
    return nDisplayable > 0 ? nDisplayable : (uint32_t)tx->num_outputs;
}

static gui_activity_t* make_input_output_activities(const char* title, const bool is_wallet_output,
    const bool is_address, const char* address_label, const char* amount, const char* ticker, const char* warning_msg,
    gui_activity_t** acttickeramt, gui_activity_t** actaddr1, gui_activity_t** actaddr2, gui_activity_t** actwarning)
{
    JADE_ASSERT(title);
    JADE_ASSERT(address_label);
    JADE_ASSERT(amount);
    JADE_ASSERT(ticker);
    // warning_msg is optional
    JADE_INIT_OUT_PPTR(acttickeramt);
    JADE_INIT_OUT_PPTR(actaddr1);
    JADE_INIT_OUT_PPTR(actaddr2);
    JADE_INIT_OUT_PPTR(actwarning);

    char display_str[128];
    const bool show_help_btn = false;
    gui_view_node_t* node;

    // First row, address
    gui_view_node_t* splitaddr;
    gui_view_node_t* addr;

    if (is_address) {
        // Address, show as 'To: <addr>'
        gui_make_hsplit(&splitaddr, GUI_SPLIT_RELATIVE, 2, 20, 80);

        gui_make_text(&addr, "To: ", TFT_WHITE);
        gui_set_align(addr, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
        gui_set_parent(addr, splitaddr);

        gui_make_text(&addr, address_label, TFT_WHITE);
        gui_set_align(addr, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
        gui_set_parent(addr, splitaddr);
    } else {
        // Simple label, show as '<label>' (centered)
        gui_make_text(&addr, address_label, TFT_WHITE);
        gui_set_align(addr, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        splitaddr = addr;
    }

    const bool show_tick = false;
    const bool default_selection = true;
    const char* addr_label_title = is_address ? "To Address" : "Description";
    *actaddr1
        = make_display_address_activities(addr_label_title, show_tick, address_label, default_selection, actaddr2);

    // Second row, amount + ticker
    gui_view_node_t* splitamount;
    gui_make_hsplit(&splitamount, GUI_SPLIT_RELATIVE, 2, 65, 35);

    gui_view_node_t* amountvalue;
    gui_make_text(&amountvalue, amount, TFT_WHITE);
    gui_set_align(amountvalue, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(amountvalue, splitamount);

    gui_make_text(&node, ticker, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, splitamount);

    int ret = snprintf(display_str, sizeof(display_str), "%s\n%s", amount, ticker);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    *acttickeramt = make_show_single_value_activity("Amount", display_str, show_help_btn);

    // Fourth row, warning (third row is the verified-wallet-output note)
    gui_view_node_t* warning = NULL;
    if (warning_msg) {
        gui_make_text(&warning, warning_msg, TFT_WHITE);
        gui_set_align(warning, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        *actwarning = make_show_single_value_activity("Warning", warning_msg, show_help_btn);
    }

    // Buttons - Cancel and Next
    btn_data_t hdrbtns[] = { { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_SIGNTX_REJECT },
        { .txt = ">", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_SIGNTX_ACCEPT } };

    // Screen items
    btn_data_t menubtns[] = { { .content = splitaddr, .ev_id = BTN_SIGNTX_ADDRESS },
        { .content = splitamount, .ev_id = BTN_SIGNTX_TICKERAMOUNT },
        { .content = NULL,
            .txt = is_wallet_output ? VERIFIED_WALLET_OUTPUT_MSG : NULL,
            .font = GUI_DEFAULT_FONT,
            .ev_id = GUI_BUTTON_EVENT_NONE },
        { .content = warning,
            .txt = NULL,
            .font = GUI_DEFAULT_FONT,
            .ev_id = warning ? BTN_SIGNTX_WARNING : GUI_BUTTON_EVENT_NONE } };

    const size_t num_btns = warning || is_wallet_output ? 4 : 2;
    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, num_btns);

    // Set the initially selected item to the 'Next' button
    gui_set_activity_initial_selection(hdrbtns[1].btn);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(amountvalue, true, TFT_BLACK, gui_get_highlight_color());
    gui_set_text_scroll_selected(addr, true, TFT_BLACK, gui_get_highlight_color());
    if (warning) {
        gui_set_text_scroll_selected(warning, true, TFT_BLACK, gui_get_highlight_color());
    }

    return act;
}

// Helper to make a screen activity to display an input or output for the user to verify.
// Displays a label or a destination address, passed amount (already formatted for display),
// and the associated ticker if one is passed.
//
// It can also display any warning message that may be associated with this output.
//
// It is not valid to call this with both an address and a label string (but must have one).

static bool show_input_output_activity(const char* title, const bool is_wallet_output, const bool is_address,
    const char* address_label, const char* amount, const char* ticker, const char* warning_msg)
{
    JADE_ASSERT(title);
    JADE_ASSERT(address_label);
    JADE_ASSERT(amount);
    JADE_ASSERT(ticker);
    // warning_msg is optional

    gui_activity_t* act_tickeramt = NULL;
    gui_activity_t* act_addr1 = NULL;
    gui_activity_t* act_addr2 = NULL;
    gui_activity_t* act_warning = NULL;
    gui_activity_t* act_summary = make_input_output_activities(title, is_wallet_output, is_address, address_label,
        amount, ticker, warning_msg, &act_tickeramt, &act_addr1, &act_addr2, &act_warning);
    gui_activity_t* act = act_summary;

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_SIGNTX_ACCEPT);
        switch (ev_id) {
        case BTN_BACK:
            act = (act == act_addr2) ? act_addr1 : act_summary;
            break;

        case BTN_ADDRESS_REJECT:
        case BTN_ADDRESS_ACCEPT:
            act = act_summary;
            break;

        case BTN_ADDRESS_NEXT:
            act = act_addr2;
            break;

        case BTN_SIGNTX_ADDRESS:
            act = act_addr1;
            break;

        case BTN_SIGNTX_TICKERAMOUNT:
            act = act_tickeramt;
            break;

        case BTN_SIGNTX_WARNING:
            act = act_warning;
            break;

        case BTN_SIGNTX_REJECT:
            return false;

        case BTN_SIGNTX_ACCEPT:
            return true;
        }
    }
}

bool show_btc_transaction_outputs_activity(
    const network_t network_id, const struct wally_tx* tx, const output_info_t* output_info)
{
    JADE_ASSERT(network_id != NETWORK_NONE);
    JADE_ASSERT(tx);
    // Note: output_info is optional and can be null

    // Show outputs which don't have a script
    const bool show_scriptless = true;

    // 1 based indices for display purposes
    uint32_t nDisplayedOutput = 0;
    const uint32_t nTotalOutputsDisplayed = displayable_outputs(tx, output_info, show_scriptless);
    const bool hiddenOutputs = nTotalOutputsDisplayed < tx->num_outputs;

    // NOTE: because signing potentially has a lot of output info to display
    // we deal with the outputs one at a time, rather than creating them all up-front.
    gui_activity_t* act_clear = gui_make_activity();

    for (size_t i = 0; i < tx->num_outputs; ++i) {
        struct wally_tx_output* out = tx->outputs + i;

        // Skip outputs we have automatically validated (eg. change outputs)
        if (hiddenOutputs && !display_output(tx->outputs, output_info, i, show_scriptless)) {
            continue;
        }
        ++nDisplayedOutput;

        // Free all existing activities between outputs
        gui_set_current_activity_ex(act_clear, true);

        const bool is_wallet_output = output_info && (output_info[i].flags & OUTPUT_FLAG_IS_OURS);

        char title[16];
        int ret = snprintf(title, sizeof(title), "Output %ld/%ld", nDisplayedOutput, nTotalOutputsDisplayed);
        JADE_ASSERT(ret > 0 && ret < sizeof(title));

        char amount[32];
        ret = snprintf(amount, sizeof(amount), "%.08f", 1.0 * out->satoshi / 1e8);
        JADE_ASSERT(ret > 0 && ret < sizeof(amount));

        char address[MAX_ADDRESS_LEN];
        script_to_address(network_id, out->script, out->script_len, out->satoshi > 0, address, sizeof(address));
        const bool is_address = true;

        // Show output info
        const char* msg = (output_info && strlen(output_info[i].message) > 0) ? output_info[i].message : NULL;
        if (!show_input_output_activity(
                title, is_wallet_output, is_address, address, amount, TICKER_BTC, msg)) {
            // User pressed 'cancel'
            return false;
        }
        // else user pressed 'next', continue to next output
    }

    // All outputs confirmed
    JADE_ASSERT(nDisplayedOutput == nTotalOutputsDisplayed);
    return true;
}

// Screens to confirm the fee / signing the tx
static gui_activity_t* make_final_confirmation_activities(const char* title, const char* feeamount, const char* ticker,
    const char* warning_msg, gui_activity_t** actfeeamt, gui_activity_t** actwarning)
{
    JADE_ASSERT(title);
    JADE_ASSERT(feeamount);
    JADE_ASSERT(ticker);
    // warning msg is optional
    JADE_INIT_OUT_PPTR(actfeeamt);
    JADE_INIT_OUT_PPTR(actwarning);

    char display_str[128];
    const bool show_help_btn = false;
    gui_view_node_t* node;

    // First row, fee amount + ticker
    gui_view_node_t* splitfee;
    gui_make_hsplit(&splitfee, GUI_SPLIT_RELATIVE, 3, 18, 52, 30);

    gui_make_text(&node, "Fee:", TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, splitfee);

    gui_view_node_t* amountvalue;
    gui_make_text(&amountvalue, feeamount, TFT_WHITE);
    gui_set_align(amountvalue, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(amountvalue, splitfee);

    gui_make_text(&node, ticker, TFT_WHITE);
    gui_set_align(node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, splitfee);

    int ret = snprintf(display_str, sizeof(display_str), "%s\n%s", feeamount, ticker);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    *actfeeamt = make_show_single_value_activity("Fee Amount", display_str, show_help_btn);

    // Second row, warning
    gui_view_node_t* warning = NULL;
    if (warning_msg) {
        gui_make_text(&warning, warning_msg, TFT_WHITE);
        gui_set_align(warning, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

        *actwarning = make_show_single_value_activity("Warning", warning_msg, show_help_btn);
    }

    // Buttons - Cancel and Confirm
    btn_data_t hdrbtns[] = { { .txt = "X", .font = GUI_TITLE_FONT, .ev_id = BTN_SIGNTX_REJECT },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = BTN_SIGNTX_ACCEPT /**/ BTN_IS_CRITICAL } };

    btn_data_t menubtns[] = {
        { .content = splitfee, .ev_id = BTN_SIGNTX_TICKERAMOUNT },
        { .content = warning, .font = GUI_DEFAULT_FONT, .ev_id = warning ? BTN_SIGNTX_WARNING : GUI_BUTTON_EVENT_NONE }
    };

    gui_activity_t* const act = make_menu_activity(title, hdrbtns, 2, menubtns, 2);

    // NOTE: can only set scrolling *after* gui tree created
    gui_set_text_scroll_selected(amountvalue, true, TFT_BLACK, gui_get_highlight_color());
    if (warning) {
        gui_set_text_scroll_selected(warning, true, TFT_BLACK, gui_get_highlight_color());
    }

    return act;
}

static bool show_final_confirmation_activity(
    const char* title, const char* feeamount, const char* ticker, const char* warning_msg)
{
    JADE_ASSERT(title);
    JADE_ASSERT(feeamount);
    JADE_ASSERT(ticker);
    // warning_msg is optional

    // final confirmation screen
    gui_activity_t* act_feeamt = NULL;
    gui_activity_t* act_warning = NULL;
    gui_activity_t* const act_summary
        = make_final_confirmation_activities(title, feeamount, ticker, warning_msg, &act_feeamt, &act_warning);
    gui_activity_t* act = act_summary;

    while (true) {
        gui_set_current_activity(act);

        const int32_t ev_id = gui_activity_wait_button(act, BTN_SIGNTX_ACCEPT);
        switch (ev_id) {
        case BTN_BACK:
            act = act_summary;
            break;

        case BTN_SIGNTX_TICKERAMOUNT:
            act = act_feeamt;
            break;

        case BTN_SIGNTX_WARNING:
            act = act_warning;
            break;

        case BTN_SIGNTX_REJECT:
            return false;

        case BTN_SIGNTX_ACCEPT:
            return true;
        }
    }
}

bool show_btc_final_confirmation_activity(const network_t network_id, const uint64_t fee, const char* warning_msg)
{
    JADE_ASSERT(network_id != NETWORK_NONE);

    char feeamount[32];
    const int ret = snprintf(feeamount, sizeof(feeamount), "%.08f", 1.0 * fee / 1e8);
    JADE_ASSERT(ret > 0 && ret < sizeof(feeamount));

    return show_final_confirmation_activity("Send Transaction", feeamount, TICKER_BTC, warning_msg);
}

#endif // AMALGAMATED_BUILD
