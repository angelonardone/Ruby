/*
 * Parse a PSBT exactly as Ruby does for sign_psbt and musig2_nonces
 * (main/process/sign_psbt.c, deserialise_psbt(): STRICT | COMPLETE), then serialise it
 * back as serialise_psbt() does. libwally's own fuzz_psbt_from_bytes covers the other
 * flag combinations.
 *
 * Properties checked besides memory safety:
 * - when the PSBT serialises, its serialisation parses again with Ruby's flags and gives
 *   the same bytes once more (what Ruby returns to the host is a PSBT Ruby would accept);
 * - with -DRUBY_REQUIRE_SERIALISABLE: every PSBT Ruby accepts can be serialised.
 *   Off for now: libwally (1.5.6 and master of 2026-11-18) accepts a PSBT whose
 *   non_witness_utxo has no outputs but refuses to serialise it, so Ruby would show the
 *   payment, let the user confirm it, then answer "Failed to serialise sign psbt".
 *   Finding F2 in fuzz/README.md. Turn it on together with the firmware check proposed
 *   there (deserialise_psbt() refusing a PSBT that does not serialise).
 */
#include <stdlib.h>
#include <string.h>
#include <wally_psbt.h>

static const uint32_t RUBY_PSBT_FLAGS = WALLY_PSBT_PARSE_FLAG_STRICT | WALLY_PSBT_PARSE_FLAG_COMPLETE;

/* serialise_psbt() of main/process/sign_psbt.c, on the host heap. */
static unsigned char *serialise(const struct wally_psbt *psbt, size_t *out_len)
{
    size_t len = 0, written = 0;
    unsigned char *bytes;

    if (wally_psbt_get_length(psbt, 0, &len) != WALLY_OK || !len)
        return NULL;
    if (!(bytes = malloc(len)))
        abort();
    if (wally_psbt_to_bytes(psbt, 0, bytes, len, &written) != WALLY_OK || written != len) {
        free(bytes);
        return NULL;
    }
    *out_len = len;
    return bytes;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct wally_psbt *psbt = NULL, *again = NULL;
    unsigned char *bytes, *bytes2;
    size_t len = 0, len2 = 0;

    if (wally_psbt_from_bytes(data, size, RUBY_PSBT_FLAGS, &psbt) != WALLY_OK || !psbt)
        return 0;

    if (!(bytes = serialise(psbt, &len))) {
#ifdef RUBY_REQUIRE_SERIALISABLE
        abort(); /* Ruby accepted a PSBT it cannot send back */
#endif
        wally_psbt_free(psbt);
        return 0;
    }

    if (wally_psbt_from_bytes(bytes, len, RUBY_PSBT_FLAGS, &again) != WALLY_OK || !again)
        abort(); /* Ruby would send back a PSBT that Ruby itself refuses */
    if (!(bytes2 = serialise(again, &len2)) || len2 != len || memcmp(bytes, bytes2, len))
        abort(); /* serialisation is not stable */

    free(bytes2);
    wally_psbt_free(again);
    free(bytes);
    wally_psbt_free(psbt);
    return 0;
}
