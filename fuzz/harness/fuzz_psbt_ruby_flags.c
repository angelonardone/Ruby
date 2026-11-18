/*
 * Parse a PSBT exactly as Ruby does for sign_psbt and musig2_nonces
 * (main/process/sign_psbt.c, deserialise_psbt(): STRICT | COMPLETE), then serialise it
 * back as serialise_psbt() does. libwally's own fuzz_psbt_from_bytes covers the other
 * flag combinations.
 *
 * Properties checked besides memory safety, on every PSBT deserialise_psbt() accepts
 * (STRICT | COMPLETE parse that also serialises back: the check added for finding F2):
 * - its serialisation parses again with Ruby's flags (what Ruby returns to the host is a
 *   PSBT Ruby would accept);
 * - serialising that again gives the same bytes (serialisation is stable).
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
        /* deserialise_psbt() refuses it (finding F2): nothing more to check */
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
