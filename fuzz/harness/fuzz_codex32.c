/*
 * main/codex32.c (BIP-93), built as it is for the device. Ruby splits the wallet seed with it (seed_split) and the
 * wallet combines the shares again, so both directions are checked.
 *
 * The first input byte picks the mode:
 *
 * even: COMBINE. The rest is text, one codex32 string per line (at most 33 lines), given to
 *       codex32_combine_seed() as the strings a user could type. Checked: memory safety, and that an accepted
 *       set gives a seed of a size BIP-93 allows.
 *
 * odd:  SPLIT, then COMBINE. The input picks the seed size and bytes, the threshold k, the number of shares n,
 *       the identifier (or a random one), the "random" bytes of the split and which shares to use. Checked:
 *       - the split succeeds and every share is "ms1" + k + the identifier, lowercase, of the right length;
 *       - any k distinct shares (in any order, also in UPPERCASE) give the seed back;
 *       - all n shares together give the seed back (the extra ones are cross-checked);
 *       - k-1 shares are refused;
 *       - 1 to 4 changed characters in one share are always detected (BIP-93: the checksum detects up to 8).
 */
#include "../../main/codex32.c"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ---- the "random" bytes of the split come from the fuzz input ---- */

static const uint8_t *rnd_data;
static size_t rnd_len, rnd_pos;

static void fuzz_random(uint8_t *buf, const size_t len)
{
    for (size_t i = 0; i < len; ++i, ++rnd_pos)
        buf[i] = rnd_len ? rnd_data[rnd_pos % rnd_len] ^ (uint8_t)(rnd_pos / rnd_len) : (uint8_t)rnd_pos;
}

/* ---- input reader ---- */

typedef struct {
    const uint8_t *p;
    size_t len, pos;
} reader_t;

static uint8_t next_byte(reader_t *r) { return r->pos < r->len ? r->p[r->pos++] : 0; }

/* ---- COMBINE of arbitrary text ---- */

static void fuzz_combine_text(const uint8_t *data, const size_t size)
{
    enum { MAX_LINES = CODEX32_MAX_SHARES + 2, MAX_LINE = 160 };
    static char lines[MAX_LINES][MAX_LINE + 1];
    const char *ptrs[MAX_LINES];
    size_t n = 0, col = 0;

    for (size_t i = 0; i <= size && n < MAX_LINES; ++i) {
        if (i == size || data[i] == '\n') {
            lines[n][col] = '\0';
            ptrs[n] = lines[n];
            ++n;
            col = 0;
        } else if (col < MAX_LINE) {
            lines[n][col++] = (char)data[i];
        }
    }

    uint8_t seed[CODEX32_MAX_SEED_LEN];
    size_t seed_len = 0;
    if (codex32_combine_seed(ptrs, n, seed, sizeof(seed), &seed_len)) {
        if (!codex32_string_len(seed_len))
            abort(); /* accepted, but not a seed size of BIP-93 */
    } else if (seed_len) {
        abort(); /* refused, but a length was left */
    }
}

/* ---- SPLIT then COMBINE ---- */

static bool combine_is(const char *const *ptrs, const size_t n, const uint8_t *seed, const size_t seed_len)
{
    uint8_t out[CODEX32_MAX_SEED_LEN];
    size_t out_len = 0;
    return codex32_combine_seed(ptrs, n, out, sizeof(out), &out_len) && out_len == seed_len
        && !memcmp(out, seed, seed_len);
}

static void fuzz_split_combine(const uint8_t *data, const size_t size)
{
    static const size_t SEED_LENS[] = { 16, 20, 24, 28, 32, 64 };
    static char shares[CODEX32_MAX_SHARES][CODEX32_STRING_BUFLEN];
    static char upper[CODEX32_MAX_SHARES][CODEX32_STRING_BUFLEN];
    reader_t r = { data, size, 0 };

    const size_t seed_len = SEED_LENS[next_byte(&r) % 6];
    const size_t k = CODEX32_MIN_THRESHOLD + next_byte(&r) % (CODEX32_MAX_THRESHOLD - CODEX32_MIN_THRESHOLD + 1);
    const size_t n = k + next_byte(&r) % (CODEX32_MAX_SHARES - k + 1);
    const uint8_t flags = next_byte(&r);
    char identifier[5] = { 0 };
    for (int i = 0; i < 4; ++i) {
        const char ch = C32_CHARSET[next_byte(&r) % 32];
        identifier[i] = (flags & 2) ? (char)toupper((unsigned char)ch) : ch;
    }
    uint8_t seed[CODEX32_MAX_SEED_LEN];
    for (size_t i = 0; i < seed_len; ++i)
        seed[i] = next_byte(&r);
    /* which shares to combine, and the changed characters, come next; the rest feeds the "random" bytes */
    uint8_t pick[CODEX32_MAX_SHARES + 16];
    for (size_t i = 0; i < sizeof(pick); ++i)
        pick[i] = next_byte(&r);
    rnd_data = r.p + r.pos;
    rnd_len = r.len - r.pos;
    rnd_pos = 0;

    if (!codex32_split_seed(seed, seed_len, k, n, (flags & 1) ? identifier : NULL, fuzz_random, shares))
        abort(); /* valid parameters refused */

    const size_t len = codex32_string_len(seed_len);
    for (size_t i = 0; i < n; ++i) {
        if (strlen(shares[i]) != len || memcmp(shares[i], "ms1", 3) || shares[i][3] != (char)('0' + k))
            abort();
        if ((flags & 1) && strncasecmp(shares[i] + 4, identifier, 4))
            abort();
        for (size_t c = 3; c < len; ++c)
            if (!strchr(C32_CHARSET, shares[i][c]))
                abort();
        for (size_t c = 0; c <= len; ++c)
            upper[i][c] = (char)toupper((unsigned char)shares[i][c]);
    }

    /* k distinct shares, picked and ordered by the input (a partial Fisher-Yates shuffle) */
    size_t order[CODEX32_MAX_SHARES];
    for (size_t i = 0; i < n; ++i)
        order[i] = i;
    for (size_t i = 0; i < k; ++i) {
        const size_t j = i + pick[i] % (n - i);
        const size_t t = order[i];
        order[i] = order[j];
        order[j] = t;
    }
    const char *ptrs[CODEX32_MAX_SHARES];
    for (size_t i = 0; i < k; ++i)
        ptrs[i] = shares[order[i]];
    if (!combine_is(ptrs, k, seed, seed_len))
        abort(); /* k shares do not give the seed back */
    for (size_t i = 0; i < k; ++i)
        ptrs[i] = upper[order[i]];
    if (!combine_is(ptrs, k, seed, seed_len))
        abort(); /* the same in uppercase */
    for (size_t i = 0; i < k; ++i)
        ptrs[i] = shares[order[i]];
    if (combine_is(ptrs, k - 1, seed, seed_len))
        abort(); /* k-1 shares were enough */

    for (size_t i = 0; i < n; ++i)
        ptrs[i] = shares[i];
    if (!combine_is(ptrs, n, seed, seed_len))
        abort(); /* all n shares refused */

    /* change 1..4 characters of one of the k shares: always detected */
    static char changed[CODEX32_STRING_BUFLEN];
    const size_t victim = pick[CODEX32_MAX_SHARES] % k;
    memcpy(changed, shares[order[victim]], len + 1);
    const size_t nchanges = 1 + pick[CODEX32_MAX_SHARES + 1] % 4;
    for (size_t c = 0; c < nchanges; ++c) {
        const size_t pos = 3 + (pick[CODEX32_MAX_SHARES + 2 + 2 * c] * 7 + c * 31) % (len - 3);
        const int old = c32_charset_index(changed[pos]);
        const int add = 1 + pick[CODEX32_MAX_SHARES + 3 + 2 * c] % 31;
        changed[pos] = C32_CHARSET[(old + add) % 32];
    }
    if (memcmp(changed, shares[order[victim]], len)) {
        for (size_t i = 0; i < k; ++i)
            ptrs[i] = i == victim ? changed : shares[order[i]];
        uint8_t out[CODEX32_MAX_SEED_LEN];
        size_t out_len = 0;
        if (codex32_combine_seed(ptrs, k, out, sizeof(out), &out_len))
            abort(); /* a share with 1-4 wrong characters was accepted */
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size)
        return 0;
    if (data[0] & 1)
        fuzz_split_combine(data + 1, size - 1);
    else
        fuzz_combine_text(data + 1, size - 1);
    return 0;
}
