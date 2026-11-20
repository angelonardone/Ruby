#ifndef AMALGAMATED_BUILD
#include "codex32.h"

#include <string.h>

// Ruby: codex32 (BIP-93), see codex32.h. Follows the Python reference of the BIP (and Codex32.cs) step by step.

static const char C32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Share indexes in the order they are handed out (bech32 letters in alphabetical order, then digits; no 's')
static const char C32_SHARE_INDEXES[] = "acdefghjklmnpqrtuvwxyz023456789";

// Data part (5-bit values, no checksum): [0] threshold, [1..4] identifier, [5] share index, [6..] payload.
// The longest payload is 103 symbols (64-byte seed).
#define CODEX32_HEADER_LEN 6
#define CODEX32_MAX_PAYLOAD_LEN 103
#define CODEX32_MAX_DATA_LEN (CODEX32_HEADER_LEN + CODEX32_MAX_PAYLOAD_LEN)
#define CODEX32_HRP_EXPANDED_LEN 5 // bech32_hrp_expand("ms")
#define CODEX32_SHORT_CHECKSUM_LEN 13
#define CODEX32_LONG_CHECKSUM_LEN 15

typedef struct {
    uint8_t data[CODEX32_MAX_DATA_LEN];
    size_t len;
} codex32_data_t;

// ---- small helpers ----

static void codex32_wipe(void* p, const size_t len)
{
    volatile uint8_t* v = (volatile uint8_t*)p;
    for (size_t i = 0; i < len; ++i) {
        v[i] = 0;
    }
}

static int c32_charset_index(const char ch)
{
    for (int i = 0; i < 32; ++i) {
        if (C32_CHARSET[i] == ch) {
            return i;
        }
    }
    return -1;
}

// ---- checksum (BCH code): residues of up to 75 bits, kept as hi:lo ----

typedef struct {
    uint64_t hi;
    uint64_t lo;
} c32_u128_t;

// Regular checksum (13 characters)
static const c32_u128_t C32_REGULAR_CONST = { 0x1, 0x0ce0795c2fd1e62aULL };
static const c32_u128_t C32_REGULAR_GEN[5] = {
    { 0x1, 0x9dc500ce73fde210ULL },
    { 0x1, 0xbfae00def77fe529ULL },
    { 0x1, 0xfbd920fffe7bee52ULL },
    { 0x1, 0x739640bdeee3fdadULL },
    { 0x0, 0x7729a039cfc75f5aULL },
};
static const c32_u128_t C32_REGULAR_MASK = { 0x0, 0x0fffffffffffffffULL };

// Long checksum (15 characters, 64-byte seeds)
static const c32_u128_t C32_LONG_CONST = { 0x433, 0x81e570bf4798ab26ULL };
static const c32_u128_t C32_LONG_GEN[5] = {
    { 0x3d5, 0x9d273535ea62d897ULL },
    { 0x7a9, 0xbecb6361c6c51507ULL },
    { 0x543, 0xf9b7e6c38d8a2a0eULL },
    { 0x0c5, 0x77eaeccf1990d13cULL },
    { 0x188, 0x7f74f8dc71b10651ULL },
};
static const c32_u128_t C32_LONG_MASK = { 0x3f, 0xffffffffffffffffULL }; // 70 bits

static uint32_t c32_u128_shr_small(const c32_u128_t v, const unsigned shift)
{
    // only used for shift 60 / 70: the result has at most 5 bits
    if (shift >= 64) {
        return (uint32_t)(v.hi >> (shift - 64));
    }
    return (uint32_t)((v.hi << (64 - shift)) | (v.lo >> shift));
}

static bool c32_u128_eq(const c32_u128_t a, const c32_u128_t b) { return a.hi == b.hi && a.lo == b.lo; }

static void c32_polymod_step(c32_u128_t* residue, const uint8_t value, const bool long_checksum)
{
    const c32_u128_t* gen = long_checksum ? C32_LONG_GEN : C32_REGULAR_GEN;
    const c32_u128_t mask = long_checksum ? C32_LONG_MASK : C32_REGULAR_MASK;
    const unsigned shift = long_checksum ? 70 : 60;

    const uint32_t b = c32_u128_shr_small(*residue, shift);
    c32_u128_t r = { residue->hi & mask.hi, residue->lo & mask.lo };
    r.hi = (r.hi << 5) | (r.lo >> 59);
    r.lo = (r.lo << 5) ^ value;
    for (int i = 0; i < 5; ++i) {
        if ((b >> i) & 1) {
            r.hi ^= gen[i].hi;
            r.lo ^= gen[i].lo;
        }
    }
    *residue = r;
}

static c32_u128_t c32_polymod(const uint8_t* values, const size_t len, const size_t zeros, const bool long_checksum)
{
    c32_u128_t residue = { 0, 0x23181b3 };
    for (size_t i = 0; i < len; ++i) {
        c32_polymod_step(&residue, values[i], long_checksum);
    }
    for (size_t i = 0; i < zeros; ++i) {
        c32_polymod_step(&residue, 0, long_checksum);
    }
    return residue;
}

static bool c32_verify_checksum(const uint8_t* data_with_checksum, const size_t len)
{
    const size_t expanded = CODEX32_HRP_EXPANDED_LEN + len;
    if (expanded >= 96) {
        return expanded <= 1023 && c32_u128_eq(c32_polymod(data_with_checksum, len, 0, true), C32_LONG_CONST);
    }
    return expanded <= 93 && c32_u128_eq(c32_polymod(data_with_checksum, len, 0, false), C32_REGULAR_CONST);
}

static size_t c32_checksum_len(const size_t data_len)
{
    return CODEX32_HRP_EXPANDED_LEN + data_len + CODEX32_SHORT_CHECKSUM_LEN > 93 ? CODEX32_LONG_CHECKSUM_LEN
                                                                                : CODEX32_SHORT_CHECKSUM_LEN;
}

// Writes "ms1" + data + checksum + NUL into 'out' (CODEX32_STRING_BUFLEN bytes)
static void c32_to_string(const codex32_data_t* d, char* out)
{
    const size_t n = c32_checksum_len(d->len);
    const bool long_checksum = n == CODEX32_LONG_CHECKSUM_LEN;
    c32_u128_t pm = c32_polymod(d->data, d->len, n, long_checksum);
    const c32_u128_t cst = long_checksum ? C32_LONG_CONST : C32_REGULAR_CONST;
    pm.hi ^= cst.hi;
    pm.lo ^= cst.lo;

    size_t o = 0;
    out[o++] = 'm';
    out[o++] = 's';
    out[o++] = '1';
    for (size_t i = 0; i < d->len; ++i) {
        out[o++] = C32_CHARSET[d->data[i]];
    }
    for (size_t i = 0; i < n; ++i) {
        const unsigned shift = (unsigned)(5 * (n - 1 - i));
        const uint32_t sym = shift >= 64 ? (uint32_t)(pm.hi >> (shift - 64))
            : shift == 0                 ? (uint32_t)pm.lo
                                         : (uint32_t)((pm.hi << (64 - shift)) | (pm.lo >> shift));
        out[o++] = C32_CHARSET[sym & 31];
    }
    out[o] = '\0';
}

// ms32_decode + the checks of Codex32String.Parse
static bool c32_parse(const char* text, codex32_data_t* d)
{
    if (!text) {
        return false;
    }
    const size_t len = strnlen(text, CODEX32_MAX_STRING_LEN + 1);
    if (len != 48 && len != 54 && len != 61 && len != 67 && len != 74 && len != 127) {
        return false;
    }
    bool has_lower = false, has_upper = false;
    char lower[CODEX32_STRING_BUFLEN];
    for (size_t i = 0; i < len; ++i) {
        char ch = text[i];
        if (ch < 33 || ch > 126) {
            return false;
        }
        if (ch >= 'A' && ch <= 'Z') {
            has_upper = true;
            ch = (char)(ch - 'A' + 'a');
        } else if (ch >= 'a' && ch <= 'z') {
            has_lower = true;
        }
        lower[i] = ch;
    }
    if (has_lower && has_upper) {
        return false;
    }
    // the separator is the LAST '1'
    size_t pos = len;
    for (size_t i = len; i-- > 0;) {
        if (lower[i] == '1') {
            pos = i;
            break;
        }
    }
    if (pos != 2 || lower[0] != 'm' || lower[1] != 's') {
        return false;
    }
    const size_t full_len = len - pos - 1;
    uint8_t full[CODEX32_MAX_DATA_LEN + CODEX32_LONG_CHECKSUM_LEN];
    if (full_len > sizeof(full)) {
        return false;
    }
    for (size_t i = 0; i < full_len; ++i) {
        const int v = c32_charset_index(lower[pos + 1 + i]);
        if (v < 0) {
            return false;
        }
        full[i] = (uint8_t)v;
    }
    if (lower[pos + 1] < '0' || lower[pos + 1] > '9') {
        return false; // the threshold is a digit
    }
    if (lower[pos + 1] == '0' && lower[pos + 6] != 's') {
        return false; // threshold 0 must be the secret
    }
    if (!c32_verify_checksum(full, full_len)) {
        codex32_wipe(full, sizeof(full));
        codex32_wipe(lower, sizeof(lower));
        return false;
    }
    const size_t n = CODEX32_HRP_EXPANDED_LEN + full_len < 94 ? CODEX32_SHORT_CHECKSUM_LEN : CODEX32_LONG_CHECKSUM_LEN;
    d->len = full_len - n;
    memcpy(d->data, full, d->len);
    codex32_wipe(full, sizeof(full));
    codex32_wipe(lower, sizeof(lower));
    return true;
}

// ---- GF(32) ----

static const uint8_t C32_GF32_INVERSE[32] = {
    0, 1, 20, 24, 10, 8, 12, 29, 5, 11, 4, 9, 6, 28, 26, 31,
    22, 18, 17, 23, 2, 25, 16, 19, 3, 21, 14, 30, 13, 7, 27, 15,
};

static uint8_t c32_gf32_mul(unsigned a, const unsigned b)
{
    unsigned res = 0;
    for (int i = 0; i < 5; ++i) {
        res ^= ((b >> i) & 1) ? a : 0;
        a *= 2;
        a ^= a >= 32 ? 41 : 0;
    }
    return (uint8_t)res;
}

static size_t c32_threshold_of(const codex32_data_t* d) { return (size_t)(C32_CHARSET[d->data[0]] - '0'); }

// ms32_interpolate: the string with share index 'x' (5-bit value) from exactly threshold-many strings
static void c32_interpolate(const codex32_data_t* shares, const size_t k, const uint8_t x, codex32_data_t* out)
{
    for (size_t s = 0; s < k; ++s) {
        if (shares[s].data[5] == x) {
            *out = shares[s];
            return;
        }
    }
    // Lagrange weights
    uint8_t w[CODEX32_MAX_THRESHOLD];
    unsigned n = 1;
    uint8_t c[CODEX32_MAX_THRESHOLD];
    for (size_t a = 0; a < k; ++a) {
        const unsigned i = shares[a].data[5];
        n = c32_gf32_mul(n, i ^ x);
        unsigned m = 1;
        for (size_t b = 0; b < k; ++b) {
            const unsigned j = shares[b].data[5];
            m = c32_gf32_mul(m, (i == j ? x : i) ^ j);
        }
        c[a] = (uint8_t)m;
    }
    for (size_t a = 0; a < k; ++a) {
        w[a] = c32_gf32_mul(n, C32_GF32_INVERSE[c[a]]);
    }
    out->len = shares[0].len;
    for (size_t i = 0; i < out->len; ++i) {
        unsigned v = 0;
        for (size_t a = 0; a < k; ++a) {
            v ^= c32_gf32_mul(w[a], shares[a].data[i]);
        }
        out->data[i] = (uint8_t)v;
    }
}

// ---- seed <-> secret ----

size_t codex32_string_len(const size_t seed_len)
{
    switch (seed_len) {
    case 16:
    case 20:
    case 24:
    case 28:
    case 32:
    case 64: {
        const size_t data_len = CODEX32_HEADER_LEN + (seed_len * 8 + 4) / 5;
        return 3 + data_len + c32_checksum_len(data_len);
    }
    default:
        return 0;
    }
}

static void c32_secret_from_seed(
    const uint8_t* seed, const size_t seed_len, const uint8_t* id, const size_t threshold, codex32_data_t* d)
{
    d->data[0] = (uint8_t)c32_charset_index((char)('0' + threshold));
    for (int i = 0; i < 4; ++i) {
        d->data[1 + i] = id[i];
    }
    d->data[5] = (uint8_t)c32_charset_index('s');
    size_t o = CODEX32_HEADER_LEN;
    uint32_t acc = 0;
    unsigned bits = 0;
    for (size_t i = 0; i < seed_len; ++i) {
        acc = ((acc << 8) | seed[i]) & 0xfff;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            d->data[o++] = (uint8_t)((acc >> bits) & 31);
        }
    }
    if (bits > 0) {
        d->data[o++] = (uint8_t)((acc << (5 - bits)) & 31);
    }
    d->len = o;
    acc = 0;
}

static bool c32_seed_from_secret(const codex32_data_t* d, uint8_t* seed, const size_t seed_buflen, size_t* seed_len)
{
    if (C32_CHARSET[d->data[5]] != 's') {
        return false;
    }
    const size_t total_bits = (d->len - CODEX32_HEADER_LEN) * 5;
    const size_t len = total_bits / 8;
    if (total_bits % 8 > 4 || codex32_string_len(len) == 0 || len > seed_buflen) {
        return false;
    }
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t o = 0;
    for (size_t i = CODEX32_HEADER_LEN; i < d->len && o < len; ++i) {
        acc = ((acc << 5) | d->data[i]) & 0xfff;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            seed[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    acc = 0;
    *seed_len = len;
    return true;
}

// ---- public API ----

bool codex32_split_seed(const uint8_t* seed, const size_t seed_len, const size_t threshold, const size_t count,
    const char* identifier, codex32_random_fn random_fn, char shares[][CODEX32_STRING_BUFLEN])
{
    if (!seed || codex32_string_len(seed_len) == 0 || !random_fn || !shares) {
        return false;
    }
    if (threshold < CODEX32_MIN_THRESHOLD || threshold > CODEX32_MAX_THRESHOLD) {
        return false;
    }
    if (count < threshold || count > CODEX32_MAX_SHARES) {
        return false;
    }

    uint8_t id[4];
    if (identifier) {
        if (strnlen(identifier, 5) != 4) {
            return false;
        }
        for (int i = 0; i < 4; ++i) {
            char ch = identifier[i];
            if (ch >= 'A' && ch <= 'Z') {
                ch = (char)(ch - 'A' + 'a');
            }
            const int v = c32_charset_index(ch);
            if (v < 0) {
                return false;
            }
            id[i] = (uint8_t)v;
        }
    } else {
        random_fn(id, sizeof(id));
        for (int i = 0; i < 4; ++i) {
            id[i] &= 31; // 256 is a multiple of 32: uniform
        }
    }

    // initial[0] = the secret, initial[1..k-1] = the random shares
    codex32_data_t initial[CODEX32_MAX_THRESHOLD];
    c32_secret_from_seed(seed, seed_len, id, threshold, &initial[0]);

    size_t out = 0;
    for (size_t i = 0; i < threshold - 1; ++i) {
        codex32_data_t* share = &initial[1 + i];
        memcpy(share->data, initial[0].data, 5);
        share->data[5] = (uint8_t)c32_charset_index(C32_SHARE_INDEXES[i]);
        share->len = initial[0].len;
        random_fn(share->data + CODEX32_HEADER_LEN, share->len - CODEX32_HEADER_LEN);
        for (size_t p = CODEX32_HEADER_LEN; p < share->len; ++p) {
            share->data[p] &= 31;
        }
        c32_to_string(share, shares[out++]);
    }
    for (size_t i = threshold - 1; i < count; ++i) {
        codex32_data_t share;
        c32_interpolate(initial, threshold, (uint8_t)c32_charset_index(C32_SHARE_INDEXES[i]), &share);
        c32_to_string(&share, shares[out++]);
        codex32_wipe(&share, sizeof(share));
    }

    codex32_wipe(initial, sizeof(initial));
    codex32_wipe(id, sizeof(id));
    return true;
}

bool codex32_combine_seed(
    const char* const* shares, const size_t nshares, uint8_t* seed, const size_t seed_buflen, size_t* seed_len)
{
    if (!shares || !nshares || !seed || !seed_len || nshares > CODEX32_MAX_SHARES + 1) {
        return false;
    }
    *seed_len = 0;

    bool ok = false;
    codex32_data_t list[CODEX32_MAX_THRESHOLD];
    codex32_data_t extra, expected, secret;
    uint8_t seen[32] = { 0 };

    if (!c32_parse(shares[0], &list[0])) {
        goto cleanup;
    }
    // the secret itself
    if (nshares == 1 && C32_CHARSET[list[0].data[5]] == 's') {
        ok = c32_seed_from_secret(&list[0], seed, seed_buflen, seed_len);
        goto cleanup;
    }
    const size_t k = c32_threshold_of(&list[0]);
    if (k < CODEX32_MIN_THRESHOLD || nshares < k) {
        goto cleanup;
    }
    seen[list[0].data[5]] = 1;

    for (size_t i = 1; i < nshares; ++i) {
        codex32_data_t* d = i < k ? &list[i] : &extra;
        if (!c32_parse(shares[i], d)) {
            goto cleanup;
        }
        // same backup: threshold, identifier, length; distinct indexes
        if (d->len != list[0].len || memcmp(d->data, list[0].data, 5) != 0 || seen[d->data[5]]) {
            goto cleanup;
        }
        seen[d->data[5]] = 1;
        if (i >= k) {
            // an extra share must agree with the first k
            c32_interpolate(list, k, d->data[5], &expected);
            if (expected.len != d->len || memcmp(expected.data, d->data, d->len) != 0) {
                goto cleanup;
            }
        }
    }

    c32_interpolate(list, k, (uint8_t)c32_charset_index('s'), &secret);
    ok = c32_seed_from_secret(&secret, seed, seed_buflen, seed_len);

cleanup:
    codex32_wipe(list, sizeof(list));
    codex32_wipe(&extra, sizeof(extra));
    codex32_wipe(&expected, sizeof(expected));
    codex32_wipe(&secret, sizeof(secret));
    if (!ok) {
        codex32_wipe(seed, seed_buflen);
        *seed_len = 0;
    }
    return ok;
}
#endif // AMALGAMATED_BUILD
