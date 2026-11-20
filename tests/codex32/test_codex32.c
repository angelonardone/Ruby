// Host unit test of main/codex32.c (Ruby's codex32 / BIP-93), built as it is for the device.
//
//   cc -O1 -g -fsanitize=address,undefined -I../../main -o test_codex32 test_codex32.c ../../main/codex32.c
//   ./test_codex32 cases.json && python3 -I codex32_reference.py cases.json
//
// (or `sh run.sh` here, or the Dockerfile here from the repo root). Checks: the BIP-93 test vectors 1-5,
// every invalid vector of the BIP refused, the splits of every seed size / threshold / count combined again (any k
// of the shares, all of them, a wrong share refused), and writes the random splits to cases.json so the BIP's own
// Python reference functions (codex32_reference.py, as in the C# library's TestCodex32) check them independently.

#include "codex32.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

static void check(const int ok, const char* what)
{
    ++checks;
    if (!ok) {
        ++failures;
        printf("FAIL  %s\n", what);
    }
}

static void to_hex(const uint8_t* b, const size_t len, char* out)
{
    for (size_t i = 0; i < len; ++i) {
        sprintf(out + 2 * i, "%02x", b[i]);
    }
    out[2 * len] = '\0';
}

static size_t from_hex(const char* hex, uint8_t* out)
{
    const size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; ++i) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static int seed_is(const char* const* shares, const size_t n, const char* expected_hex)
{
    uint8_t seed[64];
    size_t len = 0;
    if (!codex32_combine_seed(shares, n, seed, sizeof(seed), &len)) {
        return 0;
    }
    char hex[129];
    to_hex(seed, len, hex);
    return strcmp(hex, expected_hex) == 0;
}

// ---- a scripted "random" source: hands out the given 5-bit symbols (as codex32 characters) ----
static const char* scripted = NULL;
static size_t scripted_pos = 0;
static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static void scripted_random(uint8_t* buf, const size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        const char ch = scripted[scripted_pos++];
        buf[i] = (uint8_t)(strchr(CHARSET, ch) - CHARSET);
    }
}

// ---- a real random source for the round trips ----
static FILE* urandom = NULL;
static void real_random(uint8_t* buf, const size_t len)
{
    if (fread(buf, 1, len, urandom) != len) {
        abort();
    }
}

static const char* const INVALID[] = {
#include "invalid_vectors.inc"
};

int main(int argc, char** argv)
{
    const char* cases_path = argc > 1 ? argv[1] : "cases.json";

    // ---- TV1: unshared secret, 128 bits ----
    {
        const char* s[] = { "ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlw" };
        check(seed_is(s, 1, "318c6318c6318c6318c6318c6318c631"), "TV1 seed");
    }

    // ---- TV2: k=2 shares (upper case), a + c and a + d ----
    {
        const char* ac[] = { "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
            "MS12NAMECACDEFGHJKLMNPQRSTUVWXYZ023FTR2GDZMPY6PN" };
        check(seed_is(ac, 2, "d1808e096b35b209ca12132b264662a5"), "TV2 seed from a + c");
        const char* ad[] = { "MS12NAMEA320ZYXWVUTSRQPNMLKJHGFEDCAXRPP870HKKQRM",
            "ms12namedll4f8jlh4e5vdvuldlfxu2jhdnlsm97xvenrxeg" };
        check(seed_is(ad, 2, "d1808e096b35b209ca12132b264662a5"), "TV2 seed from a + d (case differs between strings)");
        const char* secret[] = { "ms12names6xqguzttxkeqnjsjzv4jv3nz5k3kwgsphuh6evw" };
        check(seed_is(secret, 1, "d1808e096b35b209ca12132b264662a5"), "TV2 secret");
    }

    // ---- TV3: split an existing 128-bit seed, k=3, identifier "cash": shares a and c are the BIP's, d e f derived ----
    {
        uint8_t seed[16];
        from_hex("ffeeddccbbaa99887766554433221100", seed);
        char shares[5][CODEX32_STRING_BUFLEN];
        scripted = "320zyxwvutsrqpnmlkjhgfedca"
                   "acdefghjklmnpqrstuvwxyz023";
        scripted_pos = 0;
        check(codex32_split_seed(seed, sizeof(seed), 3, 5, "cash", scripted_random, shares), "TV3 split");
        check(!strcmp(shares[0], "ms13casha320zyxwvutsrqpnmlkjhgfedca2a8d0zehn8a0t"), "TV3 share a");
        check(!strcmp(shares[1], "ms13cashcacdefghjklmnpqrstuvwxyz023949xq35my48dr"), "TV3 share c");
        check(!strcmp(shares[2], "ms13cashd0wsedstcdcts64cd7wvy4m90lm28w4ffupqs7rm"), "TV3 derived d");
        check(!strcmp(shares[3], "ms13casheekgpemxzshcrmqhaydlp6yhms3ws7320xyxsar9"), "TV3 derived e");
        check(!strcmp(shares[4], "ms13cashf8jh6sdrkpyrsp5ut94pj8ktehhw2hfvyrj48704"), "TV3 derived f");
        int every = 1;
        for (int i = 0; i < 5; ++i) {
            for (int j = i + 1; j < 5; ++j) {
                for (int k = j + 1; k < 5; ++k) {
                    const char* three[] = { shares[i], shares[j], shares[k] };
                    every &= seed_is(three, 3, "ffeeddccbbaa99887766554433221100");
                }
            }
        }
        check(every, "TV3 every 3 of the 5 shares give the seed");
        const char* all[] = { shares[0], shares[1], shares[2], shares[3], shares[4] };
        check(seed_is(all, 5, "ffeeddccbbaa99887766554433221100"), "TV3 all 5 shares (extra shares checked)");
        const char* alt[] = { "ms13cashsllhdmn9m42vcsamx24zrxgs3qpte35dvzkjpt0r" };
        check(seed_is(alt, 1, "ffeeddccbbaa99887766554433221100"), "TV3 secret with other padding");
        const char* two[] = { shares[0], shares[1] };
        check(!seed_is(two, 2, "ffeeddccbbaa99887766554433221100"), "TV3 two shares are not enough");
        const char* dup[] = { shares[0], shares[0], shares[1] };
        check(!seed_is(dup, 3, "ffeeddccbbaa99887766554433221100"), "TV3 the same share twice refused");
    }

    // ---- TV4: 256 bits ----
    {
        const char* s[] = { "ms10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqtum9pgv99ycma" };
        check(seed_is(s, 1, "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"), "TV4 seed");
    }

    // ---- TV5: 512 bits, long checksum ----
    {
        const char* s[] = { "MS100C8VSM32ZXFGUHPCHTLUPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZYGSFJD6AN074RXVCEMLH8WU3TK925ACDEFGHJ"
                            "KLMNPQRSTUVWXY06FHPV80UNDVARHRAK" };
        check(seed_is(s, 1,
                  "dc5423251cb87175ff8110c8531d0952d8d73e1194e95b5f19d6f9df7c01111104c9baecdfea8cccc677fb9ddc8aec5553b"
                  "86e528bcadfdcc201c17c638c47e9"),
            "TV5 seed (long checksum)");
    }

    // ---- TV6-8: other sizes ----
    {
        const char* s7[] = { "ms10seedsyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdau84gz0632s0xs" };
        check(seed_is(s7, 1, "202122232425262728292a2b2c2d2e2f3031323334353637"), "TV7 192 bits");
        const char* s8[] = { "ms10seedsgpq5ys6yg4rywjzfff95cn2wfag9z5jn2324v46ct9d9hrcduqw8c3lccl" };
        check(seed_is(s8, 1, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b"), "TV8 224 bits");
    }

    // ---- invalid vectors ----
    {
        int refused = 0;
        const size_t n = sizeof(INVALID) / sizeof(INVALID[0]);
        for (size_t i = 0; i < n; ++i) {
            const char* s[] = { INVALID[i] };
            uint8_t seed[64];
            size_t len;
            if (!codex32_combine_seed(s, 1, seed, sizeof(seed), &len)) {
                ++refused;
            } else {
                printf("  accepted (wrong): %s\n", INVALID[i]);
            }
        }
        char what[64];
        snprintf(what, sizeof(what), "invalid vectors refused: %d/%zu", refused, n);
        check((size_t)refused == n, what);
    }

    // ---- bad parameters ----
    {
        uint8_t seed[64] = { 1 };
        char shares[31][CODEX32_STRING_BUFLEN];
        urandom = fopen("/dev/urandom", "rb");
        check(!codex32_split_seed(seed, 64, 1, 3, NULL, real_random, shares), "threshold 1 refused");
        check(!codex32_split_seed(seed, 64, 10, 12, NULL, real_random, shares), "threshold 10 refused");
        check(!codex32_split_seed(seed, 64, 3, 2, NULL, real_random, shares), "fewer shares than the threshold refused");
        check(!codex32_split_seed(seed, 64, 2, 32, NULL, real_random, shares), "32 shares refused");
        check(!codex32_split_seed(seed, 33, 2, 3, NULL, real_random, shares), "33-byte seed refused");
        check(!codex32_split_seed(seed, 64, 2, 3, "cas", real_random, shares), "3-character identifier refused");
        check(!codex32_split_seed(seed, 64, 2, 3, "cab!", real_random, shares), "identifier outside the charset refused");
        check(codex32_string_len(64) == 127 && codex32_string_len(16) == 48 && codex32_string_len(33) == 0,
            "string lengths");
    }

    // ---- random round trips, written for the Python reference ----
    {
        static const size_t SIZES[] = { 16, 20, 24, 28, 32, 64 };
        FILE* out = fopen(cases_path, "w");
        fprintf(out, "[\n");
        int first = 1, ok = 1, n = 0;
        for (size_t z = 0; z < sizeof(SIZES) / sizeof(SIZES[0]); ++z) {
            for (size_t k = 2; k <= 9; ++k) {
                const size_t counts[] = { k, k + 1, k + 7 > 31 ? 31 : k + 7, 31 };
                for (size_t c = 0; c < 4; ++c) {
                    const size_t count = counts[c];
                    uint8_t seed[64];
                    real_random(seed, SIZES[z]);
                    char seed_hex[129];
                    to_hex(seed, SIZES[z], seed_hex);
                    char shares[31][CODEX32_STRING_BUFLEN];
                    if (!codex32_split_seed(seed, SIZES[z], k, count, NULL, real_random, shares)) {
                        ok = 0;
                        continue;
                    }
                    for (size_t i = 0; i < count; ++i) {
                        ok &= strlen(shares[i]) == codex32_string_len(SIZES[z]);
                    }
                    // a random subset of k shares, and all of them
                    const char* pick[31];
                    size_t idx[31];
                    for (size_t i = 0; i < count; ++i) {
                        idx[i] = i;
                    }
                    for (size_t i = count - 1; i > 0; --i) {
                        uint8_t r;
                        real_random(&r, 1);
                        const size_t j = r % (i + 1);
                        const size_t t = idx[i];
                        idx[i] = idx[j];
                        idx[j] = t;
                    }
                    for (size_t i = 0; i < k; ++i) {
                        pick[i] = shares[idx[i]];
                    }
                    ok &= seed_is(pick, k, seed_hex);
                    const char* every[31];
                    for (size_t i = 0; i < count; ++i) {
                        every[i] = shares[i];
                    }
                    ok &= seed_is(every, count, seed_hex);
                    if (count > k) {
                        // one damaged extra share (another valid string of a different backup) is refused
                        char other[31][CODEX32_STRING_BUFLEN];
                        if (codex32_split_seed(seed, SIZES[z], k, count, "zzzz", real_random, other)) {
                            every[count - 1] = other[count - 1];
                            ok &= !seed_is(every, count, seed_hex);
                        }
                    }
                    fprintf(out, "%s  {\"seed\": \"%s\", \"k\": %zu, \"shares\": [", first ? "" : ",\n", seed_hex, k);
                    for (size_t i = 0; i < count; ++i) {
                        fprintf(out, "%s\"%s\"", i ? ", " : "", shares[i]);
                    }
                    fprintf(out, "]}");
                    first = 0;
                    ++n;
                }
            }
        }
        fprintf(out, "\n]\n");
        fclose(out);
        char what[96];
        snprintf(what, sizeof(what), "%d random splits combined again (subset of k, all, wrong share refused)", n);
        check(ok, what);
    }
    fclose(urandom);

    printf("%s: %d checks, %d failed\n", failures ? "FAILED" : "ALL PASS", checks, failures);
    return failures ? 1 : 0;
}
