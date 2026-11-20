#ifndef CODEX32_H_
#define CODEX32_H_

// Ruby: codex32 (BIP-93) - Shamir's secret sharing of the BIP32 master seed over GF(32), with a BCH checksum in
// every string. Wallet Backup and Time Encrypted Vault of a Ruby wallet split the seed with it ON Ruby, so the
// computer never sees the seed nor a share (each contact's shares leave Ruby encrypted to that contact).
// Any BIP-93 implementation puts the shares together again: the wallet's C# library (Codex32.cs) does it today.
//
// A string: "ms1" + threshold (1 char) + identifier (4) + share index (1) + payload + checksum (13, or 15 for a
// 64-byte seed). Share index 's' is the secret itself. Line by line the Python reference of the BIP, as Codex32.cs.
//
// Pure C (no ESP-IDF / libwally): the host unit test (tests/codex32/) builds it as it is.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CODEX32_MIN_THRESHOLD 2
#define CODEX32_MAX_THRESHOLD 9
#define CODEX32_MAX_SHARES 31
#define CODEX32_MAX_SEED_LEN 64

// Longest string (64-byte seed): 3 + 6 + 103 + 15 = 127 characters, plus the terminating NUL
#define CODEX32_MAX_STRING_LEN 127
#define CODEX32_STRING_BUFLEN (CODEX32_MAX_STRING_LEN + 1)

// Fills 'buf' with 'len' random bytes (the firmware passes get_random)
typedef void (*codex32_random_fn)(uint8_t* buf, size_t len);

// Length of each codex32 string of a seed of 'seed_len' bytes (0 when that size is not allowed by BIP-93)
size_t codex32_string_len(size_t seed_len);

// Splits a master seed (16, 20, 24, 28, 32 or 64 bytes) into 'count' shares (indexes a, c, d, e, ... as BIP-93
// hands them out), any 'threshold' of which give the seed back. 'identifier' is 4 codex32 characters, or NULL for a
// random one. The first threshold-1 shares are random, the rest interpolated ("For an existing secret").
// 'shares' receives 'count' NUL-terminated lowercase strings of CODEX32_STRING_BUFLEN bytes each.
// Returns false (and writes nothing useful) on a bad parameter.
bool codex32_split_seed(const uint8_t* seed, size_t seed_len, size_t threshold, size_t count, const char* identifier,
    codex32_random_fn random_fn, char shares[][CODEX32_STRING_BUFLEN]);

// The master seed from 'nshares' codex32 strings: threshold-many shares (more are cross-checked against the
// others), or the secret itself (index 's'). Returns false on any invalid string, mixed backups, too few shares or
// a share that does not agree with the others.
bool codex32_combine_seed(
    const char* const* shares, size_t nshares, uint8_t* seed, size_t seed_buflen, size_t* seed_len);

#endif /* CODEX32_H_ */
