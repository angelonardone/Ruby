#ifndef FUZZ_FIRMWARE_STUBS_H_
#define FUZZ_FIRMWARE_STUBS_H_

// Host stand-ins for the firmware functions the fuzzed code links against but must not need (see
// firmware_stubs.c), plus what a harness controls: the bytes get_random() returns, and the sensitive stack.

#include <stddef.h>
#include <stdint.h>

// get_random() returns a pseudo-random stream seeded from these bytes (the same input, the same stream)
void fuzz_random_set(const uint8_t* data, size_t len);

// Items on the SENSITIVE_PUSH stack: must be 0 when the fuzzed call returns (else a secret is left unwiped)
size_t fuzz_sensitive_depth(void);

#endif /* FUZZ_FIRMWARE_STUBS_H_ */
