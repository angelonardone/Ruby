#ifndef UTILS_ADDRESS_H_
#define UTILS_ADDRESS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../jade_assert.h"
#include "network.h"

#define MAX_ADDRESS_LEN 128

typedef struct {
    char address[MAX_ADDRESS_LEN];
    network_t network_id;
    uint8_t script[MAX_ADDRESS_LEN]; // script should always be shorter than the address
    size_t script_len;
} address_data_t;

// Script pubkey to address, for BTC networks
void script_to_address(const network_t network_id, const uint8_t* script, size_t script_len, bool has_value,
    char* output, size_t output_len);

// Attempt to parse an address - return the network and the scriptpubkey
WARN_UNUSED_RESULT bool parse_address(const char* address, address_data_t* addr_data);

#endif /* UTILS_ADDRESS_H_ */
