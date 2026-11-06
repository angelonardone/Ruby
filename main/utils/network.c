#ifndef AMALGAMATED_BUILD
#include "network.h"
#include "../jade_wally_verify.h"
#include "jade_assert.h"

#include <string.h>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_crypto.h>

// Main networks
#define TAG_MAINNET "mainnet"

// Test networks
#define TAG_TESTNET "testnet"
#define TAG_LOCALTEST "localtest"

// Green CSV buckets allowed
static const size_t ALLOWED_CSV_MAINNET[] = { 25920, 51840, 65535 };
static const size_t ALLOWED_CSV_TESTNET[] = { 144, 4320, 51840 };

// return the allowed csv_blocks values for a network
static size_t network_to_csv_blocks(const network_t network_id, const size_t** allowed)
{
    JADE_INIT_OUT_PPTR(allowed);

    switch (network_id) {
    case NETWORK_BITCOIN:
        *allowed = ALLOWED_CSV_MAINNET;
        return sizeof(ALLOWED_CSV_MAINNET) / sizeof(ALLOWED_CSV_MAINNET[0]);
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
        *allowed = ALLOWED_CSV_TESTNET;
        return sizeof(ALLOWED_CSV_TESTNET) / sizeof(ALLOWED_CSV_TESTNET[0]);
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown network
}

// True if csv_blocks is one of the networks hard-coded csv_blocks values
bool network_is_known_csv_blocks(const network_t network_id, const uint32_t csv_blocks)
{
    const size_t* allowed = NULL;
    const size_t num_allowed = network_to_csv_blocks(network_id, &allowed);
    JADE_ASSERT(num_allowed > 0);
    JADE_ASSERT(allowed);

    for (size_t i = 0; i < num_allowed; ++i) {
        if (csv_blocks == allowed[i]) {
            return true;
        }
    }

    return false;
}

// True if csv_blocks is not below the networks smallest csv_blocks value
bool network_is_allowable_csv_blocks(const network_t network_id, const uint32_t csv_blocks)
{
    const size_t* allowed = NULL;
    const size_t num_allowed = network_to_csv_blocks(network_id, &allowed);
    JADE_ASSERT(num_allowed > 0);
    JADE_ASSERT(allowed);

    return csv_blocks >= allowed[0];
}

network_t network_from_name(const char* name)
{
    // Ensure our enum values match the libwally constants
    JADE_STATIC_ASSERT(NETWORK_NONE == WALLY_NETWORK_NONE);
    JADE_STATIC_ASSERT(NETWORK_BITCOIN == WALLY_NETWORK_BITCOIN_MAINNET);
    JADE_STATIC_ASSERT(NETWORK_BITCOIN_REGTEST == WALLY_NETWORK_BITCOIN_REGTEST);
    JADE_STATIC_ASSERT(NETWORK_BITCOIN_TESTNET == WALLY_NETWORK_BITCOIN_TESTNET);

    if (name) {
        if (!strcmp(TAG_MAINNET, name)) {
            return NETWORK_BITCOIN;
        } else if (!strcmp(TAG_TESTNET, name)) {
            return NETWORK_BITCOIN_TESTNET;
        } else if (!strcmp(TAG_LOCALTEST, name)) {
            return NETWORK_BITCOIN_REGTEST;
        }
    }
    return NETWORK_NONE;
}

const char* network_to_name(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return TAG_MAINNET;
    case NETWORK_BITCOIN_TESTNET:
        return TAG_TESTNET;
    case NETWORK_BITCOIN_REGTEST:
        return TAG_LOCALTEST;
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false);
    return NULL; // Unreachable
}

// network id to type (main or test)
network_type_t network_to_type(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return NETWORK_TYPE_MAIN;
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
        return NETWORK_TYPE_TEST;
    case NETWORK_NONE:
        break;
    }
    return NETWORK_TYPE_NONE;
}

// network id to BIP32 key version.
// Mainnets map to VER_MAIN_PRIVATE, testnets to VER_TEST_PRIVATE
uint32_t network_to_bip32_version(const network_t network_id)
{
    const network_type_t network_type = network_to_type(network_id);
    JADE_ASSERT(network_type != NETWORK_TYPE_NONE);
    return network_type == NETWORK_TYPE_MAIN ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
}

// network id to relevant P2PKH address prefix
uint8_t network_to_p2pkh_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return WALLY_ADDRESS_VERSION_P2PKH_MAINNET;
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
        return WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant P2SH address prefix
uint8_t network_to_p2sh_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return WALLY_ADDRESS_VERSION_P2SH_MAINNET;
    case NETWORK_BITCOIN_TESTNET:
    case NETWORK_BITCOIN_REGTEST:
        return WALLY_ADDRESS_VERSION_P2SH_TESTNET;
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return 0; // Unreachable
}

// network id to relevant bech32 hrp
const char* network_to_bech32_prefix(const network_t network_id)
{
    switch (network_id) {
    case NETWORK_BITCOIN:
        return "bc";
    case NETWORK_BITCOIN_TESTNET:
        return "tb";
    case NETWORK_BITCOIN_REGTEST:
        return "bcrt";
    case NETWORK_NONE:
        break;
    }
    JADE_ASSERT(false); // Unknown/invalid network
    return NULL; // Unreachable
}

#endif // AMALGAMATED_BUILD
