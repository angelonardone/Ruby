#ifndef FUZZ_FW_RPC_H_
#define FUZZ_FW_RPC_H_

// What a request goes through on Ruby before a handler reads its params, as in the firmware:
// - wire.c get_msg_len(): cbor_parser_init(), the whole value advances (complete and well formed), it is a map;
// - wire.c: rpc_request_valid() (an "id" and a "method" of allowed lengths);
// - process_utils.h GET_MSG_PARAMS: "params" is a valid map.
// A harness that feeds a handler's parser with whole RPC messages calls this first, so it only reports what Ruby
// itself could hit.

#include <cbor.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/cbor_rpc.h"

static inline bool fuzz_rpc_params(
    const uint8_t* data, const size_t size, CborParser* parser, CborValue* message, CborValue* params)
{
    if (cbor_parser_init(data, size, 0, parser, message) != CborNoError) {
        return false;
    }
    CborValue tmp = *message;
    if (cbor_value_advance(&tmp) != CborNoError || !cbor_value_is_map(message)) {
        return false;
    }
    if (!rpc_request_valid(message)) {
        return false;
    }
    const CborError cberr = cbor_value_map_find_value(message, CBOR_RPC_TAG_PARAMS, params);
    if (cberr != CborNoError || !cbor_value_is_valid(params) || cbor_value_get_type(params) == CborInvalidType
        || !cbor_value_is_map(params)) {
        return false;
    }
    return true;
}

#endif /* FUZZ_FW_RPC_H_ */
