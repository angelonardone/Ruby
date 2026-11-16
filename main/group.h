#ifndef GROUP_H_
#define GROUP_H_

// Ruby: registration of a DistributedCryptography Taproot group, so Ruby can recognise the group's own addresses
// (above all the change of a group payment, which is then not shown for confirmation).
//
// A group address is defined by the group's extended public keys (one per participant and chain), the threshold k and
// the address index i, exactly as the DistributedCryptography library builds it (NBitcoin DelegatedMultiSig /
// TaprootMultiSig, FromExtPubKeys):
//  - signers: the participants' chain xpubs sorted by their BIP32 serialization; each derived at i (non hardened).
//  - leaves: one BIP342 multi_a script per k-combination of the signers (lexicographic order over the sorted signers),
//    the keys of a leaf in x-only order: <x1> CHECKSIG <x2> CHECKSIGADD ... OP_k NUMEQUAL, leaf version 0xc0.
//  - tree: the defined tree: tree(S) = leaf if S has one script, else { tree(first ceil(|S|/2)), tree(rest) }.
//  - internal key: Delegated = the owner's key derived at i; Multi Signature = BIP327 KeyAgg(KeySort(signer keys)).
//  - output key: the internal key tweaked with the merkle root (BIP341); the address is P2TR of it.
// The same wallet is the standard descriptor tr(owner/*,{sortedmulti_a(k,...),...}) (Delegated) or
// tr(musig(...)/*,{...}) (Multi Signature, BIP390), but the record is kept compact and the address is calculated
// here: the generic descriptor code would repeat (and derive) every key once per leaf.
// See RUBY-GROUPS.md.

#include "utils/cbor_rpc.h"
#include "utils/network.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_bip32.h>

#define GROUP_TYPE_DELEGATED 1
#define GROUP_TYPE_MULTISIG 2

#define GROUP_CHAIN_RECEIVING 0
#define GROUP_CHAIN_CHANGE 1

// Participants with keys in the scripts (the members of a Delegated group, every signer of a Multi Signature group)
#define MAX_GROUP_SIGNERS 15
// k-combinations of the signers = leaves of the tree (calculated for every address)
#define MAX_GROUP_LEAVES 2000 // = MaxCombinations of the DistributedCryptography library
// Name shown on Ruby (the group's name in the app), without the terminating nul
#define MAX_GROUP_LABEL_LEN 40
// Registered groups
#define MAX_GROUP_REGISTRATIONS 24

typedef struct {
    network_t network_id; // the network the group was registered for
    uint8_t type; // GROUP_TYPE_
    uint8_t threshold; // k
    uint8_t num_signers; // n
    bool we_are_owner; // Delegated: this Ruby is the owner (else one of the signers)
    char label[MAX_GROUP_LABEL_LEN + 1];
    // This Ruby's chain paths (eg. m/86'/1'/0'/2 and m/86'/1'/0'/3): an address index i is the path + /i
    uint32_t chain_path[2][MAX_PATH_LEN];
    size_t chain_path_len[2];
    // Per chain: the owner's xpub (Delegated) and the signers' xpubs, sorted (BIP32 serialization)
    struct ext_key owner[2];
    struct ext_key signers[2][MAX_GROUP_SIGNERS];
} group_data_t;

// Number of k-combinations of n (C(n,k)), or SIZE_MAX if more than MAX_GROUP_LEAVES
size_t group_num_leaves(size_t n, size_t k);

// Sort the signers of each chain as the library does (by BIP32 serialization)
void group_sort_signers(group_data_t* group);

// The P2TR scriptPubKey (34 bytes) of the group address 'index' on 'chain'
bool group_get_script(const group_data_t* group, uint8_t chain, uint32_t index, uint8_t* script, size_t script_len);

// The address string of the group address 'index' on 'chain' (free with wally_free_string)
bool group_get_address(
    const group_data_t* group, network_t network_id, uint8_t chain, uint32_t index, char** address);

// If 'path' is this Ruby's path of a group address (chain path + /i), return the chain and i
bool group_path_to_chain_index(
    const group_data_t* group, const uint32_t* path, size_t path_len, uint8_t* chain, uint32_t* index);

// Record (de)serialization (with the wallet hmac, as multisig/descriptor records)
size_t group_record_len(const group_data_t* group);
bool group_to_bytes(const group_data_t* group, uint8_t* output, size_t output_len);
bool group_from_bytes(const uint8_t* bytes, size_t bytes_len, group_data_t* group);

// Load a registered group (false if missing, corrupt or for another wallet)
bool group_load_from_storage(const char* name, group_data_t* group, const char** errmsg);

// Type names for the screens and replies
const char* group_type_name(uint8_t type);

#endif /* GROUP_H_ */
