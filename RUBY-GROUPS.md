# Ruby and DistributedCryptography groups

What the Ruby firmware adds to Jade for the **Taproot groups** of the DistributedCryptography wallet, and why.
The wallet side (the C# library in the NBitcoin fork, `DistricutedCryptographyLib`) builds the payments and sends
them to Ruby; this document describes what Ruby accepts, checks, shows and signs, and the group registration.
The RPC messages are in [docs/index.rst](docs/index.rst) ("Ruby specific").

| Change | Commit | Files |
|---|---|---|
| One approval for every fee level of a payment (`sign_psbt` `fee_options`) | `7a3753b6` | `main/process/sign_psbt.c`, `main/ui/sign_tx.c` |
| Key path of an output that also has scripts (Delegated owner) | `df8fcebc` | `main/utils/psbt.c` |
| Script path of `multi_a` leaves (Delegated member, Multi Signature) | `69392994` | `main/utils/psbt.c`, `main/process/sign_psbt.c` |
| MuSig2 groups: round 1 `musig2_nonces`, round 2 in `sign_psbt`, registration of MuSig2 leaves | (this branch, `musig2-ruby`) | `main/musig2.[ch]`, `main/process/musig2_nonces.c`, `main/process/sign_psbt.c`, `main/utils/psbt.c` (key iterator), `main/group.[ch]` (types 3 and 4), `main/process/register_group.c`, `main/process/get_registered_groups.c`, `main/ui/group.c`, `main/keychain.c` (wipe), `main/process/dashboard.c`, `main/process.c` and `main/utils/temporary_stack.c` (allow-lists), `main/amalgamated.c` |
| Group registration: Ruby recognises the group's change | `be9f95d7` | `main/group.[ch]`, `main/process/register_group.c`, `main/process/get_registered_groups.c`, `main/ui/group.c`, `main/process/sign_psbt.c`, `main/process/get_receive_address.c`, `main/process/dashboard.c`, `main/process/debug_clean.c`, `main/process.c` (reply allowed), `main/storage.[ch]`, `main/process/register_multisig.c` and `register_descriptor.c` (storage reserve), `main/amalgamated.c` and `components/libwally-core/CMakeLists.txt` (`ENABLE_MODULE_MUSIG`) |

## 1. The groups

A group address is a P2TR output (BIP341) whose script tree has one BIP342 `multi_a` leaf per combination of `k`
signers (BIP387 `sortedmulti_a`):

- **Delegated**: the internal key is the **owner's** key: the owner spends alone by the key path; `k` of the `n`
  members spend together by a script path.
- **Multi Signature**: no owner. The internal key is the BIP327 **MuSig2 aggregate** of all the signers (nobody
  can spend alone by the key path); every payment is `k` of `n` by a script path. Whoever created the group is one
  more signer.

Every participant gives two **chain** extended public keys: receiving and change. For a Ruby wallet they are
`m/86'/c'/0'/2` and `m/86'/c'/0'/3` (`c` = 0' mainnet, 1' testnet / regtest). The address number `i` of a chain uses
the child `i` of every chain key. The descriptor of a whole chain (what Bitcoin Core imports) is:

    Delegated:        tr(owner/*,{sortedmulti_a(k,A/*,B/*),{sortedmulti_a(k,A/*,C/*),sortedmulti_a(k,B/*,C/*)}})
    Multi Signature:  tr(musig(A/*,B/*,C/*),{sortedmulti_a(k,...),...})            (BIP390)

with the tree written exactly as in section 4.

The **MuSig2 groups** (2026-11-17; the library's `DelegatedMultiSig2` / `TaprootMultiSig2`) are built the same way,
but each leaf is ONE key, the BIP327 aggregate of the `k` keys of its combination, signed live by those `k` signers
together (section 2.4):

- **Advanced Delegated Multi Signature** (app GroupType 80): the internal key is the owner's key, as in Delegated.
- **Advanced Multi Signature** (app GroupType 90): the internal key is the aggregate of every signer, as in Multi
  Signature, but here it is used: when ALL the signers are present they spend by the key path.

    Advanced Delegated:        tr(owner/*,{pk(musig(A/*,B/*)),{pk(musig(A/*,C/*)),pk(musig(B/*,C/*))}})   (BIP390)
    Advanced Multi Signature:  tr(musig(A/*,B/*,C/*),{pk(musig(A/*,B/*)),...})

## 2. Signing

### 2.1 Delegated owner: key path with a merkle root (`df8fcebc`)

The PSBT input has the owner's key (`PSBT_IN_TAP_BIP32_DERIVATION`, no leaf hashes) and the merkle root of the
scripts (`PSBT_IN_TAP_MERKLE_ROOT`, 0x18). Ruby signs it only if the coin spent is exactly P2TR of that key tweaked
with that merkle root (`key_iter_is_taproot_keypath_with_scripts`); libwally signs with the same tweak.

### 2.2 Delegated member and Multi Signature: script path (`69392994`)

The PSBT input has Ruby's key with the leaf hashes of the scripts it is in, and those scripts with their control
blocks (`PSBT_IN_TAP_LEAF_SCRIPT`, 0x15). Ruby signs only if (`key_iter_is_taproot_scriptpath`):

- there is one key, x-only, with at most 128 leaf hashes;
- every leaf hash has its script in the PSBT, leaf version 0xc0;
- every script is a `multi_a` script (`<x1> CHECKSIG <x2> CHECKSIGADD ... <k> NUMEQUAL`) that holds Ruby's key;
- every control block proves the leaf is committed in the coin spent (merkle path + tweak = the coin's key and
  parity).

Each leaf is signed with the BIP342 tapscript sighash (`SIGHASH_DEFAULT`) and the signature goes to
`PSBT_IN_TAP_SCRIPT_SIG` (0x14, key = x-only key || leaf hash). Nothing is signed by the key path. libwally does not
sign script paths, so `sign_taproot_script_path` in `sign_psbt.c` does it.

### 2.3 Fee options: one approval for every fee level (`7a3753b6`)

A group payment is built at several fees, so the last signer can choose one. `sign_psbt` takes them in
`fee_options` (up to 3 extra PSBTs). Ruby shows the payment once with every fee ("Sign N Fees") and signs all of
them with that one approval, but only for an option that spends **the same coins** and pays **the same outputs in
the same order**, except that **one output gets less, or is dropped, by exactly the extra fee** (normally the
change; when everything is sent, the payment). Anything else is refused or asked again.

### 2.4 MuSig2 groups: two rounds (2026-11-17)

The owner of an Advanced Delegated group pays alone by the key path exactly as in 2.1 (nothing new in the firmware).
Every other payment of a MuSig2 group is signed in a **signing room** of the app: the `k` signers present (or all of
them, key path of an Advanced Multi Signature group) exchange nonces, then partial signatures (BIP327). Ruby takes
part as one signer (`main/musig2.c`):

1. **Round 1, `musig2_nonces`** (no screen: making nonces signs nothing). The psbt's MuSig2 inputs carry, as BIP373
   fields (libwally keeps them among the input's unknown fields): the participants (`0x1a`, key = the plain aggregate
   key), Ruby's key with its origin, and either the one leaf `<x-only aggregate> OP_CHECKSIG` with its control block
   (script path) or the aggregate as the internal key with the merkle root (key path). The key iterator accepts such
   an input only if (`musig2_input_check`): the participants aggregate (KeyAgg, in the order given) to the key named,
   Ruby's key is one of them, and the leaf is committed in the coin spent / the tweaked internal key is the coin's
   output key. Ruby then makes its nonces for each input: BIP327 NonceGen with fresh randomness, its secret key, the
   BIP341 sighash and the aggregate key. The **secret nonces stay in RAM only** (never in storage: a copy brought back
   could reuse a nonce, which gives the key away), for ONE payment; the public nonces are returned.
2. **Round 2, `sign_psbt`** of the same payment with every participant's public nonce (`0x1b`). Ruby shows the
   payment as usual (outputs, fee; a registered group's change is hidden) and, once the user accepts it, checks that
   each input is exactly what its nonce was made for (key, aggregate, leaf, sighash) and that the psbt carries Ruby's
   own public nonce, aggregates the nonces and makes its partial signature (`0x1c`), verified before it is returned.

The secret nonces are wiped by that `sign_psbt` whatever happens (signed, declined, refused), by the next
`musig2_nonces`, by a lock or logout (`keychain_clear`), and after 10 minutes. So a nonce is never used twice: a
retry starts again from round 1. The work of each input (KeyAgg of up to 32 keys, sighash, NonceGen, the partial
signature and its check) runs on a 12 KB temporary stack (`musig2_check_task`, `musig2_nonce_task`,
`musig2_sign_task`: all three are in the `temp_task_wrapper` allow-list).

## 3. Group registration

### 3.1 Why

Without it Ruby does not know the group's addresses, so it shows the **change** of a group payment as one more
output to confirm. Jade recognises change by a registered wallet (multisig or descriptor). For these groups a
**descriptor** does not work well on Ruby (measured on the M5Stack Basic, no PSRAM, 2026-11-16):

- libwally does not parse `tr()` with a script tree, `multi_a` / `sortedmulti_a`, or `musig()`.
- Jade's wallet policies (BIP388) refuse a key placeholder used twice; in these trees every key is in several
  leaves.
- Jade registers only policies with both chains (`/<0;1>/*`); a group participant gives two separate chain keys
  (`/2` and `/3`), and the account key that would join them would show his own personal addresses to the group.
- libwally writes every key once **per leaf** and derives it per leaf: a group of 8 members with 4 signatures has
  70 leaves = 280 keys, about 38 KB of text plus ~500 parse nodes (RAM free: about 133 KB).
- The text of the descriptor grows with the leaves (3 017 characters for 8 members / 4 signatures; Jade's limit is
  512).

So Ruby keeps a **compact record** (the keys, once each) and calculates the address itself.

### 3.2 The record (`main/group.c`)

Stored in the NVS namespace `DCGROUPS`, under a name of at most 15 characters (the wallet uses `dc` + 13 hex
characters of the SHA-256 of the group's two descriptors, so a group whose keys change gets a new name). Layout,
version 1:

    version(1) network(1) type(1: 1 Delegated, 2 Multi Signature, 3 Advanced Delegated, 4 Advanced Multi Signature)
    k(1) n(1) flags(1: bit 0 = Ruby is the owner)
    label_len(1) label                          the group's name, shown on Ruby (at most 40 printable characters)
    2 x [ path_len(1) path(4 x path_len LE) ]   Ruby's receiving and change chain paths
    Delegated and Advanced Delegated: owner receiving xpub(78) owner change xpub(78)
    n x receiving xpub(78)   n x change xpub(78)   signers, sorted (4.1)
    hmac(32)                                    HMAC-SHA256 of the above with the wallet's master key

The HMAC (as Jade's multisig and descriptor records) means a record is only used by the wallet that registered it:
another mnemonic (or passphrase) does not see it. A Delegated group of 3 members takes about 700 bytes; 15 members
about 2.6 KB.

### 3.3 The address (`group_get_script`)

Exactly as the library (NBitcoin `DelegatedMultiSig.FromExtPubKeys` / `TaprootMultiSig.FromExtPubKeys`):

1. **Signers**: the chain xpubs sorted by their BIP32 serialization (without the version: depth, parent
   fingerprint, child number, chain code, key), each derived at `i` (not hardened). Each key is derived once.
2. **Leaves**: one per `k`-combination of the signers, in lexicographic order over the sorted signers. The keys of a
   leaf in x-only order: `<x1> OP_CHECKSIG <x2> OP_CHECKSIGADD ... OP_k OP_NUMEQUAL`, leaf version 0xc0, TapLeaf
   hash. MuSig2 groups: `<x-only KeyAgg(KeySort(the keys of the combination))> OP_CHECKSIG` (one key aggregation per
   leaf: measured on the QEMU emulator, an address takes about 0.3 s with 3 leaves and 4.4 s with 462).
3. **Tree**: `tree(S) = leaf` if `S` has one script, else `{tree(first ceil(|S|/2)), tree(the rest)}`; a branch is
   TapBranch of its two hashes in lexicographic order. The leaves are produced in order while the tree is walked,
   so no list of leaves is kept. The walk is not recursive (an explicit stack of at most 11 nodes on the heap), and
   the whole calculation runs on a temporary 10 KB stack (up to about 7.4 KB measured, with the MuSig key aggregation) (`run_in_temporary_task`, as Jade does for descriptors): a
   first version that recursed on the main task's stack crashed from about 900 leaves (the callers, eg.
   `get_receive_address`, leave only about 4.8 KB of it).
4. **Internal key**: Delegated and Advanced Delegated: the owner's chain key derived at `i`. Multi Signature and
   Advanced Multi Signature: BIP327 `KeyAgg` of the
   signers' keys in `KeySort` order (33-byte compressed), with secp256k1-zkp's MuSig module (enabled for this:
   `ENABLE_MODULE_MUSIG`).
5. **Output**: the internal key tweaked with the merkle root (BIP341); the address is P2TR of it.

### 3.4 Limits

| | Value | Why |
|---|---|---|
| Signers (`n`) | 2 to 15 | `MAX_GROUP_SIGNERS` |
| Leaves `C(n,k)` | at most 2000 | `MAX_GROUP_LEAVES` = the library's `MaxCombinations`; every address hashes all of them |
| Leaves signed per input | at most 128 | libwally keeps at most 128 leaf hashes per key (2.2) |
| Groups | 24 | `MAX_GROUP_REGISTRATIONS` |
| Storage | see 3.5 | the NVS partition (16 KB on ESP32 boards) |

### 3.5 The storage reserve (all registrations)

The NVS partition of an ESP32 board is 16 KB: 4 pages of 126 entries of 32 bytes, one page kept free by ESP-IDF.
With a real wallet and PIN, Ruby itself uses about 47 entries; about **331 entries (10.6 KB) are free**. Jade does
not check the space before a registration, and **every unlock writes the PIN attempt counter**
(`storage_decrement_counter`): with a full NVS that write fails and the wallet can not be unlocked. So every
registration (group, multisig and descriptor) now checks `storage_has_room_for_blob`: it is refused ("Not enough
storage space on Ruby") unless `STORAGE_RESERVED_FREE_ENTRIES` (32 entries, 1 KB) stay free after it.

### 3.6 Registering (`register_group`)

Ruby checks everything before showing anything: the keys parse and are of the network, every key of a chain is
different (the owner included), `2 <= n <= 15`, `C(n,k) <= 2000`, and **Ruby's own xpubs at the given chain paths
are the owner's or one signer's on both chains** ("This Ruby is not a participant of the group" otherwise). It
calculates the first receiving and change addresses, then shows:

1. **Register Group**: the group's name, its type and `k of n` ("Delegated 2 of 3", "Adv. Delegated 2 of 3", "Adv.
   Multi Signature 2 of 3"), and Ruby's role ("You are the owner", "You are a member", "You are a signer"). Yes / No
   (No selected).
2. **Group Address 1**: the first receiving address of the group, to compare with the one the wallet shows. ✓ / X.

An identical registration answers at once without asking; a different one under the same name says "Replaces the
saved one". `get_registered_groups` lists them; `get_receive_address` with `group_name` shows (and returns) any
address of a registered group.

On Ruby: **Options > Wallet > Registered Wallets** lists the groups first ("View Group"): the summary and the first address,
and **Delete Group**. The multisig and descriptor wallets follow ("Other wallets").

### 3.7 The change in a payment (`sign_psbt`)

For each input Ruby signs as a group input (2.1 or 2.2), it looks for the registered group whose address at Ruby's
key path (chain path + `/i`) is the coin spent. The group's own addresses are recognised in the outputs **only if
every input signed is of that same group** (any other input, or two groups, and nothing is recognised). An output
is the group's when it carries Ruby's key with its path (`PSBT_OUT_TAP_BIP32_DERIVATION`, which the wallet adds) and
Ruby calculates exactly that output's script from the record at that path:

- on the **change** chain: it is change: not shown, and not counted in the amount sent;
- on the **receiving** chain: it is shown, marked as the wallet's own.

An output to another group, even one registered on Ruby, is shown as a payment.

### 3.8 The wallet side

`DistricutedCryptographyLib` (NBitcoin fork): `RubyClient.RegisterGroup / GetRegisteredGroups / GetGroupAddress`;
`DelegatedMultiSigSpend.RubyGroupRecord / RegisterGroupWithRuby`. The payments with Ruby
(`OwnerSpendWithRuby`, `SignSpendWithRuby`) register the group the first time (the user confirms on Ruby; if he
declines, the payment goes on and Ruby shows the change), and add Ruby's key and path to the change output (the
index of the change address is searched on the group's change chain, up to 2000).

## 4. For developers: two allow-lists of Jade

Jade only runs functions it lists, and a function missing from a list stops the device (an assertion: on a CI build
it just stops answering, with no log):

- a **reply** encoder passed to `jade_process_reply_to_message_result` must be in `reply_fn_is_allowed`
  (`main/process.c`): `reply_registered_groups` and `reply_musig2_nonces` are there;
- a function run on a **temporary stack** (`run_in_temporary_task`) must be in the list of `temp_task_wrapper`
  (`main/utils/temporary_stack.c`): `group_get_script_task`, `musig2_check_task`, `musig2_nonce_task` and `musig2_sign_task` are there.

To see such an assertion, build the CI emulator with `--log-cbor`: the log comes over the RPC connection (jadepy
logs it; `RubyClient.Log` receives it).

## 5. Tests

- MuSig2 (2026-11-17): `TESTRUBY_GROUPS=musig2 dotnet run -c Release -- groups tcp:127.0.0.1:<port>` (`MuSig2Tests`):
  registration of MuSig2 groups (Ruby's addresses = the library's, 2 to 15 signers, up to 462 leaves); the owner of
  an Advanced Delegated group pays alone; signing rooms with Ruby and software signers: Advanced Delegated by a leaf
  (Ruby first and last), Advanced Multi Signature by the key path (everybody) and by a leaf, all mined, the change
  recognised; refusals: nonces replaced by another payment, no second signature with the same nonces, a round 2
  without Ruby's own nonce (and no retry with it), Ruby not a signer, and the firmware's own checks with altered
  psbts (participants, aggregate key, a leaf not in the coin).

- `TestRuby` (NBitcoin fork), CI emulator with the firmware log over the RPC connection
  (`--dev --ci --m5basic --log-cbor`; without `--log-cbor` the checks that read the log are skipped):
  `dotnet run -c Release -- groups tcp:127.0.0.1:<port>`. `RunGroupRegistration`:
  Ruby's addresses equal the library's for Delegated and Multi Signature groups of 2 to 15 signers (up to 1 287
  leaves), receiving and change, several indices; refusals (no Ruby in the group, another network, more than 2000
  combinations); the change recognised in owner and member payments and not for another group's address (read in
  the emulator's UART log); registrations stop with the reserve free; another wallet does not see the records.
  2026-11-16: 54 PASS (`TESTRUBY_GROUPS=registration`); the whole `groups` suite 99 PASS; the general suite 85
  PASS.
- Firmware suite (`main/qemu/qemu_ci_flash.sh`, image `--dev --ci --psram`): unchanged (177 passed; the same 8
  failed + 6 errors, PIN / pinserver, as before these changes).
