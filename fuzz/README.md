# Fuzzing Ruby

Ruby signs whatever a host sends it, after the user confirms what Ruby shows. So the code that **reads data from the
host** is the attack surface: the CBOR of the RPCs, the PSBT and everything inside it, the group descriptions. This
folder fuzzes that code on a PC, where it runs thousands of times per second, with clang's
[libFuzzer](https://llvm.org/docs/LibFuzzer.html) plus AddressSanitizer and UndefinedBehaviorSanitizer. A fuzzer
mutates inputs, keeps the ones that reach new code, and stops at the first memory error, undefined behaviour, leak,
timeout or broken property (`abort()` in a harness).

Why and what, in the project docs: DistributedCryptography `docs/ideas-roadmap.md` §12.8 "Fuzzing the Ruby firmware".

## Layout

| Path | In git | What |
|---|---|---|
| `Makefile` | yes | builds every target into `fuzz/build/`; libwally is compiled **as on the device** (below) |
| `run.sh` | yes | builds, generates the seeds, replays the regressions, fuzzes each target for N seconds |
| `Dockerfile`, `Dockerfile.dockerignore` | yes | the same, in a container (Windows / macOS) |
| `harness/fuzz_*.c` | yes | Ruby's own targets (one `LLVMFuzzerTestOneInput` each) |
| `harness/fuzz_*.options` | yes (optional) | extra libFuzzer flags of one target, used by `run.sh` (eg. `-max_len` for operation sequences) |
| `rpc/fuzz_rpc.py` | yes | the RPC fuzzer on the QEMU emulator, with the "shown vs signed" oracle ("RPC fuzzer on the emulator") |
| `rpc/check_ripemd_alignment.py` | yes | the check of unaligned RIPEMD-160 input on the emulator (see "Why `AVOID_UNALIGNED_ACCESS`") |
| `rpc/check_refused_before_screens.py` | yes | the regression check of F3 on the emulator: malformed coin scripts refused before any screen |
| `harness/fw_amalgam.h`, `harness/fw_rpc.h` | yes | firmware code on the host: one translation unit as the firmware; an RPC request filtered as `wire.c` does |
| `stubs/` | yes | host stand-ins for the firmware functions the fuzzed code links against (below) |
| `tools/make_seeds.py` | yes | generates the seed corpus from test data already in the repo |
| `corpus/<target>/` | yes (optional) | hand-made seeds, e.g. CBOR requests captured from the C# tests (`--log-cbor` image) |
| `regressions/<target>/` | yes | every input that once failed; replayed before fuzzing, must pass |
| `known-issues.supp` | yes | LeakSanitizer suppressions for documented library bugs NOT reachable on Ruby |
| `build/`, `out/` | **no** | binaries, generated seeds; grown corpus, crash inputs, logs |

## Running

Windows / macOS (Docker), from the repo root:

```sh
docker build -t ruby-fuzz -f fuzz/Dockerfile .
docker run --rm -v ruby-fuzz-out:/ruby/fuzz/out ruby-fuzz 300                 # 5 min per target
docker run --rm -v ruby-fuzz-out:/ruby/fuzz/out ruby-fuzz 600 fuzz_psbt_ruby_flags   # one target
```

The named volume `ruby-fuzz-out` keeps the grown corpus between runs. To get a crash input out of it:
`docker run --rm -v ruby-fuzz-out:/ruby/fuzz/out --entrypoint sh ruby-fuzz -c 'cat fuzz/out/crashes/<target>/<file>' > crash.bin`
(bind mounts from Windows are avoided on purpose, as in the firmware builds).

Linux (clang, make, python3, git, libmbedtls-dev; the first build fetches tinycbor 0.6.1 with git):

```sh
sh fuzz/run.sh 300                       # all targets
sh fuzz/run.sh 60 fuzz_tx_from_bytes     # one target
fuzz/build/<target> path/to/input        # replay one input, full sanitizer report
```

`run.sh` prints one line per target: `PASS <target>: <runs> runs in <s>s, coverage <edges> edges, corpus <n> inputs`
or `FAIL <target>: <sanitizer and kind> (Seed: N); input saved in out/crashes/<target>/`.

**CI**: `.github/workflows/fuzz.yml` runs every target 60 s on every push / pull request and 30 min each night
(manual runs choose the time). The grown corpus is kept in the Actions cache.

## libwally as on the device

`Makefile` compiles `components/libwally-core/upstream/src/amalgamation/combined.c` (the file the ESP-IDF component
compiles) with the defines of `components/libwally-core/CMakeLists.txt`: `BUILD_MINIMAL`, no `BUILD_ELEMENTS` (Ruby
is Bitcoin only), secp256k1-zkp modules ECDH, ECDSA_S2C, EXTRAKEYS, **MUSIG**, RECOVERY, SCHNORRSIG,
`ECMULT_WINDOW_SIZE=8`, `NDEBUG`, and Ruby's `config.h`. Differences, all harmless for parsing code: clang on x86-64
instead of xtensa gcc (so secp256k1 uses its 64-bit field and x86-64 asm on the PC), libwally's own SHA-256/512
instead of mbedTLS, and `AVOID_UNALIGNED_ACCESS`.

**Why `AVOID_UNALIGNED_ACCESS`.** `components/libwally-core/config.h` (Jade's file) sets `HAVE_UNALIGNED_ACCESS 1`, so
ccan's SHA-256, SHA-512 and RIPEMD-160 cast unaligned input to `uint32_t *` when they hash 64 bytes or more straight
from the caller's buffer. On x86-64 that only makes UBSan complain ("load of misaligned address", first 5-minute run,
`sha256.c:121`, while hashing PSBT data); libwally provides `AVOID_UNALIGNED_ACCESS` for sanitizer builds, so the
host build uses it. On the device SHA-256/512 are mbedTLS, not this code, but **RIPEMD-160 is ccan's**. Checked
2026-11-23, **safe on the ESP32**:

- *Who can reach it.* HASH160 hashes a 32-byte digest (never that path), but libwally verifies a psbt's
  `PSBT_IN_RIPEMD160` preimage **while parsing the psbt** (`pull_preimage` → `map_add` →
  `wally_map_hash_preimage_verify` → `wally_ripemd160`) on a pointer into the bytes the host sent, before any
  screen. A preimage of 128 bytes or more has its second and later blocks read in place as `uint32_t`, at whatever
  alignment the host chose. That is the only host-reachable caller (`bip38.c` is not used by Ruby).
- *What the ESP32 does.* Its Xtensa core is configured with `XCHAL_UNALIGNED_LOAD_HW 1` and
  `XCHAL_UNALIGNED_LOAD_EXCEPTION 0` (ESP-IDF `components/xtensa/esp32/include/xtensa/config/core-isa.h`): unaligned
  loads from data RAM work in hardware, no exception and no misread. So `HAVE_UNALIGNED_ACCESS 1` is right for it.
- *On the emulator* (`rpc/check_ripemd_alignment.py`, image `--dev --ci --m5basic --log-cbor`): a payment whose input
  carries a `PSBT_IN_RIPEMD160` field with a 63-, 200- and 1000-byte preimage, shifted by 1 to 4 bytes (every
  alignment): the right preimage is accepted (signed) and a wrong one refused ("Failed to extract psbt") at every
  alignment; no crash. (An empty proprietary value used for the first shift made libwally refuse the whole psbt: a
  test artefact, fixed.)

**Which safegcd runs on the device** (checked 2026-11-18, roadmap §12.8): `modinv32`. The xtensa compiler of the
image (`xtensa-esp32-elf-gcc` 14.2.0) does not define `__SIZEOF_INT128__` and has 32-bit pointers, so
`src/secp256k1/src/util.h` selects `SECP256K1_WIDEMUL_INT64`: field 10x26 and scalar 8x32, both on
`modinv32_impl.h`. The firmware ELF (`build/jade.elf` of image `ruby-qemu-ci-m5:musig2c-log`) has
`secp256k1_modinv32` (constant time, used to sign) and `secp256k1_modinv32_var` (used to verify) and no
`modinv64` symbol. So none of the code on the device is the `secp256k1_modinv64_var` proved in Coq by Blockstream
Research.

## Firmware code on the host

From step 2 on, the harnesses test Ruby's own code: the **real firmware files**, `#include`d by the harness, not
copies. What makes that work:

- **One translation unit, as the firmware.** The firmware is built as `main/amalgamated.c`: libwally's `combined.c`
  first, then every firmware file. Some firmware code relies on it (it calls libwally functions only that unit sees,
  such as `wally_psbt_get_input_best_utxo`). `harness/fw_amalgam.h` does the same, and those harnesses
  (`FW_TARGETS` in the Makefile) are not linked with `build/wally.o`. libwally gets the same defines as above.
- **ESP-IDF and FreeRTOS** come from `libjade/include`, Jade's own host shims (`libjade/` builds the firmware as a
  native library). Built with `CONFIG_LIBJADE_NO_SPIRAM`, so message sizes are those of the reference board
  (M5Stack Basic, no PSRAM). `pdMS_TO_TICKS`, used by `musig2.c`, is missing there and defined in `fw_amalgam.h`.
- **tinycbor 0.6.1**: the firmware's `espressif/cbor 0.6.1~4` has exactly these sources (checked file by file against
  the managed component of the firmware image), built with the firmware's `CBOR_PARSER_MAX_RECURSIONS=20`; the
  Makefile fetches commit `c0aad2fb` once. `main/utils/cbor_rpc.c` is the firmware's.
- **A request reaches a handler as on Ruby**: `harness/fw_rpc.h` repeats `wire.c` (`cbor_parser_init`, the whole
  value advances, it is a map, `rpc_request_valid`) and `GET_MSG_PARAMS` before a harness hands the params to the
  handler's parser. A harness therefore reports only what a host could make Ruby run.
- **`stubs/firmware_stubs.c`**: `jade_abort`, `get_random` (pseudo-random from the input: reproducible, never
  degenerate), `keychain_get_new_privatekey` (the firmware's), `sensitive_push` / `sensitive_pop` with the firmware's
  checks (32 items, LIFO, wiped; the harnesses also check the stack is empty after each call), and abort-if-reached
  stand-ins for processes, screens, keychain and storage: a harness that reaches one fails loudly instead of testing
  a fake. A harness that needs a test wallet defines `keychain_get` and the few wallet / storage functions it uses,
  copied from the firmware (`fuzz_register_group.c`, `fuzz_musig2_session.c`). The FreeRTOS clock
  (`xTaskGetTickCount`) only moves when a harness moves it (`fuzz_ticks_set` / `fuzz_ticks_advance`) and wraps at 32
  bits as on the ESP32 (`TickType_t` is 64 bits in `libjade/include`).
- mbedTLS: the host's (`libmbedtls-dev` 2.28) for AES-GCM in `seed_split`; the device has ESP-IDF's mbedTLS 3.6, the
  same GCM API.

Two kinds of input in every firmware harness, picked by the first byte: **RAW** (what a host sends, mutated freely:
memory safety and invariants of whatever is accepted) and **STRUCTURED** (the harness builds a valid request from the
input, optionally with one input-chosen *break*, and checks that Ruby accepts it exactly when there is no break, then
checks the result end to end). Random bytes almost never form a valid MuSig2 aggregate, Taproot commitment or xpub,
so STRUCTURED is what reaches the code that decides what Ruby signs.

## Targets

| Target | Source | What it reads | Seeds |
|---|---|---|---|
| `fuzz_psbt_from_bytes` | libwally `upstream/fuzz/` (unchanged) | a PSBT, with STRICT, LOOSE and default flags, then serialises it | the PSBTs of libwally's `psbt.json` + those of `tests/rpc/data/sign_psbt/` (294 distinct seeds on libwally 1.6.1) |
| `fuzz_tx_from_bytes` | libwally `upstream/fuzz/` (unchanged) | a transaction, with every tx flag | the transactions inside those PSBTs |
| `fuzz_psbt_ruby_flags` | `harness/` | a PSBT **as Ruby accepts it** (`deserialise_psbt()`: STRICT \| COMPLETE parse that also serialises, see F2), then `serialise_psbt()`; checks that what Ruby sends back parses again and serialises to the same bytes | same PSBTs |
| `fuzz_codex32` | `harness/`, `main/codex32.c` | COMBINE: any set of strings (the shares a user types); SPLIT: seed, k, n, identifier and randomness from the input. Checks: any k shares (any order, also UPPERCASE) and all n give the seed back, k-1 do not, 1 to 4 changed characters in a share are always refused | the BIP-93 strings of `tests/codex32/` |
| `fuzz_restore_seed` | `harness/`, `main/process/restore_seed.c` (+ `seed_split.c`) | RAW: the encrypted seed of `restore_seed_data`. STRUCTURED: a seed encrypted as the wallet does (BIE1); checks it decrypts to the same seed, and that a changed byte, one byte more or less, or another Ruby key are refused | hand-made |
| `fuzz_seed_split` | `harness/`, `main/process/seed_split.c`, `main/codex32.c` | RAW: whole `seed_split` requests. STRUCTURED: requests with contacts whose private keys the harness knows, valid or not; checks Ruby accepts exactly the valid ones, then decrypts every contact's shares as the contact does (BIE1 key, AES-256-GCM text, JSON array), checks the share counts, and that all of them and any k of them give the seed (backup) or the pad that, XOR `masked`, is the seed (vault) | hand-made CBOR requests |
| `fuzz_psbt_taproot` | `harness/`, `main/utils/psbt.c`, `main/musig2.c` | RAW: PSBTs through `key_iter_is_supported_taproot()` and `musig2_input_load()` (each participant and each Taproot key as ours). STRUCTURED: one valid input of each kind Ruby signs (key path with scripts, multi_a leaf, TEV bounty leaf, MuSig2 key path, MuSig2 leaf) or the same with one of 14 breaks; Ruby must accept exactly the valid ones; on a MuSig2 key path, libsecp256k1's MuSig2 tweak must agree with libwally's BIP341 tweak | the PSBTs above + one input per kind and break |
| `fuzz_register_group` | `harness/`, `main/process/register_group.c`, `main/group.c` | RAW: whole `register_group` requests. STRUCTURED: the 4 group types, 2-6 signers, this Ruby as owner or signer, or one of 18 breaks; Ruby must accept exactly the valid ones; an accepted group must give P2TR addresses on both chains (deterministic, path back to chain and index) and a storage record that round-trips and refuses any changed byte | one input per type and break |
| `fuzz_musig2_session` | `harness/`, `main/musig2.c`, `main/utils/psbt.c` | MuSig2 signing sessions: a payment (1-4 inputs: MuSig2 key path or leaf, another wallet's MuSig2 input, a plain input of ours; 2-5 participants) and up to 16 input-chosen operations: round 1 (`musig2_create_nonces`) on the payment or a variant (other amount, coin amount, lock time, sequence, extra field, one input less, one output more), round 2 (`musig2_sign_input`, as `sign_psbt` calls it) with every cosigner's real nonce or ONE tamper (our nonce swapped or missing, a cosigner's missing / wrong length / not a point / a copy of ours / chosen so the aggregate nonce is infinity), `sign_psbt`'s loop and cleanup, round 2 on a psbt with changed bytes, `musig2_clear`, the clock moved to just inside / outside the nonces' lifetime (also across the 32-bit wrap). A model of what Ruby holds predicts every result. Checked: **no secret nonce ever signs twice**; after round 2 of an input its nonce is all zeroes, after a clear or a failed round 1 there is none; every nonce is new; the message kept is the input's BIP341 sighash; a partial signature verifies (BIP327) and, with honest cosigners, the aggregate is a valid BIP340 signature for the coin; Ruby adds exactly one field; a changed-bytes psbt is signed only for round 1's message and nonce | hand-made sequences (`make_seeds.py`) |

Results of 2026-11-18 (Docker on the Windows dev PC, one core per target, 300 s each, after the fixes below), all PASS:

| Target | Runs | Coverage (edges) | Corpus |
|---|---|---|---|
| `fuzz_psbt_from_bytes` | 3 010 618 | 1 234 | 2 180 |
| `fuzz_tx_from_bytes` | 28 120 326 | 411 | 1 768 |
| `fuzz_psbt_ruby_flags` | 8 632 850 | 1 231 | 1 748 |

Same run on libwally `release_1.6.1` (branch `libwally-1.6.1`, no LSan suppression, fresh corpus, the QEMU suite
running on the same PC at the same time), all PASS:

| Target | Runs | Coverage (edges) | Corpus |
|---|---|---|---|
| `fuzz_psbt_from_bytes` | 2 990 058 | 1 249 | 1 459 |
| `fuzz_tx_from_bytes` | 18 807 076 | 411 | 1 673 |
| `fuzz_psbt_ruby_flags` | 6 035 788 | 1 234 | 1 082 |

On the way there: F1 at once (initial corpus), F2 within seconds, and UBSan "misaligned load" in ccan's SHA-256
within 5 minutes (host-only, see "Why `AVOID_UNALIGNED_ACCESS`").

Step 2, 2026-11-23 (Ruby 1.0.1, libwally `release_1.6.1`), all PASS. Long runs during development (Docker on the
Windows dev PC, three targets at a time) and the clean image (`docker build` + `run.sh 120`, fresh corpus):

| Target | Development run | Clean image, 120 s | Coverage (edges) |
|---|---|---|---|
| `fuzz_codex32` | 366 586 runs / 180 s | 254 609 | 241 |
| `fuzz_restore_seed` | 160 554 / 90 s | 286 023 | 378 |
| `fuzz_seed_split` | 2 349 665 / 600 s (+ 220 000 / 300 s) | 412 911 | 993 |
| `fuzz_psbt_taproot` | 3 736 927 / 420 s | 923 956 | 1 664 |
| `fuzz_register_group` | 87 120 / 420 s | 20 681 | 1 177 |

`fuzz_register_group` is slow on purpose: every accepted group computes real addresses (up to `LEAF_CAP` = 256
leaves, KeyAgg per leaf for the MuSig2 types) and its storage record. Before the fuzzing, every STRUCTURED kind and
break was run once by hand (`FUZZ_TRACE=1 fuzz/build/<target> <input>` prints what each STRUCTURED input checked):
`fuzz_psbt_taproot` 5 kinds valid + every applicable break (39 cases), `fuzz_register_group` 4 types + 18 breaks,
`fuzz_seed_split` a 2-of-3 backup (32-byte seed) and a 3-of-6 vault (64-byte seed) decrypted and combined.

Step 3, 2026-11-23 (Ruby 1.0.1 + step 2), `fuzz_musig2_session`, PASS: 43 826 sequences in 600 s, then 48 342 in
1 200 s with longer inputs (`fuzz_musig2_session.options`: `-max_len=160`; a whole input, 4 inputs + 16 operations,
is 121 bytes), coverage 1 827 edges, corpus 828. It is slow on purpose (40-70 sequences/s): every operation builds
the payment again, derives keys and makes real nonces and signatures. Before the fuzzing, by hand (`FUZZ_TRACE=1`):
a 2-of-2 key path, a 3-of-3 leaf at depth 2, 4 inputs (key path 5 participants with merkle root, leaf depth 3,
another wallet's input, key path), a plain input of ours (round 1 refused), round 2 twice (second refused), every
tamper (refused except "copy of ours" and "infinity", which BIP327 allows), variants between rounds, and the
lifetime: signed at exactly 600 000 ticks after round 1, refused one tick later, with the 32-bit tick count wrapping
in between. Clean image (`docker build` + `run.sh 120`, fresh corpus), every target PASS; `fuzz_musig2_session`
10 633 sequences, 1 696 edges (`fuzz_seed_split` was re-run after a clock jump: 471 238 runs, 998 edges).

**Docker Desktop's clock.** On the Windows dev PC the container clock sometimes jumps: libFuzzer then reports
"Done N runs in -10 second(s)", stops right after loading the seeds (a PASS with a few runs and an empty corpus), and
saves `slow-unit-*` files for inputs that take milliseconds. Re-run that target; the CI (Linux) is not affected.

## RPC fuzzer on the emulator

The host harnesses above test functions; `rpc/fuzz_rpc.py` tests **the whole firmware** on the QEMU emulator, with
the question a hardware wallet must answer: *does it sign what it showed?* (not only "does it refuse what it should").
For Ruby that matters most for what it hides: its own change and the change of a registered group (RUBY-GROUPS.md).

- **What the screens show.** The CI build (`--ci`) confirms its own screens. With `CONFIG_DEBUG_UNATTENDED_CI` it
  also logs what each review screen shows (`CI_SHOWN` in `main/ui/sign_tx.c`: `SHOWN outputs <n> of <total>`,
  `SHOWN output <i> <address> <amount>[ verified][ warning=...]` or `SHOWN output <i> hidden`, `SHOWN fee <amount>`,
  `SHOWN fee option <i> ...`); built with `--log-cbor` the log comes over the RPC connection. No device build has it.
- **The requests.** Ruby's wallet is a fixed test mnemonic (`debug_set_mnemonic`, dev builds). Three Delegated groups
  are registered (`register_group`): Ruby the owner (`fz-owner`), Ruby a member (`fz-member`), Ruby the owner of
  another one (`fz-other`); their addresses are computed in Python from the xpubs as RUBY-GROUPS.md defines them and
  checked against Ruby's `get_receive_address` at start. Each request is a valid payment (P2WPKH or P2TR coins of
  the wallet, or coins of a group by the key path or a leaf; a payee; a change output) changed by 0-3 mutations: the
  change's index or chain moved (key kept consistent), its script replaced (payee, another group's change, the same
  key in another script type), another group's change with a valid path, a mixed input added (a single-key coin, a
  coin of another group), amounts (0, dust, overflow, more than the inputs), an extra output (OP_RETURN, empty,
  non-standard, foreign script with our path), the output's key path broken (fingerprint, a second key, leaf
  hashes, hardened), input fields (no utxo, wrong merkle root, sighash, leaf, utxo script), transaction fields
  (lock time, version, sequence, a duplicated input, outputs reordered), and 1 in 10 also gets random bytes
  flipped. The psbt is written in Python field by field, so any field can be broken.
- **The oracle**, for every request Ruby signs:
  - SAFETY: every output is shown or hidden; a shown one has the transaction's address and amount; a hidden one is
    provably this Ruby's: one of its keys (derived in Python from the mnemonic) at the psbt's path in a standard
    script of that key, or the address of a registered group at that path; the fee shown is inputs - outputs; Ruby
    returns the same transaction and coins; every signature it added verifies (BIP143 / BIP341 computed in Python)
    for that transaction and key; Ruby never stops answering.
  - DESIGN: a hidden output that is ours but should have been shown (a receiving address; a group's change while
    the inputs Ruby signs are not all of that group); and, for a request Ruby refuses, a refusal after the review
    screens (the CI build confirms every screen, so the user would have confirmed for nothing, as F2 and F3 did).
  - NOTE (counted, not a finding): Ruby signed an input whose coin is not a script of the signing key. Jade does the
    same; the signature commits to that coin's script, so it can spend nothing.
- **The oracle is tested** (`--selftest N`): N valid payments are signed, then each exchange is altered (a payee
  hidden, an amount or the fee shown 1 sat lower, no screens, a signature byte changed) and the oracle must flag
  every altered one and none of the valid ones.

Run (the image takes a while to build the first time):

```sh
docker build -t ruby-qemu-ci-m5:fuzz -f Dockerfile.qemu --build-arg QEMU_CONFIG_ARGS="--dev --ci --m5basic --log-cbor" .
docker run -d --name ruby-rpc-fuzz ruby-qemu-ci-m5:fuzz           # the emulator, tcp 30121 inside the container
docker exec -w /jade ruby-rpc-fuzz sh -c '/opt/esp/python_env/*/bin/python fuzz/rpc/fuzz_rpc.py --selftest 12'
docker exec -w /jade ruby-rpc-fuzz sh -c '/opt/esp/python_env/*/bin/python fuzz/rpc/fuzz_rpc.py --seconds 3600 --out /tmp/rpc'
docker exec -w /jade ruby-rpc-fuzz sh -c '/opt/esp/python_env/*/bin/python fuzz/rpc/fuzz_rpc.py --replay /tmp/rpc/findings/1.json'
```

`--seed N` repeats a run; `--qemu` starts (and after a crash restarts) QEMU itself, as the CI job does. Output:
`findings/<n>.json` (severity, problems, mutations, the psbt, Ruby's reply and log) and `stats.json` (requests,
signed, refused by error, findings, outputs shown / hidden by kind). About 2 requests per second.

**CI**: job `rpc-fuzzer` of `.github/workflows/fuzz.yml`, every night (2 h) and by hand: builds the image, runs
`fuzz_rpc.py --qemu`, prints the counts only (public repo) and fails on a SAFETY finding. Refusals with an internal
error (`-32603`) are saved in `internal/` to look at (not findings).

Results, 2026-11-23 (Ruby 1.0.1 + `CI_SHOWN`, image `--dev --ci --m5basic --log-cbor`, Docker on the Windows dev
PC): `--selftest 12`: 58 altered exchanges, all flagged; no valid one flagged. A 40-minute run: 4 257 requests,
3 692 signed (single key P2WPKH 619, P2TR 594; groups: owner 825, member 802, another owned group 852), 565
refused; 5 722 outputs shown, 1 994 hidden and every hidden one provably Ruby's (706 own change, 1 288 group
change), no DESIGN case, no crash or hang; 38 NOTEs. One SAFETY report, the oracle's: an output `76a914<20>88ad`
(CHECKSIGVERIFY, made by a mutation) is no address and Ruby rightly showed "Unknown Address", but the oracle read it
as P2PKH; `address_of()` now checks the whole pattern, and the replay is clean. With that fix, a 20-minute run
(another seed): 2 098 requests, 1 842 signed, 1 022 hidden outputs all Ruby's, no finding; and 25 minutes on a third
emulator (seed 47): 2 673 requests, 2 345 signed, no finding (one `-32603`, see F3, now fixed).

**Open, not reproduced: one emulator stopped answering once.** In a third run, on a second emulator container that
had already served the RIPEMD-160 checks, Ruby stopped answering a group payment (`fz-other`, change moved to
another chain, two outputs replaced by group change) right after "Found suitable group record": no reply, no log, no
UART output, QEMU busy at ~80% CPU, no answer to any later request. Not reproduced: the same request on a fresh
emulator signs in under a second; the same seed from the start (the same sequence of requests), also after the
same RIPEMD-160 checks, runs 475-493 requests without a hang. So it may be the emulator (QEMU) rather than the
firmware (the emulator runs with the watchdog timer disabled, `qemu_run.sh`). A request that hangs Ruby is now
saved with the 30 requests before it (`previous_psbts`, replayed in order by `--replay`), and without `--qemu` the
run stops there.

## Findings

**F1: leak in libwally's loose PSBT parsing. Not reachable on Ruby; fixed by libwally 1.6.1.** `fuzz_psbt_from_bytes`, in its
initial corpus (libwally's own vector "PSBTv0 but with PSBT_GLOBAL_VERSION set to 2"): with
`WALLY_PSBT_PARSE_FLAG_LOOSE`, a PSBT that has `PSBT_GLOBAL_UNSIGNED_TX` *before* `PSBT_GLOBAL_VERSION = 2` makes
`psbt_set_global_tx()` allocate the input/output arrays and the v2 path overwrite them (984 bytes per PSBT). Ruby
parses every PSBT with STRICT | COMPLETE, which refuses it first. Fixed in libwally 10f41d80 (2026-11-08,
`release_1.6.1`). It was suppressed in `known-issues.supp` while the submodule was `release_1.5.6-11-g3bf543cd`; since
the submodule moved to `release_1.6.1` (2026-11-18, branch `libwally-1.6.1`) the suppression is gone and
`fuzz_psbt_from_bytes` passes without it.

**F2: Ruby accepted a PSBT it could not send back. Fixed in the firmware (2026-11-18).** `fuzz_psbt_ruby_flags`
after a few seconds (input: `regressions/fuzz_psbt_ruby_flags/f2-non-witness-utxo-without-outputs`): a PSBT whose
`PSBT_IN_NON_WITNESS_UTXO` is a transaction **with no outputs** passes STRICT | COMPLETE parsing (`wally_tx_from_bytes()`
accepts a transaction with no outputs even without `WALLY_TX_FLAG_ALLOW_PARTIAL`), but `wally_psbt_to_bytes()` refuses
it (`WALLY_EINVAL`: writing a transaction with no inputs or no outputs needs that flag). On libwally 1.5.6
`wally_psbt_get_length()` even returns a length for it; on 1.6.1 and master (2026-11-18) `get_length` fails too, but
the parser still accepts the PSBT. No memory error and no crash
(`serialise_psbt()` checks both calls), but `sign_psbt` went through the whole signing (review, confirmation,
signatures: the amounts and scripts come from `wally_psbt_get_input_best_utxo()`, which prefers the `witness_utxo`)
and only then answered `-32603 CBOR_RPC_INTERNAL_ERROR` "Failed to serialise sign psbt". Seen on the QEMU emulator
(image of `110ee7a9`, CI auto-confirm). A malicious or buggy host could only waste a confirmation (the signatures never
left Ruby).
Fix: `deserialise_psbt()` (`main/process/sign_psbt.c`, used by `sign_psbt`, `musig2_nonces`, QR and USB storage) also
serialises the PSBT once and refuses it when that fails, so the host gets `-32602 CBOR_RPC_BAD_PARAMETERS` "Failed to
extract psbt from passed bytes" before any screen (checked on the emulator). The harness now mirrors that check and
asserts that every PSBT Ruby accepts round-trips. Reported to libwally on 2026-11-23:
[ElementsProject/libwally-core#567](https://github.com/ElementsProject/libwally-core/issues/567), with a proposed fix
(`pull_psbt_input()` refuses a non-witness UTXO with no inputs or outputs).

**Step 2 (2026-11-23): no finding in Ruby's code.** One harness failure on the way was the harness's own: its first
`get_random` cycled the input bytes, so an input of zeros gave four invalid (all-zero) ephemeral keys in a row and
`seed_split` refused, correctly, with "Failed to encrypt the shares of a contact" (on the device the TRNG never does
that). `get_random` is now a PRNG seeded from the input.

**F3: an input whose coin script is malformed was refused only after the screens. Minor, as Jade; fixed in the
firmware (2026-11-24).**
`fuzz_rpc.py` (`internal/`): a P2WPKH payment where one input's `witness_utxo` script became `0021<20 bytes>` (a
push of 33 bytes with 20 left, from `flip_bytes`). `sign_psbt` treats it as one more script type ("Your transaction
inputs are of varying types" on the fee screen), shows the outputs and the fee, and only when signing that input
answers `-32603` "Failed to generate tx input hash". Nothing is signed and nothing leaves Ruby; a buggy or malicious
host only wastes a confirmation (as F2 did). 1 to 5 such answers per 2 000-4 000 requests.
Fix (2026-11-24): `sign_psbt()` (`main/process/sign_psbt.c`) computes the signature hash of every input it signs
with a single signature (not MuSig2, not script path) before the screens and keeps it for the signing, so such an
input is refused with `-32602` "Failed to generate tx input hash" and no screen. `rpc/check_refused_before_screens.py`
sends 5 kinds of bad coin script on either input: before the fix all 10 payments were refused after the screens,
after it all 10 before any screen. `fuzz_rpc.py` now reports any refusal after the screens as DESIGN; 20 minutes
with the fix (seed 61): 1 962 requests, 1 720 signed, no finding, no `-32603`. Also checked with the fix: TestRuby
general 154, groups 99, musig2 82, bounty 12, all PASS; Jade's suite 177 pass with the same 8 + 6 PIN / pinserver
failures as before (23 `test_sign_psbt` tests pass).

**Steps 3 and 4 (2026-11-23): no finding in Ruby's code.** The MuSig2 sessions never reused a secret nonce and
behaved as the model said in every sequence; the emulator never signed anything it did not show, never hid an
output that is not its own, and always showed the real fee. What the runs did show, all as Jade does:

- Ruby signs an input whose coin is not a script of the signing key (a P2WPKH coin of another hash with our key
  path): the signature commits to that coin's script and can spend nothing (NOTE in `fuzz_rpc.py`).
- MuSig2 round 2 accepts a cosigner nonce that is a copy of Ruby's, or one that makes the aggregate nonce the point
  at infinity: BIP327 allows both, the partial signature is valid, and Ruby's secret nonce is still used once.
- A failed round 2 of an input (a nonce missing, ours swapped) uses up Ruby's nonce of that input: the payment
  must start again from round 1 (the safe choice: a nonce never meets two different sets of cosigner nonces).

## Crashes in a public repo

This repository is public, and a crash input for the firmware is an exploit hint. So:

- `run.sh` with `CI=true` (GitHub Actions) prints only the target, the kind of error and the libFuzzer seed; the CI
  never uploads crash inputs or sanitizer reports.
- Reproduce locally, fix, and only then commit the input to `regressions/<target>/` together with the fix.
- If a crash can leak keys, sign something not shown, or brick the device, do not open a public issue: tell the
  maintainers privately first (see SECURITY.md for Jade's own code).
- `known-issues.supp` is only for library bugs that Ruby cannot reach, each with its proof and its removal
  condition. Never suppress a bug of Ruby's own code.

## Adding a target

1. `harness/fuzz_<name>.c` with `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`; the Makefile picks it
   up and links it with libwally, tinycbor, `cbor_rpc.c` and `stubs/`. For firmware code: include
   `fw_amalgam.h` first, then the firmware `.c` files, and add the target to `FW_TARGETS` (see "Firmware code on
   the host"); feed handlers whole requests through `fw_rpc.h`.
2. Turn the security property into an `abort()` (e.g. "never signs an input it refused", "the change it hides really
   pays to the group"), not only memory safety.
3. Seeds: extend `tools/make_seeds.py`, or add files to `corpus/fuzz_<name>/`.
4. Run it for a while locally before pushing (`sh fuzz/run.sh 600 fuzz_<name>`). Extra libFuzzer flags of that
   target go in `harness/fuzz_<name>.options` (one line).

## Next steps (roadmap §12.8 order)

1. ~~libwally's fuzzers + confirm `modinv32`~~ done 2026-11-18 (this folder; F1, F2 fixed in the firmware). The
   left-over check of unaligned RIPEMD-160 input on the ESP32 done 2026-11-23: safe (see "Why
   `AVOID_UNALIGNED_ACCESS`").
2. ~~Host harnesses for Ruby's own parsers~~ done 2026-11-23: `musig2.c` (`musig2_input_load` / `_check`), the
   Taproot checks of `utils/psbt.c` (key path with scripts, multi_a and TEV bounty leaves), `register_group` /
   `group.c`, and the code added in Ruby 1.0.0: `codex32.c`, `seed_split`, `restore_seed`.
3. ~~Stateful fuzzing of the MuSig2 secret nonces~~ done 2026-11-23: `fuzz_musig2_session` (round 1, round 2 with
   the 0x1b / 0x1c fields, `sign_psbt`'s loop and cleanup, clear, the clock).
4. ~~RPC fuzzer against the QEMU emulator with a "shown vs signed" oracle~~ first version 2026-11-23: `rpc/`,
   nightly job `rpc-fuzzer`. Not covered by it yet, in order of value: MuSig2 payments over the RPCs
   (`musig2_nonces` then `sign_psbt`; the nonce logic itself is `fuzz_musig2_session`), Multi Signature and MuSig2
   groups (their internal key is a KeyAgg, not in the Python oracle yet), group fee options (`fee_options`), the TEV
   bounty leaf, and requests other than `sign_psbt` (`register_group`, `seed_split`, `restore_seed` over the wire:
   their parsers are fuzzed on the host).
