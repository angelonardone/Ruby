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
| `stubs/` | yes (later) | small replacements of ESP-IDF / NVS / storage calls, for harnesses over `main/` code |
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

Linux (clang, make, python3):

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
host build uses it. On the device SHA-256/512 are mbedTLS, not this code, but **RIPEMD-160 is ccan's**: whether
an unaligned 32-bit load faults or misreads on the ESP32's Xtensa core, and whether any caller passes RIPEMD-160 an
unaligned buffer of 64 bytes or more (HASH160 hashes a 32-byte digest, which never takes that path), is still to be
checked (next steps).

**Which safegcd runs on the device** (checked 2026-11-18, roadmap §12.8): `modinv32`. The xtensa compiler of the
image (`xtensa-esp32-elf-gcc` 14.2.0) does not define `__SIZEOF_INT128__` and has 32-bit pointers, so
`src/secp256k1/src/util.h` selects `SECP256K1_WIDEMUL_INT64`: field 10x26 and scalar 8x32, both on
`modinv32_impl.h`. The firmware ELF (`build/jade.elf` of image `ruby-qemu-ci-m5:musig2c-log`) has
`secp256k1_modinv32` (constant time, used to sign) and `secp256k1_modinv32_var` (used to verify) and no
`modinv64` symbol. So none of the code on the device is the `secp256k1_modinv64_var` proved in Coq by Blockstream
Research.

## Targets

| Target | Source | What it reads | Seeds |
|---|---|---|---|
| `fuzz_psbt_from_bytes` | libwally `upstream/fuzz/` (unchanged) | a PSBT, with STRICT, LOOSE and default flags, then serialises it | the 248 PSBTs of libwally's `psbt.json` + the 21 PSBTs of `tests/rpc/data/sign_psbt/` |
| `fuzz_tx_from_bytes` | libwally `upstream/fuzz/` (unchanged) | a transaction, with every tx flag | the transactions inside those PSBTs |
| `fuzz_psbt_ruby_flags` | `harness/` | a PSBT **as Ruby accepts it** (`deserialise_psbt()`: STRICT \| COMPLETE parse that also serialises, see F2), then `serialise_psbt()`; checks that what Ruby sends back parses again and serialises to the same bytes | same PSBTs |

Results of 2026-11-18 (Docker on the Windows dev PC, one core per target, 300 s each, after the fixes below), all PASS:

| Target | Runs | Coverage (edges) | Corpus |
|---|---|---|---|
| `fuzz_psbt_from_bytes` | 3 010 618 | 1 234 | 2 180 |
| `fuzz_tx_from_bytes` | 28 120 326 | 411 | 1 768 |
| `fuzz_psbt_ruby_flags` | 8 632 850 | 1 231 | 1 748 |

On the way there: F1 at once (initial corpus), F2 within seconds, and UBSan "misaligned load" in ccan's SHA-256
within 5 minutes (host-only, see "Why `AVOID_UNALIGNED_ACCESS`").

## Findings

**F1: leak in libwally's loose PSBT parsing. Not reachable on Ruby; fixed upstream.** `fuzz_psbt_from_bytes`, in its
initial corpus (libwally's own vector "PSBTv0 but with PSBT_GLOBAL_VERSION set to 2"): with
`WALLY_PSBT_PARSE_FLAG_LOOSE`, a PSBT that has `PSBT_GLOBAL_UNSIGNED_TX` *before* `PSBT_GLOBAL_VERSION = 2` makes
`psbt_set_global_tx()` allocate the input/output arrays and the v2 path overwrite them (984 bytes per PSBT). Ruby
parses every PSBT with STRICT | COMPLETE, which refuses it first. Fixed in libwally 10f41d80 (2026-11-08,
`release_1.6.1`); our submodule is `release_1.5.6-11-g3bf543cd`. Suppressed in `known-issues.supp` until the submodule
reaches 1.6.1 (upstream Jade bumps it; we merge upstream).

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
asserts that every PSBT Ruby accepts round-trips. Worth reporting to libwally as well (parser and serialiser
disagree).

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
   up and links it with libwally (and later `stubs/`). Prefer pure functions over libwally structs.
2. Turn the security property into an `abort()` (e.g. "never signs an input it refused", "the change it hides really
   pays to the group"), not only memory safety.
3. Seeds: extend `tools/make_seeds.py`, or add files to `corpus/fuzz_<name>/`.
4. Run it for a while locally before pushing (`sh fuzz/run.sh 600 fuzz_<name>`).

## Next steps (roadmap §12.8 order)

1. ~~libwally's fuzzers + confirm `modinv32`~~ done 2026-11-18 (this folder; F1, F2 fixed in the firmware).
   Left over: on the QEMU image, check what an unaligned 32-bit load does on the ESP32 and list the callers of
   `wally_ripemd160` / ccan `ripemd160` with 64+ bytes (see "Why `AVOID_UNALIGNED_ACCESS`").
2. Host harnesses for Ruby's own parsers: `main/musig2.c` (`musig2_input_load` / `musig2_input_check`, the BIP373
   fields 0x1a / 0x1b / 0x1c that libwally keeps as unknowns), the Taproot checks of `main/utils/psbt.c`
   (`key_iter_is_taproot_keypath_with_scripts`, `key_iter_is_taproot_scriptpath`), the group parser of
   `register_group` (`main/group.c`).
3. Stateful fuzzing of the MuSig2 secret nonces (sequences of `musig2_nonces` / `sign_psbt` / lock / timeout; property:
   no two partial signatures from the same secret nonce).
4. Nightly RPC fuzzer against the QEMU emulator with a "shown vs signed" oracle.
