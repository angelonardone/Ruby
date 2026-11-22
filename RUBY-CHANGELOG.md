# Ruby changelog

Ruby's own versions. [CHANGELOG.md](./CHANGELOG.md) is Jade's (upstream) changelog and is kept as it is.

The firmware version shown on the device and returned as `JADE_VERSION` by `get_version_info` is the nearest
`ruby-*` git tag (see the top of [CMakeLists.txt](./CMakeLists.txt)): `ruby-1.0.0` for the release,
`ruby-1.0.0-3-gabcdef12` for a development build 3 commits later, plus `-dirty` when a source file was changed.
Jade's tags (`1.0.41`, …) are ignored, so merging upstream Jade does not change Ruby's version. The protocol keeps
Jade's names (`JADE_VERSION`, `JADE_STATE`, …) on purpose: clients depend on them.

## [ruby-1.0.1] - 2026-11-21

ruby-1.0.0 plus:

- **Time Encrypted Vault bounty** ([RUBY-GROUPS.md §2.2b](./RUBY-GROUPS.md)): Ruby signs the bounty leaf
  (`<date> CHECKLOCKTIMEVERIFY DROP HASH256 <hash> EQUALVERIFY <key> CHECKSIG`) by the script path, so a Ruby wallet
  that is a bounty member can collect the bounty.

## [ruby-1.0.0] - 2026-11-21

First Ruby version. Based on **Blockstream Jade 1.0.41** (all of its security fixes) and **libwally-core 1.6.1**.
Reference hardware: **M5Stack Basic Core v2.7** (no PSRAM, no camera, USB only).

Ruby compared with Jade:

- **Bitcoin only**: Liquid / Elements removed (networks, confidential transactions, blinding keys, asset
  registry, PSET); libwally built without Elements.
- **Our device**: DistributedCryptography logo, texts say Ruby, help links go to distributedcryptography.com/ruby;
  M5Stack Basic layout, also in the QEMU web display; the emulator board runs the real board's code.
- **PIN oracle of the wallet**: the default PIN oracle is the wallet's own blind oracle, paired with only its public
  key; no Blockstream PIN server by default; a remote oracle only when chosen on Ruby before a PIN exists.
- **`get_utility_keys`**: the wallet's utility keys, sent after the PIN (the PIN is the approval).
- **Groups of the DistributedCryptography wallet** ([RUBY-GROUPS.md](./RUBY-GROUPS.md)):
  - `sign_psbt` `fee_options`: one approval for every fee level of a group payment;
  - Taproot key path of an output that also has scripts (Delegated owner), script path of `multi_a` leaves
    (Delegated member, Multi Signature);
  - `register_group` / `get_registered_groups` / `get_receive_address` of a group, so the group's change is
    recognised; a storage reserve kept for every registration;
  - MuSig2 groups (`musig2_nonces`, BIP373 fields in `sign_psbt`).
- **The seed is stored**: Ruby keeps the 64-byte BIP32 seed (Jade kept the master xpriv). Wallets set up with an
  older Ruby still open, but have no stored seed: set them up again from their recovery words to use the next item.
- **Wallet Backup / Time Encrypted Vault of a Ruby wallet** (`seed_split`): the seed is split with **codex32
  (BIP-93)** on Ruby, the contacts and their keys are shown on Ruby, and each contact's shares leave Ruby already
  encrypted to that contact.
- **Restore into a new Ruby** (`restore_seed`): a wallet recovered by a Wallet Backup / TEV group can be loaded into
  a Ruby with no wallet; the seed travels encrypted to a one-time key of Ruby, the fingerprint is confirmed on Ruby,
  then the PIN is chosen on Ruby.
- **Fuzzing**: the code that reads host data is fuzzed on a PC ([fuzz/README.md](./fuzz/README.md)); finding F2
  fixed (`sign_psbt` refuses a PSBT that parses but does not serialise).

The new RPC messages are documented in [docs/index.rst](./docs/index.rst), section "Ruby specific".
