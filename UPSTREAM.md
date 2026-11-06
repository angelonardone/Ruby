# Keeping Ruby in sync with upstream Jade

Ruby is based on [Blockstream/Jade](https://github.com/Blockstream/Jade). The upstream history is kept
intact (Ruby started from Jade commit `a59d14c2`), so upstream fixes, security fixes above all, can be merged.

## Remotes

| Remote     | URL                                          | Use                   |
|------------|----------------------------------------------|-----------------------|
| `origin`   | https://github.com/angelonardone/Ruby.git    | Ruby (push here)      |
| `upstream` | https://github.com/Blockstream/Jade.git      | Jade (fetch only)     |

A fresh clone only has `origin`; add the other one with:

```
git remote add upstream https://github.com/Blockstream/Jade.git
git remote set-url --push upstream DISABLED
```

## Merging upstream changes

```
git fetch upstream --tags
git log --oneline master..upstream/master        # what is new in Jade
git checkout -b merge-upstream-<date> master
git merge upstream/master
git submodule update --init --recursive          # Jade may move its submodules
# build + run the tests (emulator), then merge into master and push
```

- Check `CHANGELOG.md` and the release notes of Jade for security fixes; merge those first and soon.
- Prefer merge over rebase, so the upstream commits stay identical and later merges stay easy.
- Keep Ruby changes in clearly separated files/components where possible to keep conflicts small.

## Liquid was removed

Ruby is Bitcoin only: the Liquid / Elements code of Jade was removed. When merging upstream:

- Changes to files Ruby deleted (eg. `components/assets/`, `main/process/get_commitments.c`,
  `main/process/get_blinding_*.c`, `main/process/get_shared_nonce.c`, `main/assets.c`,
  `tests/rpc/test_blinding.py`, Liquid test data) are resolved by keeping them deleted.
- In shared files (`sign_tx.c`, `sign_psbt.c`, `sign_utils.c`, `wallet.c`, `network.c`, multisig,
  descriptors, `jadepy/jade.py`, tests) take the Bitcoin part of the upstream change and drop the Liquid part.
- libwally is built without `BUILD_ELEMENTS` (see `main/amalgamated.c` and
  `components/libwally-core/CMakeLists.txt`); the firmware asserts this at boot (`main/utils/wally_ext.c`).
- The SLIP-77 master key is still derived (`main/keychain.c`) because it seeds BIP85-RSA keys.

## Line endings (Windows)

The firmware is built in Linux containers: shell scripts must keep LF endings. On Windows:

```
git config core.autocrlf false
git submodule foreach --recursive git config core.autocrlf false
```
