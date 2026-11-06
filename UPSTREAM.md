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

## Line endings (Windows)

The firmware is built in Linux containers: shell scripts must keep LF endings. On Windows:

```
git config core.autocrlf false
git submodule foreach --recursive git config core.autocrlf false
```
