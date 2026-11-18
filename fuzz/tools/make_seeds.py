#!/usr/bin/env python3
"""Build the seed corpus of every fuzz target from data already in the repo.

Usage: make_seeds.py ROOT OUTDIR

Seeds are generated (not committed) so they always follow the repo's test data:
- fuzz_psbt_from_bytes, fuzz_psbt_ruby_flags: every base64 PSBT in libwally's PSBT vectors
  (valid AND invalid ones) and in Jade's sign_psbt RPC tests (tests/rpc/data/sign_psbt/*.json).
- fuzz_tx_from_bytes: the transactions inside those PSBTs (v0 global unsigned tx and
  every input's non_witness_utxo).

Each seed is written as OUTDIR/<target>/<sha1 of the bytes>, so duplicates collapse.
"""
import base64
import glob
import hashlib
import os
import re
import sys

PSBT_B64 = re.compile(rb'cHNidP8[A-Za-z0-9+/]+=*')


def read_compact(b, i):
    n = b[i]
    if n < 0xfd:
        return n, i + 1
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + size], 'little'), i + 1 + size


def read_map(b, i):
    """Return ([(key, value)], next index) of one PSBT key-value map."""
    entries = []
    while True:
        klen, i = read_compact(b, i)
        if klen == 0:
            return entries, i
        key = b[i:i + klen]
        i += klen
        vlen, i = read_compact(b, i)
        val = b[i:i + vlen]
        if len(key) != klen or len(val) != vlen:
            raise ValueError('truncated')
        i += vlen
        entries.append((key, val))


def txs_in_psbt(psbt):
    """Yield the raw transactions found in a PSBT (best effort; invalid PSBTs yield nothing)."""
    if not psbt.startswith(b'psbt\xff'):
        return
    glob_map, i = read_map(psbt, 5)
    n_inputs = None
    for key, val in glob_map:
        if key == b'\x00':                       # PSBT_GLOBAL_UNSIGNED_TX (v0)
            yield val
            n_inputs, _ = read_compact(val, 4)   # version (4 bytes), then vin count
        elif key == b'\x05':                     # PSBT_GLOBAL_INPUT_COUNT (v2)
            n_inputs, _ = read_compact(val, 0)
    for _ in range(n_inputs or 0):
        in_map, i = read_map(psbt, i)
        for key, val in in_map:
            if key == b'\x00':                   # PSBT_IN_NON_WITNESS_UTXO
                yield val


def main(root, outdir):
    sources = [os.path.join(root, 'components/libwally-core/upstream/src/data/psbt.json')]
    sources += sorted(glob.glob(os.path.join(root, 'tests/rpc/data/sign_psbt/*.json')))
    corpora = {'fuzz_psbt_from_bytes': set(), 'fuzz_tx_from_bytes': set()}
    for path in sources:
        with open(path, 'rb') as f:
            text = f.read()
        for m in PSBT_B64.finditer(text):
            try:
                psbt = base64.b64decode(m.group(0), validate=True)
            except ValueError:
                continue
            corpora['fuzz_psbt_from_bytes'].add(psbt)
            try:
                corpora['fuzz_tx_from_bytes'].update(t for t in txs_in_psbt(psbt) if t)
            except (ValueError, IndexError, KeyError):
                pass
    corpora['fuzz_psbt_ruby_flags'] = corpora['fuzz_psbt_from_bytes']
    for target, seeds in corpora.items():
        d = os.path.join(outdir, target)
        os.makedirs(d, exist_ok=True)
        for s in seeds:
            with open(os.path.join(d, hashlib.sha1(s).hexdigest()), 'wb') as f:
                f.write(s)
        print('seeds %-24s %d' % (target, len(seeds)))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
