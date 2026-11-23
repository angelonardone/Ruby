#!/usr/bin/env python3
"""Build the seed corpus of every fuzz target from data already in the repo.

Usage: make_seeds.py ROOT OUTDIR

Seeds are generated (not committed) so they always follow the repo's test data:
- fuzz_psbt_from_bytes, fuzz_psbt_ruby_flags: every base64 PSBT in libwally's PSBT vectors
  (valid AND invalid ones) and in Jade's sign_psbt RPC tests (tests/rpc/data/sign_psbt/*.json).
- fuzz_tx_from_bytes: the transactions inside those PSBTs (v0 global unsigned tx and
  every input's non_witness_utxo).
- fuzz_codex32: the BIP-93 strings of tests/codex32/ (valid and invalid), alone and in runs of
  2 to 4 from the same file (COMBINE mode, first byte 0), plus a few SPLIT inputs (first byte 1).
- fuzz_psbt_taproot: every PSBT above (RAW mode, first byte 0) and one STRUCTURED input (first
  byte 1) per kind of Taproot input and break.
- fuzz_restore_seed, fuzz_seed_split, fuzz_register_group: hand-made RAW inputs (whole RPC
  requests in CBOR for the last two) and STRUCTURED inputs covering every kind / break.

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


CODEX32 = re.compile(rb'"(ms1[0-9a-z]+|MS1[0-9A-Z]+)"')


def codex32_seeds(root):
    seeds = set()
    paths = sorted(glob.glob(os.path.join(root, 'tests/codex32/*.c')) +
                   glob.glob(os.path.join(root, 'tests/codex32/*.inc')))
    for path in paths:
        with open(path, 'rb') as f:
            strings = [m.group(1) for m in CODEX32.finditer(f.read())]
        for n in range(1, 5):
            for i in range(len(strings) - n + 1):
                seeds.add(b'\x00' + b'\n'.join(strings[i:i + n]))
    # SPLIT: seed size, k, n, flags, identifier, seed bytes, picks, random bytes
    for size in range(6):
        for k in (0, 3, 7):
            seeds.add(bytes([1, size, k, 255 - k, size & 3]) + bytes(range(4 + 64 + 47)))
    return seeds


def cbor(v):
    """Minimal CBOR encoder (definite lengths): int >= 0, str, bytes, list, dict."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | ai]) + n.to_bytes(size, 'big')
        raise ValueError(n)
    if isinstance(v, bool):
        return bytes([0xf5 if v else 0xf4])
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b''.join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


def rpc(method, params):
    return cbor({'id': '1', 'method': method, 'params': params})


# Compressed public keys of 1G, 2G, 3G (valid curve points)
G1 = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
G2 = bytes.fromhex('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
G3 = bytes.fromhex('02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')


def seed_split_seeds():
    seeds = set()
    contacts = [{'name': 'Ann', 'pubkey': G1, 'shares': 1}, {'name': 'Bob', 'pubkey': G2, 'shares': 2},
                {'name': 'Carol', 'pubkey': G3, 'shares': 1}]
    for mode in ('backup', 'vault'):
        for k in (2, 3):
            seeds.add(b'\x00' + rpc('seed_split', {'mode': mode, 'threshold': k, 'contacts': contacts}))
    seeds.add(b'\x00' + rpc('seed_split', {'mode': 'backup', 'threshold': 2, 'contacts': contacts[:1]}))
    # STRUCTURED: mode, k, n, seed size, seed bytes, then per contact name length, name, key, shares
    for mode in (0, 1):
        for size in (0, 4, 5):
            body = bytes([mode, 2, 3, size]) + bytes(range(64))
            for i in range(3):
                body += bytes([3]) + b'Ann' + bytes([i, 1 + i])
            seeds.add(b'\x01' + body + bytes(range(40)))
    return seeds


def restore_seed_seeds():
    return {b'\x00' + b'BIE1' + G1 + bytes(range(80)) + bytes(32),
            b'\x01' + bytes(range(100)),
            b'\x01' + bytes(range(255, 155, -1))}


def taproot_seeds(psbts):
    seeds = {b'\x00' + p for p in psbts}
    for kind in range(5):
        for brk in range(15):
            seeds.add(bytes([1, kind, brk, 3, 5, 4, 2, 1, 3]) + b'A' * 150)
    return seeds


def register_group_seeds():
    seeds = set()
    for t in range(4):
        for brk in range(19):
            seeds.add(bytes([1, t, brk, 2, 1, 1, 1, 5, 7, 9, 0x11]))
    xpub = {'receiving': 'tpubD6NzVbkrYhZ4X', 'change': 'tpubD6NzVbkrYhZ4Y'}
    for t in ('delegated', 'multisig', 'musig2-delegated', 'musig2-multisig'):
        params = {'network': 'testnet', 'group_name': 'group1', 'label': 'Family', 'type': t, 'threshold': 2,
                  'signers': [xpub, xpub, xpub], 'receiving_path': [0x80000056, 0x80000001, 0x80000000, 2],
                  'change_path': [0x80000056, 0x80000001, 0x80000000, 3]}
        if t.endswith('delegated'):
            params['owner'] = xpub
        seeds.add(b'\x00' + rpc('register_group', params))
    return seeds


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
    corpora['fuzz_codex32'] = codex32_seeds(root)
    corpora['fuzz_psbt_taproot'] = taproot_seeds(corpora['fuzz_psbt_from_bytes'])
    corpora['fuzz_restore_seed'] = restore_seed_seeds()
    corpora['fuzz_seed_split'] = seed_split_seeds()
    corpora['fuzz_register_group'] = register_group_seeds()
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
