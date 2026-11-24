#!/usr/bin/env python3
"""RPC fuzzer of Ruby on the QEMU emulator, with a "shown vs signed" oracle.

Runs the REAL firmware (CI build: `--dev --ci --m5basic --log-cbor`, its screens confirm themselves and it logs what
each review screen shows, see `CI_SHOWN` in main/ui/sign_tx.c) and sends it `sign_psbt` requests: valid payments
built here, then changed by input-chosen mutations. The classic hardware-wallet bug is not only "signs what it should
refuse" but "shows X and signs Y"; for Ruby it matters most for the change it hides (its own change and the change of
a registered group, RUBY-GROUPS.md). So for every request Ruby signs, the oracle checks:

  SAFETY (a finding):
  - every output of the transaction is either shown (address and amount as the screen shows them, equal to the
    transaction's) or hidden, and every hidden output is provably this Ruby's: one of its keys (derived here from the
    test mnemonic, independently) at the path the psbt gives, in a standard script of that key, or the address of a
    registered group (computed here from the group's xpubs as RUBY-GROUPS.md / main/group.h define it) at the path;
  - the fee shown is inputs - outputs;
  - Ruby returns the same transaction and coins it was sent (it only adds signatures), and every signature it added
    verifies for that transaction (BIP143 / BIP341 sighash computed here) and the key at that input's path;
  - Ruby never stops answering (a crash or a hang of the firmware).
  DESIGN (also reported): a hidden output that is ours but should have been shown: a receiving address, or a group's
    change while the inputs are not all of that one group.

The run needs the emulator listening on tcp:HOST:30121 (the image's default CMD), or `--qemu` to start and restart
it here (inside the image). Everything goes to OUTDIR: findings/<n>.json (the request, the mutations, the log),
stats.json. See fuzz/README.md, "RPC fuzzer on the emulator".

Usage: fuzz_rpc.py [--seconds N] [--seed N] [--device tcp:127.0.0.1:30121] [--qemu] [--out DIR]
"""
import argparse
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
import traceback

import wallycore as wally

sys.path.insert(0, os.environ.get('JADE_DIR', '/jade'))
from jadepy.jade import JadeAPI, JadeError  # noqa: E402

NETWORK = 'testnet'
H = 0x80000000
# Ruby's wallet: a fixed test mnemonic (debug_set_mnemonic, dev builds only)
MNEMONIC = wally.bip39_mnemonic_from_bytes(None, bytes(range(0x52, 0x52 + 16)))

# ---------------------------------------------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------------------------------------------

SEED = wally.bip39_mnemonic_to_seed512(MNEMONIC, None)
MASTER = wally.bip32_key_from_seed_alloc(SEED, wally.BIP32_VER_TEST_PRIVATE, 0)
OUR_FP = bytes(wally.bip32_key_get_fingerprint(MASTER))


def derive(key, path, private=False):
    flags = wally.BIP32_FLAG_KEY_PRIVATE if private else wally.BIP32_FLAG_KEY_PUBLIC
    return wally.bip32_key_from_parent_path_alloc(key, path, flags)


def pub(key):
    return bytes(wally.bip32_key_get_pub_key(key))


def our_pub(path):
    return pub(derive(MASTER, path))


def external_master(n):
    seed = bytes(wally.sha512(b'ruby rpc fuzz participant' + bytes([n])))
    return wally.bip32_key_from_seed_alloc(seed, wally.BIP32_VER_TEST_PRIVATE, 0)


def xpub_str(key):
    return wally.bip32_key_to_base58(key, wally.BIP32_FLAG_KEY_PUBLIC)


def tagged(tag, data):
    return bytes(wally.bip340_tagged_hash(data, tag))


def tweak_xonly(xonly, merkle=None):
    return bytes(wally.ec_public_key_bip341_tweak(xonly, merkle, 0))[1:]


def p2tr(xonly):
    return b'\x51\x20' + xonly


def p2wpkh(pk):
    return b'\x00\x14' + bytes(wally.hash160(pk))


def p2sh_p2wpkh(pk):
    return b'\xa9\x14' + bytes(wally.hash160(p2wpkh(pk))) + b'\x87'


def p2pkh(pk):
    return b'\x76\xa9\x14' + bytes(wally.hash160(pk)) + b'\x88\xac'


def singlesig_scripts(pk):
    return {p2wpkh(pk), p2sh_p2wpkh(pk), p2pkh(pk), p2tr(tweak_xonly(pk[1:]))}


# ---------------------------------------------------------------------------------------------------------------
# registered groups (RUBY-GROUPS.md, main/group.h): Delegated only (the owner's key is the internal key)
# ---------------------------------------------------------------------------------------------------------------

class Group:
    def __init__(self, name, threshold, owner, signers, ruby_paths, ruby_is_owner):
        self.name = name
        self.k = threshold
        self.owner = owner  # [receiving, change] ext_keys (public)
        self.signers = signers  # list of [receiving, change]
        self.ruby_paths = ruby_paths  # [receiving chain path, change chain path]
        self.ruby_is_owner = ruby_is_owner
        self._cache = {}

    def sorted_signers(self, chain):
        keys = [s[chain] for s in self.signers]
        return sorted(keys, key=lambda k: bytes(wally.bip32_key_serialize(k, wally.BIP32_FLAG_KEY_PUBLIC))[4:])

    def leaves(self, chain, index):
        """The leaf scripts in tree order"""
        xonly = [pub(wally.bip32_key_from_parent_alloc(k, index, wally.BIP32_FLAG_KEY_PUBLIC))[1:]
                 for k in self.sorted_signers(chain)]
        out = []

        def combos(start, k, acc):
            if k == 0:
                out.append(acc)
                return
            for i in range(start, len(xonly) - k + 1):
                combos(i + 1, k - 1, acc + [i])
        combos(0, self.k, [])
        scripts = []
        for c in out:
            keys = sorted(xonly[i] for i in c)
            s = b''
            for j, x in enumerate(keys):
                s += b'\x20' + x + (b'\xac' if j == 0 else b'\xba')
            s += bytes([0x50 + self.k]) + b'\x9c'
            scripts.append(s)
        return scripts

    def tree(self, chain, index):
        """(internal xonly, merkle root, [(leaf script, merkle path)])"""
        key = (chain, index)
        if key in self._cache:
            return self._cache[key]
        scripts = self.leaves(chain, index)

        def leaf_hash(s):
            return tagged('TapLeaf', bytes([0xc0]) + compact(len(s)) + s)

        def build(items):  # items: list of (script, hash, path)
            if len(items) == 1:
                return items[0][1], items
            half = (len(items) + 1) // 2
            lh, left = build(items[:half])
            rh, right = build(items[half:])
            left = [(s, h, p + [rh]) for s, h, p in left]
            right = [(s, h, p + [lh]) for s, h, p in right]
            branch = tagged('TapBranch', min(lh, rh) + max(lh, rh))
            return branch, left + right
        root, items = build([(s, leaf_hash(s), []) for s in scripts])
        internal = pub(wally.bip32_key_from_parent_alloc(self.owner[chain], index, wally.BIP32_FLAG_KEY_PUBLIC))[1:]
        result = (internal, root, [(s, h, p) for s, h, p in items])
        self._cache[key] = result
        return result

    def script(self, chain, index):
        internal, root, _ = self.tree(chain, index)
        return p2tr(tweak_xonly(internal, root))

    def ruby_path(self, chain, index):
        return self.ruby_paths[chain] + [index]

    def rpc_params(self):
        def chains(c):
            return {'receiving': xpub_str(c[0]), 'change': xpub_str(c[1])}
        return {'network': NETWORK, 'group_name': self.name, 'label': 'Fuzz ' + self.name, 'type': 'delegated',
                'threshold': self.k, 'owner': chains(self.owner), 'signers': [chains(s) for s in self.signers],
                'receiving_path': self.ruby_paths[0], 'change_path': self.ruby_paths[1]}


def ext_chains(master, account):
    base = [86 | H, 1 | H, account | H]
    return [derive(master, base + [2]), derive(master, base + [3])]


def make_groups():
    ext = [external_master(i) for i in range(8)]
    # G1: Ruby is the owner; G2: Ruby is a member; G3: Ruby is the owner of another group
    r1 = [[86 | H, 1 | H, 5 | H, 2], [86 | H, 1 | H, 5 | H, 3]]
    g1 = Group('fz-owner', 2, [derive(MASTER, p) for p in r1], [ext_chains(ext[i], 0) for i in (0, 1, 2)], r1, True)
    r2 = [[86 | H, 1 | H, 6 | H, 2], [86 | H, 1 | H, 6 | H, 3]]
    g2 = Group('fz-member', 2, ext_chains(ext[3], 0), [[derive(MASTER, p) for p in r2]]
               + [ext_chains(ext[i], 0) for i in (4, 5)], r2, False)
    r3 = [[86 | H, 1 | H, 9 | H, 2], [86 | H, 1 | H, 9 | H, 3]]
    g3 = Group('fz-other', 1, [derive(MASTER, p) for p in r3], [ext_chains(ext[i], 1) for i in (0, 6)], r3, True)
    return [g1, g2, g3]


# ---------------------------------------------------------------------------------------------------------------
# psbt v0, written here (so any field can be set or broken)
# ---------------------------------------------------------------------------------------------------------------

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def read_compact(b, i):
    n = b[i]
    if n < 0xfd:
        return n, i + 1
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + size], 'little'), i + 1 + size


def path_bytes(fp, path):
    return fp + b''.join(p.to_bytes(4, 'little') for p in path)


class Payment:
    """A psbt as key-value maps, plus what the harness knows of it"""

    def __init__(self):
        self.version = 2
        self.locktime = 0
        self.ins = []  # dicts: txid, vout, seq, fields {key: value}
        self.outs = []  # dicts: amount, script, fields
        self.mutations = []
        self.kind = ''

    def tx_bytes(self):
        b = self.version.to_bytes(4, 'little') + compact(len(self.ins))
        for i in self.ins:
            b += i['txid'] + i['vout'].to_bytes(4, 'little') + b'\x00' + i['seq'].to_bytes(4, 'little')
        b += compact(len(self.outs))
        for o in self.outs:
            b += (o['amount'] & 0xffffffffffffffff).to_bytes(8, 'little') + compact(len(o['script'])) + o['script']
        return b + self.locktime.to_bytes(4, 'little')

    def to_bytes(self):
        def kv(k, v):
            return compact(len(k)) + k + compact(len(v)) + v
        b = b'psbt\xff' + kv(b'\x00', self.tx_bytes()) + b'\x00'
        for m in [i['fields'] for i in self.ins] + [o['fields'] for o in self.outs]:
            for k, v in m.items():
                b += kv(k, v)
            b += b'\x00'
        return b


def parse_psbt(b):
    """(global map, [input maps], [output maps]) of a serialized psbt v0, maps as lists of (key, value)"""
    b = bytes(b)  # jadepy returns a bytearray
    assert b[:5] == b'psbt\xff'
    i = 5
    maps = []
    while i < len(b):
        m = []
        while True:
            kl, i = read_compact(b, i)
            if kl == 0:
                break
            k = b[i:i + kl]
            i += kl
            vl, i = read_compact(b, i)
            m.append((k, b[i:i + vl]))
            i += vl
        maps.append(m)
    tx = wally.tx_from_bytes(dict(maps[0])[b'\x00'], 0)
    n_in, n_out = wally.tx_get_num_inputs(tx), wally.tx_get_num_outputs(tx)
    return maps[0], maps[1:1 + n_in], maps[1 + n_in:1 + n_in + n_out], tx


def witness_utxo(amount, script):
    return amount.to_bytes(8, 'little') + compact(len(script)) + script


def rnd_txid(rng):
    return bytes(rng.getrandbits(8) for _ in range(32))


def payee_script(rng):
    k = pub(derive(external_master(7), [rng.randrange(1000)]))
    return rng.choice([p2wpkh(k), p2tr(k[1:]), p2sh_p2wpkh(k), p2pkh(k)])


# ---- templates: valid payments Ruby should sign ----

def tpl_singlesig(rng, purpose):
    """P2WPKH (84') or P2TR (86') coins of Ruby's wallet, a payee, a change output"""
    p = Payment()
    p.kind = 'single%d' % purpose
    acct = [purpose | H, 1 | H, 0 | H]
    total = 0
    for _ in range(rng.randint(1, 3)):
        path = acct + [rng.randint(0, 1), rng.randrange(50)]
        pk = our_pub(path)
        amount = rng.randint(20000, 5000000)
        total += amount
        f = {}
        if purpose == 84:
            f[b'\x01'] = witness_utxo(amount, p2wpkh(pk))
            f[b'\x06' + pk] = path_bytes(OUR_FP, path)
        else:
            f[b'\x01'] = witness_utxo(amount, p2tr(tweak_xonly(pk[1:])))
            f[b'\x16' + pk[1:]] = b'\x00' + path_bytes(OUR_FP, path)
            f[b'\x17'] = pk[1:]
        p.ins.append({'txid': rnd_txid(rng), 'vout': rng.randrange(3), 'seq': 0xfffffffd, 'fields': f})
    spend = rng.randint(1000, total // 2)
    fee = rng.randint(200, 5000)
    p.outs.append({'amount': spend, 'script': payee_script(rng), 'fields': {}})
    cpath = acct + [1, rng.randrange(50)]
    cpk = our_pub(cpath)
    if purpose == 84:
        c = {'amount': total - spend - fee, 'script': p2wpkh(cpk), 'fields': {b'\x02' + cpk: path_bytes(OUR_FP, cpath)}}
    else:
        c = {'amount': total - spend - fee, 'script': p2tr(tweak_xonly(cpk[1:])),
             'fields': {b'\x07' + cpk[1:]: b'\x00' + path_bytes(OUR_FP, cpath), b'\x05': cpk[1:]}}
    p.outs.insert(rng.randint(0, 1), c)
    return p


def group_input(rng, g, chain, index, amount):
    internal, root, leaves = g.tree(chain, index)
    path = g.ruby_path(chain, index)
    ours = our_pub(path)[1:]
    f = {b'\x01': witness_utxo(amount, g.script(chain, index))}
    if g.ruby_is_owner:  # key path with the scripts' merkle root
        f[b'\x16' + ours] = b'\x00' + path_bytes(OUR_FP, path)
        f[b'\x17'] = internal
        f[b'\x18'] = root
    else:  # script path: one leaf with our key
        mine = [(s, h, mp) for s, h, mp in leaves if ours in s]
        s, h, mp = rng.choice(mine)
        out_key = bytes(wally.ec_public_key_bip341_tweak(internal, root, 0))
        control = bytes([0xc0 | (out_key[0] & 1)]) + internal + b''.join(mp)
        f[b'\x15' + control] = s + b'\xc0'
        f[b'\x16' + ours] = compact(1) + h + path_bytes(OUR_FP, path)
    return {'txid': rnd_txid(rng), 'vout': rng.randrange(3), 'seq': 0xfffffffd, 'fields': f}


def group_output(g, chain, index, amount):
    path = g.ruby_path(chain, index)
    ours = our_pub(path)[1:]
    return {'amount': amount, 'script': g.script(chain, index),
            'fields': {b'\x07' + ours: b'\x00' + path_bytes(OUR_FP, path)}}


def tpl_group(rng, g):
    p = Payment()
    p.kind = 'group-' + g.name
    total = 0
    for _ in range(rng.randint(1, 2)):
        amount = rng.randint(20000, 3000000)
        total += amount
        p.ins.append(group_input(rng, g, rng.randint(0, 1), rng.randrange(20), amount))
    spend = rng.randint(1000, total // 2)
    fee = rng.randint(200, 5000)
    p.outs.append({'amount': spend, 'script': payee_script(rng), 'fields': {}})
    p.outs.insert(rng.randint(0, 1), group_output(g, 1, rng.randrange(20), total - spend - fee))
    return p


# ---- mutations: each one changes the payment; Ruby may sign it or refuse it, the oracle judges what it signs ----

def our_output_indices(p):
    return [i for i, o in enumerate(p.outs) if any(k[0] in (2, 7) for k in o['fields'])]


def mut_change_index(rng, p, groups):
    """the change's path moves to another index (key updated, script kept)"""
    idx = our_output_indices(p)
    if not idx:
        return False
    o = p.outs[rng.choice(idx)]
    k, v = next((k, v) for k, v in o['fields'].items() if k[0] in (2, 7))
    hashes_len = 1 if k[0] == 7 else 0
    path = [int.from_bytes(v[hashes_len + 4 + 4 * j:hashes_len + 8 + 4 * j], 'little')
            for j in range((len(v) - hashes_len - 4) // 4)]
    path[-1] = (path[-1] + rng.randint(1, 3)) % 100
    pk = our_pub(path)
    del o['fields'][k]
    nk = (b'\x02' + pk) if k[0] == 2 else (b'\x07' + pk[1:])
    o['fields'][nk] = v[:hashes_len] + path_bytes(OUR_FP, path)
    return True


def mut_change_chain(rng, p, groups):
    """the change's path goes to the receiving chain (key updated, script kept)"""
    idx = our_output_indices(p)
    if not idx:
        return False
    o = p.outs[rng.choice(idx)]
    k, v = next((k, v) for k, v in o['fields'].items() if k[0] in (2, 7))
    hl = 1 if k[0] == 7 else 0
    path = [int.from_bytes(v[hl + 4 + 4 * j:hl + 8 + 4 * j], 'little') for j in range((len(v) - hl - 4) // 4)]
    path[-2] = {1: 0, 3: 2, 0: 1, 2: 3}.get(path[-2], path[-2])
    pk = our_pub(path)
    del o['fields'][k]
    o['fields'][((b'\x02' + pk) if k[0] == 2 else (b'\x07' + pk[1:]))] = v[:hl] + path_bytes(OUR_FP, path)
    return True


def mut_change_script(rng, p, groups):
    """the change pays elsewhere, its key path stays"""
    idx = our_output_indices(p)
    if not idx:
        return False
    o = p.outs[rng.choice(idx)]
    choice = rng.randrange(4)
    if choice == 0:
        o['script'] = payee_script(rng)
    elif choice == 1:  # another group's change
        g = rng.choice(groups)
        o['script'] = g.script(1, rng.randrange(20))
    elif choice == 2:  # same key, other script type
        k = next(k for k in o['fields'] if k[0] in (2, 7))
        if k[0] == 2:
            o['script'] = rng.choice([p2tr(tweak_xonly(k[2:])), p2pkh(k[1:]), p2sh_p2wpkh(k[1:])])
        else:
            o['script'] = p2tr(k[1:])  # untweaked
    else:
        o['script'] = o['script'][:-1] + bytes([o['script'][-1] ^ 1])
    return True


def mut_other_group_change(rng, p, groups):
    """an output becomes the change of a registered group with Ruby's key path (maybe not the inputs' group)"""
    g = rng.choice(groups)
    i = rng.randrange(len(p.outs))
    p.outs[i] = group_output(g, rng.randint(0, 1), rng.randrange(20), p.outs[i]['amount'])
    return True


def mut_mix_inputs(rng, p, groups):
    """an input of another kind is added (a singlesig coin, or a coin of another group)"""
    amount = rng.randint(1000, 100000)
    if rng.random() < 0.5:
        path = [84 | H, 1 | H, 0 | H, 0, rng.randrange(50)]
        pk = our_pub(path)
        f = {b'\x01': witness_utxo(amount, p2wpkh(pk)), b'\x06' + pk: path_bytes(OUR_FP, path)}
        p.ins.append({'txid': rnd_txid(rng), 'vout': 0, 'seq': 0xfffffffd, 'fields': f})
    else:
        p.ins.append(group_input(rng, rng.choice(groups), rng.randint(0, 1), rng.randrange(20), amount))
    p.outs[0]['amount'] += amount - rng.randint(0, 500)
    return True


def mut_amount(rng, p, groups):
    """an output or coin amount changes (the fee shown must follow)"""
    if rng.random() < 0.5:
        o = rng.choice(p.outs)
        o['amount'] = rng.choice([0, 1, 546, o['amount'] + rng.randint(1, 10000), o['amount'] * 3,
                                  2100000000000000, 2100000000000001, (1 << 63) - 1, 1 << 63])
    else:
        i = rng.choice(p.ins)
        wu = i['fields'].get(b'\x01')
        if wu:
            amount = max(0, int.from_bytes(wu[:8], 'little') + rng.randint(-30000, 30000))
            i['fields'][b'\x01'] = amount.to_bytes(8, 'little') + wu[8:]
    return True


def mut_extra_output(rng, p, groups):
    """an extra output: OP_RETURN, empty, non-standard, or foreign script with our key path"""
    choice = rng.randrange(4)
    if choice == 0:
        o = {'amount': 0, 'script': b'\x6a\x04ruby', 'fields': {}}
    elif choice == 1:
        o = {'amount': rng.randint(0, 1000), 'script': b'', 'fields': {}}
    elif choice == 2:
        o = {'amount': rng.randint(546, 5000), 'script': bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 60))),
             'fields': {}}
    else:
        path = [86 | H, 1 | H, 0 | H, 1, rng.randrange(50)]
        pk = our_pub(path)
        o = {'amount': rng.randint(546, 5000), 'script': payee_script(rng),
             'fields': {b'\x07' + pk[1:]: b'\x00' + path_bytes(OUR_FP, path)}}
    p.outs.insert(rng.randint(0, len(p.outs)), o)
    p.outs[-1]['amount'] = max(0, p.outs[-1]['amount'] - o['amount'])
    return True


def mut_derivation(rng, p, groups):
    """an output's key path is broken: other fingerprint, a second key, leaf hashes, or a hardened index"""
    idx = our_output_indices(p)
    if not idx:
        return False
    o = p.outs[rng.choice(idx)]
    k, v = next((k, v) for k, v in o['fields'].items() if k[0] in (2, 7))
    hl = 1 if k[0] == 7 else 0
    choice = rng.randrange(4)
    if choice == 0:
        o['fields'][k] = v[:hl] + bytes([v[hl] ^ 0xff]) + v[hl + 1:]
    elif choice == 1:
        other = pub(derive(external_master(5), [rng.randrange(9)]))
        o['fields'][(bytes([k[0]]) + (other if k[0] == 2 else other[1:]))] = v
    elif choice == 2 and k[0] == 7:
        o['fields'][k] = compact(1) + bytes(32) + v[1:]
    else:
        o['fields'][k] = v[:-4] + (int.from_bytes(v[-4:], 'little') | H).to_bytes(4, 'little')
    return True


def mut_input_field(rng, p, groups):
    """an input field is dropped or changed: utxo, merkle root, internal key, leaf, sighash"""
    i = rng.choice(p.ins)
    f = i['fields']
    choice = rng.randrange(5)
    if choice == 0 and b'\x01' in f:
        del f[b'\x01']
    elif choice == 1 and b'\x18' in f:
        f[b'\x18'] = bytes(rng.getrandbits(8) for _ in range(32))
    elif choice == 2:
        f[b'\x03'] = rng.choice([0, 1, 2, 3, 0x81, 0x83]).to_bytes(4, 'little')
    elif choice == 3:
        leaf = [k for k in f if k[0] == 0x15]
        if leaf:
            v = f[leaf[0]]
            f[leaf[0]] = v[:-2] + bytes([v[-2] ^ 1]) + v[-1:]
    else:
        wu = f.get(b'\x01')
        if wu:
            f[b'\x01'] = wu[:-1] + bytes([wu[-1] ^ 1])
    return True


def mut_tx(rng, p, groups):
    """transaction level: lock time, version, sequence, duplicated input, outputs reordered"""
    choice = rng.randrange(5)
    if choice == 0:
        p.locktime = rng.choice([1, 500000000, 0xffffffff])
    elif choice == 1:
        p.version = rng.choice([1, 3, 0xffffffff])
    elif choice == 2:
        rng.choice(p.ins)['seq'] = rng.choice([0, 0xffffffff, 0xfffffffe])
    elif choice == 3:
        p.ins.append(dict(p.ins[0], fields=dict(p.ins[0]['fields'])))
    else:
        rng.shuffle(p.outs)
    return True


MUTATIONS = [mut_change_index, mut_change_chain, mut_change_script, mut_other_group_change, mut_mix_inputs,
             mut_amount, mut_extra_output, mut_derivation, mut_input_field, mut_tx]


def flip_bytes(rng, b):
    b = bytearray(b)
    for _ in range(rng.randint(1, 4)):
        b[rng.randrange(5, len(b))] ^= rng.randint(1, 255)
    return bytes(b)


# ---------------------------------------------------------------------------------------------------------------
# the oracle
# ---------------------------------------------------------------------------------------------------------------

def address_of(script):
    try:
        if script[:1] in (b'\x00', b'\x51') and len(script) in (22, 34) and script[1] == len(script) - 2:
            return wally.addr_segwit_from_bytes(script, 'tb', 0)
        # the whole pattern: eg. 76a914<20>88ad (CHECKSIGVERIFY) is not P2PKH and has no address
        if len(script) == 25 and script[:3] == b'\x76\xa9\x14' and script[23:] == b'\x88\xac':
            return wally.base58_from_bytes(b'\x6f' + script[3:23], wally.BASE58_FLAG_CHECKSUM)
        if len(script) == 23 and script[:2] == b'\xa9\x14' and script[22:] == b'\x87':
            return wally.base58_from_bytes(b'\xc4' + script[2:22], wally.BASE58_FLAG_CHECKSUM)
    except Exception:
        pass
    return None


def btc(sat):
    return '%.08f' % (1.0 * sat / 1e8)


def parse_shown(lines):
    """the SHOWN log lines of one request: ({index: (address, amount, flags)}, {hidden index}, fee, total, count)"""
    shown, hidden, fees, total, count = {}, set(), [], None, None
    for line in lines:
        pos = line.find('SHOWN ')
        if pos < 0:
            continue
        text = line[pos + 6:].rstrip('\n')
        words = text.split()
        if words[0] == 'outputs':
            count, total = int(words[1]), int(words[3])
        elif words[0] == 'output' and words[2] == 'hidden':
            hidden.add(int(words[1]))
        elif words[0] == 'output':
            # "output <i> <address or text, may hold spaces> <amount>[ verified][ warning=<text>]"
            m = SHOWN_OUTPUT.match(text)
            shown[int(words[1])] = (m.group(2), m.group(3), m.group(4)) if m else (text, None, '')
        elif words[0] == 'fee' and words[1] == 'option':
            fees.append(words[3])
        elif words[0] == 'fee':
            fees.append(words[1])
    return shown, hidden, fees, total, count


SHOWN_OUTPUT = re.compile(r'output (\d+) (.*) (\d+\.\d{8})((?: verified)?(?: warning=.*)?)$')


def path_of(v, hashes_len):
    return [int.from_bytes(v[hashes_len + 4 + 4 * j:hashes_len + 8 + 4 * j], 'little')
            for j in range((len(v) - hashes_len - 4) // 4)]


def explain_ours(script, fields, groups):
    """('single', path) / ('group', group, chain, index) if the output is provably this Ruby's, else None"""
    for k, v in fields:
        if k[0] not in (2, 7) or len(v) < 4:
            continue
        hl = 0
        if k[0] == 7:
            n, hl = read_compact(v, 0)
            hl += 32 * n
        if v[hl:hl + 4] != OUR_FP or (len(v) - hl - 4) % 4:
            continue
        path = path_of(v, hl)
        try:
            pk = our_pub(path)
        except Exception:
            continue
        if (k[0] == 2 and k[1:] != pk) or (k[0] == 7 and k[1:] != pk[1:]):
            continue
        if script in singlesig_scripts(pk):
            return ('single', path)
        for g in groups:
            for chain in (0, 1):
                rp = g.ruby_paths[chain]
                if path[:-1] == rp and not path[-1] & H and script == g.script(chain, path[-1]):
                    return ('group', g, chain, path[-1])
    return None


def input_group(script, fields, groups):
    for k, v in fields:
        if k[0] != 0x16:
            continue
        n, hl = read_compact(v, 0)
        hl += 32 * n
        path = path_of(v, hl)
        for g in groups:
            for chain in (0, 1):
                if path[:-1] == g.ruby_paths[chain] and not path[-1] & H and script == g.script(chain, path[-1]):
                    return g
    return None


COUNTS = {'shown': 0, 'shown verified': 0, 'hidden single': 0, 'hidden group': 0, 'hidden unexplained': 0}


def selftest_cases(req, reply, lines):
    """Altered copies of a real signed exchange that the oracle MUST flag: (what, request, reply, log)"""
    shown, hidden, fees, total, count = parse_shown(lines)
    cases = []
    for i in sorted(shown):  # a shown output hidden instead (and counted as such: only "is it ours" can catch it)
        alt = [('>> I SHOWN output %d hidden' % i) if re.search(r'SHOWN output %d ' % i, ln) else ln for ln in lines]
        alt = [('>> I SHOWN outputs %d of %d' % (count - 1, total)) if 'SHOWN outputs ' in ln else ln for ln in alt]
        cases.append(('payee %d hidden' % i, req, reply, alt))
        break
    for i, (addr, amount, flags) in shown.items():  # an amount shown 1 sat lower
        if amount:
            low = '%.08f' % (float(amount) - 1e-8)
            alt = [ln.replace(' %s' % amount, ' %s' % low) if re.search(r'SHOWN output %d ' % i, ln) else ln
                   for ln in lines]
            cases.append(('amount %d shown lower' % i, req, reply, alt))
        break
    if fees:  # the fee shown 1 sat lower
        low = '%.08f' % (float(fees[0]) - 1e-8)
        cases.append(('fee shown lower', req, reply, [ln.replace('SHOWN fee %s' % fees[0], 'SHOWN fee %s' % low)
                                                       for ln in lines]))
    cases.append(('no screens', req, reply, [ln for ln in lines if 'SHOWN' not in ln]))
    g, ins, outs, tx = parse_psbt(reply)  # a signature byte changed
    rb = bytearray(reply)
    for k, v in ins[0]:
        if k[0] in (0x02, 0x13):
            pos = bytes(rb).find(v)
            rb[pos + 10] ^= 1
            cases.append(('signature changed', req, bytes(rb), lines))
            break
    return cases


def check_signed(req_bytes, reply_bytes, log_lines, groups):
    """Returns [(severity, message)] for a request Ruby signed"""
    problems = []
    _, req_in, req_out, req_tx = parse_psbt(req_bytes)
    rep_glob, rep_in, rep_out, rep_tx = parse_psbt(reply_bytes)
    if wally.tx_to_bytes(req_tx, 0) != wally.tx_to_bytes(rep_tx, 0):
        problems.append(('SAFETY', 'the transaction returned is not the one sent'))
    n_out = wally.tx_get_num_outputs(req_tx)
    outs = [(wally.tx_get_output_satoshi(req_tx, i), bytes(wally.tx_get_output_script(req_tx, i))) for i in range(n_out)]

    # what was shown
    shown, hidden, fees, total, count = parse_shown(log_lines)
    if total is None:
        problems.append(('SAFETY', 'signed without showing the outputs'))
        return problems
    if total != n_out or count != len(shown) or set(shown) | hidden != set(range(n_out)) or set(shown) & hidden:
        problems.append(('SAFETY', 'outputs shown %s + hidden %s != the %d outputs' % (sorted(shown), sorted(hidden),
                                                                                         n_out)))
    for i, (addr, amount, flags) in shown.items():
        if i >= n_out:
            continue
        if amount != btc(outs[i][0]):
            problems.append(('SAFETY', 'output %d shows %s, signs %s' % (i, amount, btc(outs[i][0]))))
        expected = address_of(outs[i][1])
        if expected and addr != expected:
            problems.append(('SAFETY', 'output %d shows %s, signs %s' % (i, addr, expected)))

    # the inputs' amounts, and the groups of the inputs Ruby signed (Ruby recognises a group's change only when
    # every input it signs is of that one group)
    in_amount = 0
    in_groups = set()
    mixed = False
    for m, rep in zip(req_in, rep_in):
        f = dict(m)
        wu = f.get(b'\x01')
        if wu:
            in_amount += int.from_bytes(wu[:8], 'little')
        if not [kv for kv in rep if kv not in m]:
            continue  # not signed by Ruby
        g = None
        if wu:
            ln, pos = read_compact(wu, 8)
            g = input_group(wu[pos:pos + ln], m, groups)
        if g:
            in_groups.add(g.name)
        else:
            mixed = True
    fee = in_amount - sum(a for a, _ in outs)
    if not fees or fees[0] != btc(fee):
        problems.append(('SAFETY', 'fee shown %s, inputs - outputs = %s' % (fees[:1], btc(fee))))

    for i, (addr, amount, flags) in shown.items():
        COUNTS['shown verified' if 'verified' in flags else 'shown'] += 1

    # every hidden output provably ours
    for i in sorted(hidden):
        if i >= n_out:
            continue
        why = explain_ours(outs[i][1], req_out[i], groups)
        COUNTS['hidden ' + (why[0] if why else 'unexplained')] += 1
        if not why:
            problems.append(('SAFETY', 'output %d (%s %s) hidden but it is not this Ruby\'s'
                             % (i, address_of(outs[i][1]) or outs[i][1].hex(), btc(outs[i][0]))))
        elif why[0] == 'single' and why[1][-2] != 1:
            problems.append(('DESIGN', 'output %d hidden: a receiving address of this Ruby' % i))
        elif why[0] == 'group':
            g, chain = why[1], why[2]
            if chain != 1:
                problems.append(('DESIGN', 'output %d hidden: receiving address of group %s' % (i, g.name)))
            if mixed or in_groups != {g.name}:
                problems.append(('DESIGN', 'output %d hidden as change of group %s, inputs of %s%s'
                                 % (i, g.name, sorted(in_groups), ' and others' if mixed else '')))

    # the signatures Ruby added verify for this transaction
    problems += check_signatures(req_in, rep_in, req_tx)
    return problems


def verifies(pub_key, msg, flags, sig):
    try:
        wally.ec_sig_verify(pub_key, msg, flags, sig)
        return True
    except ValueError:
        return False


def check_signatures(req_in, rep_in, tx):
    problems = []
    n_in = len(req_in)
    scripts, values = wally.map_init_alloc(n_in, None), []
    have_all = True
    for i, m in enumerate(req_in):
        wu = dict(m).get(b'\x01')
        if not wu:
            have_all = False
            values.append(0)
            continue
        ln, pos = read_compact(wu, 8)
        wally.map_add_integer(scripts, i, wu[pos:pos + ln])
        values.append(int.from_bytes(wu[:8], 'little'))
    for i, (req, rep) in enumerate(zip(req_in, rep_in)):
        added = [kv for kv in rep if kv not in req]
        f = dict(req)
        for k, v in added:
            try:
                if k[0] == 0x02:  # ECDSA partial signature: BIP143, scriptCode from the coin's P2WPKH script
                    pk = k[1:]
                    sighash = v[-1]
                    wu = f.get(b'\x01')
                    ln, pos = read_compact(wu, 8)
                    coin = wu[pos:pos + ln]
                    if len(coin) != 22 or coin[:2] != b'\x00\x14':
                        problems.append(('SAFETY', 'input %d: ECDSA signature for a coin that is not P2WPKH' % i))
                        continue
                    if coin != p2wpkh(pk):
                        problems.append(('NOTE', 'input %d: signed although its coin is not this key\'s script '
                                         '(Jade does the same; the signature cannot spend anything)' % i))
                    script_code = b'\x76\xa9\x14' + coin[2:] + b'\x88\xac'
                    msg = wally.tx_get_btc_signature_hash(tx, i, script_code, values[i], sighash,
                                                          wally.WALLY_TX_FLAG_USE_WITNESS)
                    ok = verifies(pk, msg, wally.EC_FLAG_ECDSA, wally.ec_sig_from_der(v[:-1]))
                elif k[0] in (0x13, 0x14):  # BIP340: key path (0x13) or leaf (0x14: key = xonly || leaf hash)
                    sighash = v[64] if len(v) == 65 else wally.WALLY_SIGHASH_DEFAULT
                    leaf = None
                    if k[0] == 0x14:
                        xonly, lh = k[1:33], k[33:65]
                        leaf = next((lv[:-1] for lk, lv in req if lk[0] == 0x15 and
                                     tagged('TapLeaf', lv[-1:] + compact(len(lv) - 1) + lv[:-1]) == lh), None)
                        key = xonly
                    else:
                        tk = [kk for kk in f if kk[0] == 0x16]
                        merkle = f.get(b'\x18')
                        key = tweak_xonly(tk[0][1:], merkle) if tk else None
                    if not have_all or key is None or (k[0] == 0x14 and leaf is None):
                        problems.append(('SAFETY', 'input %d: a signature that cannot be checked' % i))
                        continue
                    msg = wally.tx_get_btc_taproot_signature_hash(tx, i, scripts, values, leaf, 0,
                                                                  0xffffffff, None, sighash, 0)
                    ok = verifies(b'\x02' + key, msg, wally.EC_FLAG_SCHNORR, v[:64])
                else:
                    problems.append(('SAFETY', 'input %d: Ruby added field %s' % (i, k[:1].hex())))
                    continue
            except Exception as e:
                ok = False
                problems.append(('SAFETY', 'input %d: signature check error %s' % (i, e)))
            if not ok:
                problems.append(('SAFETY', 'input %d: a signature that does not verify for this transaction' % i))
    return problems


# ---------------------------------------------------------------------------------------------------------------
# the emulator
# ---------------------------------------------------------------------------------------------------------------

class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class Emulator:
    def __init__(self, device, start_qemu):
        self.device = device
        self.start_qemu = start_qemu
        self.jade = None
        self.capture = LogCapture()
        dl = logging.getLogger('jadepy.jade-device')
        dl.setLevel(logging.DEBUG)
        dl.addHandler(self.capture)
        dl.propagate = False

    def connect(self, groups):
        if self.start_qemu:
            subprocess.call(['pkill', '-f', 'qemu-system-xtensa'])
            time.sleep(1)
            # qemu-system-xtensa is on the PATH only with ESP-IDF's environment (the image's entrypoint loads it)
            subprocess.Popen(['bash', '-c', 'command -v qemu-system-xtensa >/dev/null || . /opt/esp/idf/export.sh '
                              '>/dev/null 2>&1; exec /jade/main/qemu/qemu_run.sh'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 120
        while True:
            try:
                self.jade = JadeAPI.create_serial(device=self.device, timeout=60)
                self.jade.connect()
                self.jade.get_version_info()
                break
            except Exception:
                if time.time() > deadline:
                    raise
                time.sleep(2)
        self.jade.set_mnemonic(MNEMONIC)
        for g in groups:
            self.jade._jadeRpc('register_group', g.rpc_params(), long_timeout=True)
        # the oracle's group addresses must be Ruby's (Ruby's are checked against the library by TestRuby)
        for g in groups:
            for chain in (0, 1):
                for index in (0, 7):
                    addr = self.jade._jadeRpc('get_receive_address', {'network': NETWORK, 'group_name': g.name,
                                                                      'branch': chain, 'pointer': index})
                    if addr != address_of(g.script(chain, index)):
                        raise RuntimeError('group %s %d/%d: Ruby %s, oracle %s' % (g.name, chain, index, addr,
                                                                                    address_of(g.script(chain,
                                                                                                        index))))

    def disconnect(self):
        try:
            if self.jade:
                self.jade.disconnect()
        except Exception:
            pass
        self.jade = None

    def sign(self, psbt_bytes):
        """(reply psbt bytes or None, error or None, log lines); raises on a lost connection"""
        self.capture.lines = []
        try:
            reply = self.jade.sign_psbt(NETWORK, psbt_bytes)
            return reply, None, list(self.capture.lines)
        except JadeError as e:
            return None, '%s %s' % (e.code, e.message), list(self.capture.lines)


# ---------------------------------------------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--seconds', type=int, default=600)
    ap.add_argument('--seed', type=int, default=None)
    ap.add_argument('--device', default='tcp:127.0.0.1:30121')
    ap.add_argument('--qemu', action='store_true', help='start / restart QEMU here (inside the image)')
    ap.add_argument('--out', default='fuzz/out/rpc')
    ap.add_argument('--replay', help='a findings/<n>.json file: send its request again')
    ap.add_argument('--selftest', type=int, metavar='N',
                    help='check the oracle: N signed payments, each altered so the oracle must flag it')
    args = ap.parse_args()

    seed = args.seed if args.seed is not None else int.from_bytes(os.urandom(4), 'little')
    rng = random.Random(seed)
    os.makedirs(os.path.join(args.out, 'findings'), exist_ok=True)
    groups = make_groups()
    emu = Emulator(args.device, args.qemu)
    emu.connect(groups)
    print('connected; seed %d; groups registered: %s' % (seed, ', '.join(g.name for g in groups)), flush=True)

    if args.replay:
        case = json.load(open(args.replay))
        for n, prev in enumerate(case.get('previous_psbts', [])):  # what Ruby did before (a hang case)
            _, err, _ = emu.sign(bytes.fromhex(prev))
            print('previous %d: %s' % (n, err or 'signed'), flush=True)
        req = bytes.fromhex(case['psbt'])
        reply, err, lines = emu.sign(req)
        print('error' if err else 'signed', err or '')
        for line in lines:
            print('  ', line)
        if reply:
            for sev, msg in check_signed(req, reply, lines, groups):
                print(sev, msg)
        return 0

    if args.selftest:
        missed, checked = 0, 0
        for n in range(args.selftest):
            p = tpl_singlesig(rng, rng.choice([84, 86])) if n % 2 else tpl_group(rng, groups[n % 3])
            req = p.to_bytes()
            reply, err, lines = emu.sign(req)
            if err:
                print('selftest: template refused: %s (%s)' % (err, p.kind))
                missed += 1
                continue
            clean = [x for x in check_signed(req, reply, lines, groups) if x[0] != 'NOTE']
            if clean:
                print('selftest: a valid template flagged: %s (%s)' % (clean, p.kind))
                missed += 1
            for what, rq, rp, ln in selftest_cases(req, bytes(reply), lines):
                checked += 1
                if not [x for x in check_signed(rq, rp, ln, groups) if x[0] == 'SAFETY']:
                    print('selftest: NOT flagged: %s (%s)' % (what, p.kind))
                    missed += 1
        print('selftest: %d altered exchanges checked, %d problems; %s' % (checked, missed, COUNTS))
        return 1 if missed else 0

    stats = {'seed': seed, 'requests': 0, 'signed': 0, 'refused': 0, 'findings': 0, 'design': 0, 'restarts': 0,
             'by_kind': {}, 'errors': {}, 'notes': {}}
    findings = 0
    history = []  # the last requests sent (hex)
    end = time.time() + args.seconds
    while time.time() < end:
        choice = rng.randrange(6)
        if choice < 2:
            p = tpl_singlesig(rng, rng.choice([84, 86]))
        else:
            p = tpl_group(rng, groups[min(choice - 2, 2) if choice < 5 else rng.randrange(3)])
        for _ in range(rng.choice([0, 0, 1, 1, 1, 2, 3])):
            m = rng.choice(MUTATIONS)
            if m(rng, p, groups):
                p.mutations.append(m.__name__)
        req = p.to_bytes()
        if rng.random() < 0.1:
            req = flip_bytes(rng, req)
            p.mutations.append('flip_bytes')
        stats['requests'] += 1
        k = stats['by_kind'].setdefault(p.kind, [0, 0])
        k[0] += 1
        history.append(req.hex())
        del history[:-30]
        try:
            reply, err, lines = emu.sign(req)
        except Exception as e:
            findings += 1
            stats['findings'] += 1
            # with the requests before it: a hang may depend on what Ruby did before (replay them in order)
            case = {'severity': 'SAFETY', 'problems': [['SAFETY', 'Ruby stopped answering: %r' % e]],
                    'kind': p.kind, 'mutations': p.mutations, 'psbt': req.hex(), 'log': list(emu.capture.lines),
                    'request_number': stats['requests'], 'previous_psbts': history[:-1]}
            json.dump(case, open(os.path.join(args.out, 'findings', '%d.json' % findings), 'w'), indent=1)
            print('FINDING %d: Ruby stopped answering (%s, %s)' % (findings, p.kind, p.mutations), flush=True)
            emu.disconnect()
            stats['restarts'] += 1
            if not args.qemu:
                print('the emulator does not answer and --qemu was not given: stopping', flush=True)
                break
            emu.connect(groups)
            continue
        if err:
            stats['refused'] += 1
            short = err.split(':')[0][:60]
            stats['errors'][short] = stats['errors'].get(short, 0) + 1
            if err.startswith('-32603') and stats['errors'][short] <= 20:
                # an internal error (not a refusal of bad parameters): kept to look at, not a finding
                os.makedirs(os.path.join(args.out, 'internal'), exist_ok=True)
                case = {'error': err, 'kind': p.kind, 'mutations': p.mutations, 'psbt': req.hex(), 'log': lines,
                        'shown': any('SHOWN fee' in ln for ln in lines)}
                json.dump(case, open(os.path.join(args.out, 'internal', '%d.json' % stats['requests']), 'w'),
                          indent=1)
            if any('SHOWN fee' in ln for ln in lines):
                # refused after the user confirmed (the CI build confirms every screen): a wasted confirmation, as
                # F2 and F3 were (fuzz/README.md); Ruby must refuse a request before showing it
                findings += 1
                stats['design'] += 1
                case = {'severity': 'DESIGN', 'problems': [['DESIGN', 'refused after the screens: ' + err]],
                        'kind': p.kind, 'mutations': p.mutations, 'psbt': req.hex(), 'log': lines}
                json.dump(case, open(os.path.join(args.out, 'findings', '%d.json' % findings), 'w'), indent=1)
                print('FINDING %d (DESIGN): refused after the screens: %s [%s %s]' % (findings, err, p.kind,
                                                                                      p.mutations), flush=True)
            continue
        stats['signed'] += 1
        k[1] += 1
        try:
            problems = check_signed(req, reply, lines, groups)
        except Exception:
            problems = [('SAFETY', 'oracle error: ' + traceback.format_exc(limit=3))]
        for sev, msg in problems:
            if sev == 'NOTE':
                note = msg.split(':', 1)[-1].strip()
                stats['notes'][note] = stats['notes'].get(note, 0) + 1
        problems = [p for p in problems if p[0] != 'NOTE']
        if problems:
            sev = 'SAFETY' if any(s == 'SAFETY' for s, _ in problems) else 'DESIGN'
            findings += 1
            stats['findings' if sev == 'SAFETY' else 'design'] += 1
            case = {'severity': sev, 'problems': problems, 'kind': p.kind, 'mutations': p.mutations,
                    'psbt': req.hex(), 'reply': reply.hex(), 'log': lines}
            json.dump(case, open(os.path.join(args.out, 'findings', '%d.json' % findings), 'w'), indent=1)
            print('FINDING %d (%s): %s [%s %s]' % (findings, sev, problems[0][1], p.kind, p.mutations), flush=True)
        stats['outputs'] = COUNTS
        if stats['signed'] % 50 == 0:
            print('%d requests, %d signed, %d refused, %d findings, %d design; outputs %s' % (
                stats['requests'], stats['signed'], stats['refused'], stats['findings'], stats['design'], COUNTS),
                flush=True)
            json.dump(stats, open(os.path.join(args.out, 'stats.json'), 'w'), indent=1)
    stats['outputs'] = COUNTS
    json.dump(stats, open(os.path.join(args.out, 'stats.json'), 'w'), indent=1)
    print(json.dumps(stats, indent=1))
    return 1 if stats['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
