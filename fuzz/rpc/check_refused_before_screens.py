#!/usr/bin/env python3
"""F3 (fuzz/README.md): a payment Ruby can not sign must be refused before any screen.

Sends Ruby (QEMU emulator, CI build with --log-cbor) single-key payments where the coin script of one input Ruby
signs is malformed or of no type Ruby can make a signature hash for, and checks for each one that Ruby either
refuses it with no review screen at all (no "SHOWN" log line), or signs it. Before the fix of F3 Ruby showed the
outputs and the fee, the user confirmed, and only then came "-32603 Failed to generate tx input hash".

Usage: check_refused_before_screens.py [--device tcp:127.0.0.1:30121] [--qemu]
"""
import argparse
import random
import sys

import fuzz_rpc as f

# coin scripts for the input Ruby signs (its key path is still Ruby's)
SCRIPTS = [
    ('F3: push of 33 bytes with 20 left', bytes.fromhex('0021') + bytes(range(20))),
    ('push of 20 bytes with 19 left', bytes.fromhex('0014') + bytes(range(19))),
    ('a lone OP_0', b'\x00'),
    ('a lone push opcode', b'\x4c'),
    ('PUSHDATA2 longer than the script', bytes.fromhex('4dff00') + bytes(10)),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default='tcp:127.0.0.1:30121')
    ap.add_argument('--qemu', action='store_true')
    args = ap.parse_args()
    emu = f.Emulator(args.device, args.qemu)
    emu.connect([])
    bad = 0
    for what, script in SCRIPTS:
        for victim in (0, 1):
            rng = random.Random(11)
            p = f.tpl_singlesig(rng, 84)
            while len(p.ins) < 2:
                p = f.tpl_singlesig(rng, 84)
            fields = p.ins[victim]['fields']
            amount = int.from_bytes(fields[b'\x01'][:8], 'little')
            fields[b'\x01'] = f.witness_utxo(amount, script)
            reply, err, lines = emu.sign(p.to_bytes())
            shown = any('SHOWN ' in ln for ln in lines)
            if err and shown:
                outcome = 'BAD: refused after the screens: ' + err
                bad += 1
            elif err:
                outcome = 'refused before any screen: ' + err
            else:
                outcome = 'signed'
            print('%s (input %d): %s' % (what, victim, outcome), flush=True)
    print('refused after the screens: %d' % bad)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
