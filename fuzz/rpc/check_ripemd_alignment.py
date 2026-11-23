#!/usr/bin/env python3
"""What an unaligned RIPEMD-160 input does on the ESP32 (fuzz/README.md, "Why AVOID_UNALIGNED_ACCESS").

libwally verifies a psbt's PSBT_IN_RIPEMD160 preimage while it parses the psbt (wally_map_hash_preimage_verify),
on a pointer INTO the bytes the host sent. ccan's RIPEMD-160 (HAVE_UNALIGNED_ACCESS 1 in Ruby's libwally config)
then reads every 64-byte block after the first straight from that buffer as uint32_t. This sends Ruby (QEMU
emulator) a valid payment whose input 0 carries such a field (key = RIPEMD-160 of a 200-byte preimage), shifted by
0..3 bytes so every alignment is tried, then the same payment without the field, and reports what Ruby answers:
  signed / the usual refusal -> the hash came out right; "Failed to extract psbt" -> the hash came out wrong (the
  preimage refused); no answer -> the firmware crashed (an unaligned-access exception).

Usage: check_ripemd_alignment.py [--device tcp:127.0.0.1:30121] [--qemu]
"""
import argparse
import random
import sys

import wallycore as wally

import fuzz_rpc as f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', default='tcp:127.0.0.1:30121')
    ap.add_argument('--qemu', action='store_true')
    args = ap.parse_args()
    emu = f.Emulator(args.device, args.qemu)
    emu.connect([])
    results = []
    # 63 bytes: hashed from ccan's own (aligned) block buffer only; 128+: blocks after the first read in place
    for size in (63, 200, 1000):
        for wrong in (False, True):
            for shift in range(4):
                rng = random.Random(7)  # the same payment every time: only the shift changes
                preimage = bytes(rng.getrandbits(8) for _ in range(size))
                key = b'\x0a' + bytes(wally.ripemd160(preimage))
                p = f.tpl_singlesig(rng, 84)
                fields = p.ins[0]['fields']
                # a proprietary field before it, whose length (1..4 bytes: libwally refuses an empty value) moves
                # the preimage by 'shift' bytes
                fields[b'\xfc\x04ruby\x00'] = bytes(shift + 1)
                fields[key] = preimage if not wrong else preimage[:-1] + bytes([preimage[-1] ^ 1])
                req = p.to_bytes()
                off = req.find(preimage[:32])
                try:
                    reply, err, lines = emu.sign(req)
                    outcome = 'signed' if reply else err
                except Exception as e:
                    outcome = 'NO ANSWER (%r)' % e
                    emu.disconnect()
                    emu.connect([])
                what = '%s %d-byte preimage' % ('wrong' if wrong else 'right', size)
                results.append((what, shift, outcome))
                print('%s, shift %d (psbt offset %d): %s' % (what, shift, off, outcome), flush=True)
    crashed = [r for r in results if r[2].startswith('NO ANSWER')]
    misread = [r for r in results if r[0].startswith('right') and 'extract psbt' in r[2]]
    accepted_wrong = [r for r in results if r[0].startswith('wrong') and 'extract psbt' not in r[2]]
    print('crashes: %d, right preimage refused: %d, wrong preimage accepted: %d'
          % (len(crashed), len(misread), len(accepted_wrong)))
    return 1 if crashed or misread or accepted_wrong else 0


if __name__ == '__main__':
    sys.exit(main())
