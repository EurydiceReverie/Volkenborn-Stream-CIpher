#!/usr/bin/env python3
import argparse, subprocess, tempfile, os, statistics

KEY0 = bytearray(range(32))
IV0 = bytearray(range(32, 48))

def hx(b): return bytes(b).hex()

def stream(tool, key, iv, n):
    return subprocess.check_output([tool, 'stream', hx(key), hx(iv), str(n)])

def bitcount(x): return int(x).bit_count()

def main():
    ap = argparse.ArgumentParser(description='Volkenborn-2 avalanche reporter')
    ap.add_argument('--tool', default='volkenborn2-c/v2tool.exe')
    ap.add_argument('--bytes', type=int, default=256)
    ap.add_argument('--bits', type=int, default=128)
    args = ap.parse_args()
    base = stream(args.tool, KEY0, IV0, args.bytes)
    rates = []
    for bit in range(args.bits):
        key = bytearray(KEY0); iv = bytearray(IV0)
        if bit < 256: key[bit // 8] ^= 1 << (bit & 7)
        else: iv[(bit - 256) // 8] ^= 1 << ((bit - 256) & 7)
        out = stream(args.tool, key, iv, args.bytes)
        flips = sum(bitcount(a ^ b) for a, b in zip(base, out))
        rates.append(flips / (8 * args.bytes))
    print(f'cases={len(rates)} bytes={args.bytes}')
    print(f'mean_flip_rate={statistics.mean(rates):.6f}')
    print(f'min_flip_rate={min(rates):.6f}')
    print(f'max_flip_rate={max(rates):.6f}')
    print(f'stdev={statistics.pstdev(rates):.6f}')

if __name__ == '__main__': main()
