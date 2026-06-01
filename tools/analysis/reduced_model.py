#!/usr/bin/env python3
"""
Reduced Volkenborn-2 model for cryptanalysis experiments.

Models the full tick cycle:
  1. Per-coefficient inverse multiplication (precomputed)
  2. Inter-coefficient MDS mixing (XOR + rotate at offsets +1, +7, +16)
  3. Sum extraction (keystream = sum of all coefficients)
  4. Permutation post-processing on output block (simplified ARX)
  5. State shift (rotate coefficients, inject fresh top)
"""
import argparse

MASKS = {16: (1 << 16) - 1, 32: (1 << 32) - 1, 64: (1 << 64) - 1}

def inv_odd_mod(x, bits):
    """Modular inverse of odd x mod 2^bits via Hensel lifting."""
    mod = 1 << bits
    y = 1
    for _ in range(bits.bit_length() + 1):
        y = (y * (2 - x * y)) % mod
    return y

def rotl(x, r, bits):
    """Rotate left by r bits within bits-wide word."""
    r = r % bits
    mask = (1 << bits) - 1
    return ((x << r) | (x >> (bits - r))) & mask

def mds_mix(coeffs, bits):
    """
    Inter-coefficient MDS mixing.
    Each coefficient is XORed with rotated versions of 3 neighbors
    at offsets +1, +7, +16 (mod 32).
    Rotation amounts are distinct per position (nothing-up-my-sleeve).
    """
    n = len(coeffs)
    # Rotation amounts (same as C/Rust implementation, scaled to reduced bits)
    rot_full = [3,7,11,19,29,37,43,53,59,5,13,23,31,41,47,61,
                2,14,22,34,38,50,58,62,9,17,25,33,45,51,55,1]
    rot = [r % bits for r in rot_full[:n]]
    tmp = list(coeffs)
    for i in range(n):
        a = (i + 1) % n
        b = (i + 7) % n
        c = (i + 16) % n
        coeffs[i] ^= rotl(tmp[a], rot[a], bits) ^ rotl(tmp[b], rot[b], bits) ^ rotl(tmp[c], rot[c], bits)

def permute_word(x, bits, rounds=4):
    """
    Simplified ARX permutation on a single word.
    Uses the same structure as v2_permute but reduced to `bits` width.
    For full analysis, use the C/Rust implementation directly.
    """
    mask = (1 << bits) - 1
    c = 0x243f6a8885a308d3 & mask  # nothing-up-my-sleeve constant
    for rnd in range(rounds):
        x = (x + c + (rnd << (bits - 8))) & mask
        x ^= rotl(x, 7, bits)
        x = (x + rotl(x, 13, bits)) & mask
        x = rotl(x, (5 + rnd * 3) % bits, bits)
    return x

def tick(coeffs, bits, inv_cache):
    """
    One full Volkenborn-2 tick:
      1. Multiply each coefficient by its precomputed odd inverse
      2. Apply MDS mixing across all coefficients
      3. Sum all coefficients to produce keystream word
      4. Apply permutation to keystream (non-linear post-processing)
      5. Shift state (rotate + inject)
    """
    mod = 1 << bits

    # Step 1: per-coefficient inverse multiplication
    for i in range(len(coeffs)):
        coeffs[i] = (coeffs[i] * inv_cache[i]) % mod

    # Step 2: MDS mixing (cross-coefficient diffusion)
    mds_mix(coeffs, bits)

    # Step 3: sum extraction
    acc = 0
    for c in coeffs:
        acc = (acc + c) % mod

    # Step 4: permutation post-processing (non-linear output layer)
    ks = permute_word(acc, bits)

    # Step 5: state shift
    out = coeffs[1:] + [((coeffs[0] ^ ks) + 0x9e37 + len(coeffs)) % mod]

    return out, ks

def main():
    ap = argparse.ArgumentParser(description='Reduced Volkenborn-2 model for experiments')
    ap.add_argument('--bits', type=int, default=16, choices=sorted(MASKS))
    ap.add_argument('--coeffs', type=int, default=4)
    ap.add_argument('--rounds', type=int, default=16)
    args = ap.parse_args()

    bits = args.bits
    mod = 1 << bits

    # Precompute inverse coefficients (same as cipher does in v2_init)
    inv_cache = [inv_odd_mod(2 * i + 1, bits) for i in range(args.coeffs)]

    coeffs = [((i + 1) * 0x1235) & (mod - 1) for i in range(args.coeffs)]
    seen = {}

    print(f'Model: {args.coeffs} coefficients, {bits} bits, {args.rounds} rounds')
    print(f'Precomputed inverses: {[f"0x{x:x}" for x in inv_cache]}')
    print()

    for r in range(args.rounds):
        state = tuple(coeffs)
        if state in seen:
            print(f'cycle detected round={r} first={seen[state]} period={r - seen[state]}')
            break
        seen[state] = r
        coeffs, ks = tick(coeffs, bits, inv_cache)
        print(f'round={r:3d} ks=0x{ks:04x} state=' + ','.join(f'0x{x:x}' for x in coeffs))

if __name__ == '__main__':
    main()
