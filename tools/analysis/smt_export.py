#!/usr/bin/env python3
"""
Export Volkenborn-2 reduced model to SMT-LIB format for SAT/SMT solvers.

Models the full tick:
  1. Per-coefficient inverse multiplication (odd inverse mod 2^b)
  2. Inter-coefficient MDS mixing (XOR + rotate at offsets +1, +7, +16)
  3. Sum extraction (keystream = sum of all coefficients mod 2^b)
  4. ARX permutation post-processing on output
  5. State shift

Usage:
  python smt_export.py --bits 8 --coeffs 4 --rounds 2 > model.smt2
  python smt_export.py --bits 16 --coeffs 8 --rounds 4 > model.smt2
"""
import argparse


def rotl_const(x_var, r, b):
    """Emit SMT-LIB rotate-left by constant r on bitvec of width b."""
    if r % b == 0:
        return x_var
    return f'(bvrol {x_var} #b{r:0{b}b})' if b <= 64 else f'((_ rotate_left {r}) {x_var})'


def main():
    ap = argparse.ArgumentParser(description='Export reduced Volkenborn-2 model to SMT-LIB')
    ap.add_argument('--bits', type=int, default=8, help='bit width per coefficient')
    ap.add_argument('--coeffs', type=int, default=4, help='number of coefficients')
    ap.add_argument('--rounds', type=int, default=2, help='number of tick rounds')
    ap.add_argument('--perm-rounds', type=int, default=2, help='ARX permutation rounds in output layer')
    args = ap.parse_args()

    b = args.bits
    n = args.coeffs
    nr = args.rounds
    pr = args.perm_rounds

    # Rotation amounts for MDS mixing (from the cipher, mod bits)
    rot_full = [3,7,11,19,29,37,43,53,59,5,13,23,31,41,47,61,
                2,14,22,34,38,50,58,62,9,17,25,33,45,51,55,1]
    rot = [r % b for r in rot_full[:n]]

    # Precompute odd inverses mod 2^b
    def inv_odd(x, bits):
        mod = 1 << bits
        y = 1
        for _ in range(bits.bit_length() + 1):
            y = (y * (2 - x * y)) % mod
        return y

    invs = [inv_odd(2 * i + 1, b) for i in range(n)]

    print(f'; Volkenborn-2 reduced SMT model')
    print(f'; {n} coefficients, {b} bits, {nr} rounds, {pr} perm rounds')
    print(f'; Precomputed inverses: {[hex(x) for x in invs]}')
    print(f'; MDS rotation amounts: {rot}')
    print()
    print('(set-logic QF_BV)')
    print()

    # Declare initial state variables
    for r in range(nr + 1):
        for i in range(n):
            print(f'(declare-fun c{r}_{i} () (_ BitVec {b}))')
    # Declare keystream output variables
    for r in range(nr):
        print(f'(declare-fun ks{r} () (_ BitVec {b}))')
    print()

    # Add inverse coefficient constants
    for i in range(n):
        print(f'(define-fun inv_{i} () (_ BitVec {b}) #x{invs[i]:0{(b+3)//4}x})')
    print()

    for r in range(nr):
        print(f'; --- Round {r} ---')

        # Step 1: inverse multiplication
        # c'_i = c_i * inv_i mod 2^b
        for i in range(n):
            print(f'(define-fun m{r}_{i} () (_ BitVec {b}) (bvmul c{r}_{i} inv_{i}))')

        # Step 2: MDS mixing
        # Each coefficient XORed with rotated versions of 3 neighbors
        for i in range(n):
            a = (i + 1) % n
            aa = (i + 7) % n
            aaa = (i + 16) % n
            ra, rb, rc = rot[a], rot[aa], rot[aaa]
            parts = [f'm{r}_{i}']
            for nb, rr in [(a, ra), (aa, rb), (aaa, rc)]:
                if rr == 0:
                    parts.append(f'm{r}_{nb}')
                else:
                    parts.append(f'((_ rotate_left {rr}) m{r}_{nb})')
            if len(parts) == 1:
                print(f'(define-fun x{r}_{i} () (_ BitVec {b}) {parts[0]})')
            else:
                xor_chain = parts[0]
                for p in parts[1:]:
                    xor_chain = f'(bvxor {xor_chain} {p})'
                print(f'(define-fun x{r}_{i} () (_ BitVec {b}) {xor_chain})')

        # Step 3: sum extraction
        sum_expr = f'x{r}_0'
        for i in range(1, n):
            sum_expr = f'(bvadd {sum_expr} x{r}_{i})'
        print(f'(define-fun acc{r} () (_ BitVec {b}) {sum_expr})')

        # Step 4: ARX permutation on output
        print(f'; ARX permutation on acc{r} (simplified: {pr} rounds)')
        perm_expr = f'acc{r}'
        c_const = 0x243f6a8885a308d3 & ((1 << b) - 1)
        for pr_i in range(pr):
            c_val = (c_const + (pr_i << max(0, b - 8))) & ((1 << b) - 1)
            perm_expr = f'(bvadd {perm_expr} #x{c_val:0{(b+3)//4}x})'
            # XOR with rotated self
            r1 = 7 % b
            if r1 > 0:
                perm_expr = f'(bvxor {perm_expr} ((_ rotate_left {r1}) {perm_expr}))'
            r2 = 13 % b
            perm_expr = f'(bvadd {perm_expr} ((_ rotate_left {r2}) {perm_expr}))'
            r3 = (5 + pr_i * 3) % b
            if r3 > 0:
                perm_expr = f'((_ rotate_left {r3}) {perm_expr})'
        print(f'(define-fun perm{r} () (_ BitVec {b}) {perm_expr})')

        # Step 5: keystream = permuted output
        print(f'(assert (= ks{r} perm{r}))')
        print()

        # Step 6: state shift (coefficients rotate down, new top injected)
        for i in range(n - 1):
            print(f'(assert (= c{r+1}_{i} x{r}_{i+1}))')
        # New top coefficient: refresh + feedback from ks
        refresh_val = 0x9e37 + n
        print(f'(define-fun feed{r} () (_ BitVec {b}) (bvadd (bvxor x{r}_0 perm{r}) #x{refresh_val:0{(b+3)//4}x}))')
        print(f'(assert (= c{r+1}_{n-1} feed{r}))')
        print()

    print('; Add observed keystream constraints here:')
    for r in range(nr):
        print(f'; (assert (= ks{r} #x{"00" * ((b+7)//8)})) ; fill in observed keystream')
    print()
    print('; Then run: (check-sat) (get-model)')
    print('(check-sat)')


if __name__ == '__main__':
    main()
