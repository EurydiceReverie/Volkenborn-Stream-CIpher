use std::env;
use volkenborn2::{open_poly1305, seal_poly1305};

fn next_u64(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn fill(s: &mut u64, out: &mut [u8]) {
    for i in 0..out.len() {
        if (i & 7) == 0 { let _ = next_u64(s); }
        out[i] = (*s >> (8 * (i & 7))) as u8;
    }
}

fn main() {
    let cases = env::args().nth(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(10_000);
    let max_len = env::args().nth(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(2048);
    let mut seed = 0x46555a5a5f56325fu64;
    for case in 0..cases {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 16];
        fill(&mut seed, &mut key);
        fill(&mut seed, &mut nonce);
        let len = (next_u64(&mut seed) as usize) % (max_len + 1);
        let mut plain = vec![0u8; len];
        fill(&mut seed, &mut plain);
        let (mut ct, mut tag) = seal_poly1305(&key, &nonce, &plain);
        let recovered = open_poly1305(&key, &nonce, &ct, &tag).expect("valid tag rejected");
        assert_eq!(plain, recovered, "roundtrip mismatch in case {case}");
        if !ct.is_empty() {
            let idx = (next_u64(&mut seed) as usize) % ct.len();
            ct[idx] ^= 1;
            assert!(open_poly1305(&key, &nonce, &ct, &tag).is_none(), "ciphertext tamper accepted in case {case}");
        } else {
            tag[0] ^= 1;
            assert!(open_poly1305(&key, &nonce, &ct, &tag).is_none(), "tag tamper accepted in case {case}");
        }
    }
    println!("rust deterministic fuzz passed cases={cases} max_len={max_len}");
}
