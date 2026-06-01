use std::env;
use std::time::Instant;
use volkenborn2::{seal, Volkenborn2};

fn fill(buf: &mut [u8], seed: u8) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = seed.wrapping_add(131u8.wrapping_mul(i as u8)).wrapping_add((i >> 3) as u8);
    }
}

fn mib_s(bytes: usize, rounds: usize, elapsed: f64) -> f64 {
    if elapsed <= 0.0 { 0.0 } else { (bytes as f64 * rounds as f64 / (1024.0 * 1024.0)) / elapsed }
}

fn bench_raw(bytes: usize, rounds: usize) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    fill(&mut key, 0x42);
    fill(&mut iv, 0x24);
    let mut input = vec![0u8; bytes];
    let mut output = vec![0u8; bytes];
    fill(&mut input, 0x11);
    let start = Instant::now();
    for _ in 0..rounds {
        Volkenborn2::new(&key, &iv).encrypt(&input, &mut output);
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!("raw_encrypt bytes={bytes} rounds={rounds} seconds={elapsed:.6} MiB_s={:.2}", mib_s(bytes, rounds, elapsed));
}

fn bench_seal(bytes: usize, rounds: usize) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    fill(&mut key, 0x52);
    fill(&mut iv, 0x34);
    let mut input = vec![0u8; bytes];
    fill(&mut input, 0x21);
    let start = Instant::now();
    let mut tag_sink = 0u8;
    for _ in 0..rounds {
        let (_, tag) = seal(&key, &iv, &input);
        tag_sink ^= tag[0];
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!("seal bytes={bytes} rounds={rounds} seconds={elapsed:.6} MiB_s={:.2} sink={tag_sink}", mib_s(bytes, rounds, elapsed));
}

fn bench_stream(bytes: usize, rounds: usize) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    fill(&mut key, 0x62);
    fill(&mut iv, 0x44);
    let start = Instant::now();
    let mut sink = 0u8;
    for _ in 0..rounds {
        let mut ctx = Volkenborn2::new(&key, &iv);
        let mut remaining = bytes;
        while remaining != 0 {
            let block = ctx.keystream_block();
            sink ^= block[0];
            remaining -= remaining.min(32);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!("stream bytes={bytes} rounds={rounds} seconds={elapsed:.6} MiB_s={:.2} sink={sink}", mib_s(bytes, rounds, elapsed));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let bytes = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(1 << 20);
    let rounds = args.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(16).max(1);
    bench_raw(bytes, rounds);
    bench_seal(bytes, rounds);
    bench_stream(bytes, rounds);
}
