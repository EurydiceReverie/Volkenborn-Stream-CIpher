use volkenborn2::{Volkenborn2, seal, open, seal_poly1305, open_poly1305, seal_auto_poly1305, open_auto_poly1305};

fn next_u64(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

fn random_bytes(s: &mut u64, out: &mut [u8]) {
    for i in 0..out.len() {
        if (i & 7) == 0 { let _ = next_u64(s); }
        out[i] = (*s >> (8 * (i & 7))) as u8;
    }
}

#[test]
fn random_raw_roundtrip() {
    let mut rng = 0x123456789ABCDEF0u64;
    let lengths = [0usize, 1, 2, 7, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257, 512];
    let mut total = 0u32;
    for _ in 0..50 {
        for &len in &lengths {
            let mut key = [0u8; 32];
            let mut iv = [0u8; 16];
            let mut plain = vec![0u8; len];
            random_bytes(&mut rng, &mut key);
            random_bytes(&mut rng, &mut iv);
            random_bytes(&mut rng, &mut plain);
            let mut cipher = vec![0u8; len];
            let mut recovered = vec![0u8; len];
            Volkenborn2::new(&key, &iv).encrypt(&plain, &mut cipher);
            Volkenborn2::new(&key, &iv).decrypt(&cipher, &mut recovered);
            assert_eq!(plain, recovered, "raw roundtrip failed len={len}");
            total += 1;
        }
    }
    eprintln!("Raw roundtrip: {total}/{total} passed");
}

#[test]
fn random_seal_roundtrip() {
    let mut rng = 0x223456789ABCDEF0u64;
    let lengths = [0usize, 1, 7, 15, 16, 17, 32, 33, 64, 128, 256, 512];
    let mut total = 0u32;
    for _ in 0..50 {
        for &len in &lengths {
            let mut key = [0u8; 32];
            let mut iv = [0u8; 16];
            let mut plain = vec![0u8; len];
            random_bytes(&mut rng, &mut key);
            random_bytes(&mut rng, &mut iv);
            random_bytes(&mut rng, &mut plain);
            let (ciphertext, tag) = seal(&key, &iv, &plain);
            let recovered = open(&key, &iv, &ciphertext, &tag).expect("seal open rejected valid tag");
            assert_eq!(plain, recovered, "seal roundtrip failed len={len}");
            if len > 0 {
                let mut tampered = ciphertext.clone();
                tampered[len / 2] ^= 1;
                assert!(open(&key, &iv, &tampered, &tag).is_none(), "seal tamper not detected len={len}");
            }
            total += 1;
        }
    }
    eprintln!("Seal roundtrip: {total}/{total} passed");
}

#[test]
fn random_poly1305_roundtrip() {
    let mut rng = 0x323456789ABCDEF0u64;
    let lengths = [0usize, 1, 7, 16, 17, 32, 33, 64, 128, 256, 512];
    let mut total = 0u32;
    for _ in 0..50 {
        for &len in &lengths {
            let mut key = [0u8; 32];
            let mut nonce = [0u8; 16];
            let mut plain = vec![0u8; len];
            random_bytes(&mut rng, &mut key);
            random_bytes(&mut rng, &mut nonce);
            random_bytes(&mut rng, &mut plain);
            let (ciphertext, tag) = seal_poly1305(&key, &nonce, &plain);
            let recovered = open_poly1305(&key, &nonce, &ciphertext, &tag).expect("sealp open rejected valid tag");
            assert_eq!(plain, recovered, "sealp roundtrip failed len={len}");
            if len > 0 {
                let mut tampered = ciphertext.clone();
                tampered[len / 2] ^= 1;
                assert!(open_poly1305(&key, &nonce, &tampered, &tag).is_none(), "sealp tamper not detected len={len}");
            }
            total += 1;
        }
    }
    eprintln!("Poly1305 roundtrip: {total}/{total} passed");
}

#[test]
fn random_auto_nonce_roundtrip() {
    let mut rng = 0x423456789ABCDEF0u64;
    let lengths = [0usize, 1, 16, 32, 64, 128, 256];
    let mut total = 0u32;
    for _ in 0..50 {
        for &len in &lengths {
            let mut key = [0u8; 32];
            let mut plain = vec![0u8; len];
            random_bytes(&mut rng, &mut key);
            random_bytes(&mut rng, &mut plain);
            let sealed = seal_auto_poly1305(&key, &plain).expect("seal-auto failed");
            let recovered = open_auto_poly1305(&key, &sealed).expect("open-auto rejected valid sealed");
            assert_eq!(plain, recovered, "auto-nonce roundtrip failed len={len}");
            if sealed.len() > 20 {
                let mut tampered = sealed.clone();
                tampered[20] ^= 1;
                assert!(open_auto_poly1305(&key, &tampered).is_none(), "auto-nonce tamper not detected len={len}");
            }
            total += 1;
        }
    }
    eprintln!("Auto-nonce: {total}/{total} passed");
}

#[test]
fn random_determinism() {
    let mut rng = 0x523456789ABCDEF0u64;
    for _ in 0..100 {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        random_bytes(&mut rng, &mut key);
        random_bytes(&mut rng, &mut iv);
        let plain = [0u8; 64];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        Volkenborn2::new(&key, &iv).encrypt(&plain, &mut a);
        Volkenborn2::new(&key, &iv).encrypt(&plain, &mut b);
        assert_eq!(a, b, "determinism failed");
    }
    eprintln!("Determinism: 100/100 passed");
}

#[test]
fn random_key_iv_diversity() {
    let mut rng = 0x623456789ABCDEF0u64;
    for _ in 0..100 {
        let mut key1 = [0u8; 32];
        let mut iv = [0u8; 16];
        random_bytes(&mut rng, &mut key1);
        random_bytes(&mut rng, &mut iv);
        let mut key2 = key1;
        key2[0] ^= 1;
        let mut ks1 = [0u8; 32];
        let mut ks2 = [0u8; 32];
        Volkenborn2::new(&key1, &iv).keystream_block().iter().enumerate().for_each(|(i, &b)| ks1[i] = b);
        Volkenborn2::new(&key2, &iv).keystream_block().iter().enumerate().for_each(|(i, &b)| ks2[i] = b);
        assert_ne!(ks1, ks2, "different keys produced same output");

        let mut iv2 = iv;
        iv2[0] ^= 1;
        Volkenborn2::new(&key1, &iv).keystream_block().iter().enumerate().for_each(|(i, &b)| ks1[i] = b);
        Volkenborn2::new(&key1, &iv2).keystream_block().iter().enumerate().for_each(|(i, &b)| ks2[i] = b);
        assert_ne!(ks1, ks2, "different IVs produced same output");
    }
    eprintln!("Key/IV diversity: 200/200 passed");
}

#[test]
fn uniqueness_seal_auto() {
    let key = [0x42u8; 32];
    let plain = [0xAAu8; 64];
    let trials = 200;

    let mut sealed_outputs: Vec<Vec<u8>> = Vec::new();
    let mut nonce_collisions = 0u32;
    let mut full_collisions = 0u32;
    let mut decrypt_failures = 0u32;

    for i in 0..trials {
        let sealed = seal_auto_poly1305(&key, &plain).expect("seal-auto failed");

        /* Verify decryption */
        match open_auto_poly1305(&key, &sealed) {
            Some(recovered) => {
                if recovered != plain {
                    eprintln!("roundtrip mismatch at trial {i}");
                    decrypt_failures += 1;
                }
            }
            None => {
                eprintln!("open-auto failed at trial {i}");
                decrypt_failures += 1;
            }
        }

        /* Check uniqueness */
        for (j, prev) in sealed_outputs.iter().enumerate() {
            if sealed[..16] == prev[..16] {
                eprintln!("NONCE COLLISION: trial {i} and {j}");
                nonce_collisions += 1;
            }
            if sealed == *prev {
                eprintln!("FULL COLLISION: trial {i} and {j}");
                full_collisions += 1;
            }
        }
        sealed_outputs.push(sealed);
    }

    eprintln!("=== Uniqueness Test ===");
    eprintln!("Trials: {trials} (same key, same plaintext)");
    eprintln!("Nonce collisions: {nonce_collisions} (expected: 0)");
    eprintln!("Full collisions: {full_collisions} (expected: 0)");
    eprintln!("Decrypt failures: {decrypt_failures} (expected: 0)");
    eprintln!("First 5 nonces:");
    for i in 0..5.min(trials) {
        eprintln!("  [{i}] {:02x?}", &sealed_outputs[i][..16]);
    }

    assert_eq!(nonce_collisions, 0, "nonce collisions detected");
    assert_eq!(full_collisions, 0, "full output collisions detected");
    assert_eq!(decrypt_failures, 0, "decrypt failures detected");
    eprintln!("Uniqueness: {trials}/{trials} all unique - PASS");
}
