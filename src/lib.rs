#![allow(unsafe_code)]

pub mod donna_poly1305;

pub const KEY_BYTES: usize = 32;
pub const IV_BYTES: usize = 16;
pub const BLOCK_BYTES: usize = 32;
pub const TAG_BYTES: usize = 32;
pub const POLY_TAG_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 16;
pub const AUTO_OVERHEAD_BYTES: usize = NONCE_BYTES + POLY_TAG_BYTES;
pub const MAX_BLOCKS: u64 = 1 << 48; /* ~8.8 PiB keystream limit per key/IV */
const COEFFS: usize = 32;

/// Experimental Volkenborn-2 stream cipher context.
///
/// Security status: research prototype only. This cipher is novel and unaudited;
/// do not use it to protect production secrets without extensive cryptanalysis.
#[derive(Clone)]
pub struct Volkenborn2 {
    coeff: [[u64; 4]; COEFFS],
    precomp_inv: [[u64; 4]; COEFFS],
    refresh_key: [u64; 4],
    block_counter: u64,
}

fn load64_le(input: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&input[..8]);
    u64::from_le_bytes(b)
}

fn store_u256(out: &mut [u8; 32], x: &[u64; 4]) {
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&x[i].to_le_bytes());
    }
}

fn load_u256(input: &[u8; 32]) -> [u64; 4] {
    [
        load64_le(&input[0..8]),
        load64_le(&input[8..16]),
        load64_le(&input[16..24]),
        load64_le(&input[24..32]),
    ]
}

fn add256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    out
}

fn sub256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let bi = b[i].wrapping_add(borrow);
        let next_borrow = u64::from(bi < b[i] || a[i] < bi);
        out[i] = a[i].wrapping_sub(bi);
        borrow = next_borrow;
    }
    out
}

fn mul256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..(4 - i) {
            let z = a[i] as u128 * b[j] as u128 + r[i + j] as u128 + carry;
            r[i + j] = z as u64;
            carry = z >> 64;
        }
    }
    r
}

fn inverse_odd_u256(odd: u64) -> [u64; 4] {
    let d = [odd, 0, 0, 0];
    let two = [2, 0, 0, 0];
    let mut x = [1, 0, 0, 0];
    for _ in 0..8 {
        let dx = mul256(d, x);
        let term = sub256(two, dx);
        x = mul256(x, term);
    }
    x
}

fn permute(s: &mut [u64; 8]) {
    const C: [u64; 8] = [
        0x243f6a8885a308d3,
        0x13198a2e03707344,
        0xa4093822299f31d0,
        0x082efa98ec4e6c89,
        0x452821e638d01377,
        0xbe5466cf34e90c6c,
        0xc0ac29b7c97c50dd,
        0x3f84d5b5b5470917,
    ];
    for round in 0..24u64 {
        for i in 0..8 {
            let mut x = s[i]
                .wrapping_add(C[(i + round as usize) & 7])
                .wrapping_add(round << 56);
            x ^= s[(i + 1) & 7].rotate_left(17);
            x = x.wrapping_add(s[(i + 3) & 7].rotate_left(41));
            s[i] = x.rotate_left(7 + ((i as u32 * 9 + round as u32) & 31));
        }
        for i in 0..4 {
            s[i] = s[i].wrapping_add(s[i + 4]);
            s[i + 4] ^= s[i].rotate_left(23 + i as u32);
        }
    }
}

fn xof_init(key: &[u8; 32], iv: &[u8; 16]) -> [u64; 8] {
    let mut s = [
        0x765f32616469635f,
        0x766f6c6b656e626f,
        0x726e5f325f737472,
        0x65616d5f63697068,
        0x65725f7265736561,
        0x7263685f76315f5f,
        0x9e3779b97f4a7c15,
        0xd1b54a32d192ed03,
    ];
    for i in 0..4 {
        s[i] ^= load64_le(&key[i * 8..i * 8 + 8]);
    }
    s[4] ^= load64_le(&iv[0..8]);
    s[5] ^= load64_le(&iv[8..16]);
    s[6] ^= 32;
    s[7] ^= 16;
    permute(&mut s);
    s
}

fn xof_squeeze(s: &mut [u64; 8], domain: u64, counter: u64) -> [u8; 32] {
    s[0] ^= domain;
    s[1] = s[1].wrapping_add(counter);
    s[2] ^= counter.rotate_left(29);
    permute(s);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&(s[i] ^ s[i + 4]).to_le_bytes());
    }
    out
}

fn store_usize_le(out: &mut [u8], x: usize) {
    let v = x as u64;
    out[..8].copy_from_slice(&v.to_le_bytes());
}

fn mac_iv(iv: &[u8; IV_BYTES]) -> [u8; IV_BYTES] {
    const D: [u8; 16] = *b"V2-MAC-DOMAIN-01";
    let mut out = [0u8; 16];
    for i in 0..16 { out[i] = iv[i] ^ D[i]; }
    out
}

pub fn tag_equal(a: &[u8; TAG_BYTES], b: &[u8; TAG_BYTES]) -> bool {
    let mut diff = 0u8;
    for i in 0..TAG_BYTES {
        diff |= a[i] ^ b[i];
    }
    let result = diff == 0;
    std::hint::black_box(result)
}

pub fn mac(key: &[u8; KEY_BYTES], iv: &[u8; IV_BYTES], data: &[u8]) -> [u8; TAG_BYTES] {
    let miv = mac_iv(iv);
    let mut ctx = Volkenborn2::new(key, &miv);
    let mut acc = [0u8; 32];
    store_usize_le(&mut acc[0..8], data.len());
    store_usize_le(&mut acc[8..16], data.len() ^ usize::MAX);
    let mut off = 0usize;
    while off < data.len() || (data.is_empty() && off == 0) {
        let take = (data.len() - off).min(32);
        let mut block = [0u8; 32];
        if take != 0 { block[..take].copy_from_slice(&data[off..off + take]); }
        block[0] ^= take as u8;
        block[31] ^= if off + take == data.len() { 0x81 } else { 0x18 };
        let ks = ctx.keystream_block();
        for i in 0..32 { acc[i] ^= block[i] ^ ks[i]; }
        off += take;
        if take == 0 { break; }
    }
    let mut tag = [0u8; 32];
    ctx.encrypt(&acc, &mut tag);
    tag
}

pub fn seal(key: &[u8; KEY_BYTES], iv: &[u8; IV_BYTES], plaintext: &[u8]) -> (Vec<u8>, [u8; TAG_BYTES]) {
    let mut ciphertext = vec![0u8; plaintext.len()];
    Volkenborn2::new(key, iv).encrypt(plaintext, &mut ciphertext);
    let tag = mac(key, iv, &ciphertext);
    (ciphertext, tag)
}

pub fn open(key: &[u8; KEY_BYTES], iv: &[u8; IV_BYTES], ciphertext: &[u8], tag: &[u8; TAG_BYTES]) -> Option<Vec<u8>> {
    let expected = mac(key, iv, ciphertext);
    if !tag_equal(&expected, tag) { return None; }
    let mut plaintext = vec![0u8; ciphertext.len()];
    Volkenborn2::new(key, iv).decrypt(ciphertext, &mut plaintext);
    Some(plaintext)
}

fn xor_domain16(input: &[u8; 16], domain: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 { out[i] = input[i] ^ domain[i]; }
    out
}

pub fn derive_message_iv(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> [u8; IV_BYTES] {
    let div = xor_domain16(nonce, b"V2-IV-DERIVE-001");
    let mut ctx = Volkenborn2::new(key, &div);
    let stream = ctx.keystream_block();
    let mut iv = [0u8; 16];
    for i in 0..16 { iv[i] = stream[i] ^ nonce[15 - i]; }
    iv
}

/* Custom poly1305_auth16 - kept for reference, replaced by donna_poly1305 */
/*
fn poly1305_auth16(m: &[u8], key: &[u8; 32]) -> [u8; 16] {
    ... custom implementation commented out ...
}
*/

pub fn poly1305_mac32(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], ciphertext: &[u8]) -> Option<[u8; POLY_TAG_BYTES]> {
    let maciv = xor_domain16(nonce, b"V2-POLY1305-0001");
    let mut ctx = Volkenborn2::new(key, &maciv);
    let mut okm = [0u8; 64];
    okm[..32].copy_from_slice(&ctx.keystream_block());
    okm[32..].copy_from_slice(&ctx.keystream_block());

    let mut lenb = [0u8; 8];
    store_usize_le(&mut lenb, ciphertext.len());

    /* Build header: domain || nonce || length */
    let mut hdr = [0u8; 40];
    hdr[..16].copy_from_slice(b"V2-P1305-SEAL001");
    hdr[16..32].copy_from_slice(nonce);
    hdr[32..40].copy_from_slice(&lenb);

    let k0: [u8; 32] = okm[..32].try_into().unwrap();
    let k1: [u8; 32] = okm[32..].try_into().unwrap();

    /* First tag: header || ciphertext */
    let mut framed = Vec::with_capacity(40 + ciphertext.len());
    framed.extend_from_slice(&hdr);
    framed.extend_from_slice(ciphertext);
    let mut tag = [0u8; 32];
    donna_poly1305::donna_poly1305_auth((&mut tag[..16]).try_into().unwrap(), &framed, &k0);
    framed[0] ^= 0x80;
    donna_poly1305::donna_poly1305_auth((&mut tag[16..]).try_into().unwrap(), &framed, &k1);
    Some(tag)
}

pub fn seal_poly1305(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> (Vec<u8>, [u8; POLY_TAG_BYTES]) {
    let iv = derive_message_iv(key, nonce);
    let mut ciphertext = vec![0u8; plaintext.len()];
    Volkenborn2::new(key, &iv).encrypt(plaintext, &mut ciphertext);
    let tag = poly1305_mac32(key, nonce, &ciphertext).expect("poly1305_mac32 failed");
    (ciphertext, tag)
}

pub fn open_poly1305(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], ciphertext: &[u8], tag: &[u8; POLY_TAG_BYTES]) -> Option<Vec<u8>> {
    let expected = poly1305_mac32(key, nonce, ciphertext)?;
    if !tag_equal(&expected, tag) { return None; }
    let iv = derive_message_iv(key, nonce);
    let mut plaintext = vec![0u8; ciphertext.len()];
    Volkenborn2::new(key, &iv).decrypt(ciphertext, &mut plaintext);
    Some(plaintext)
}

#[cfg(unix)]
pub fn random_nonce() -> std::io::Result<[u8; NONCE_BYTES]> {
    use std::io::Read;
    let mut nonce = [0u8; NONCE_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    Ok(nonce)
}

#[cfg(windows)]
pub fn random_nonce() -> std::io::Result<[u8; NONCE_BYTES]> {
    use std::io;
    type HCRYPTPROV = usize;
    const PROV_RSA_FULL: u32 = 1;
    const CRYPT_VERIFYCONTEXT: u32 = 0xF0000000;
    #[link(name = "advapi32")]
    extern "system" {
        fn CryptAcquireContextA(phprov: *mut HCRYPTPROV, pszcontainer: *const u8, pszprovider: *const u8, dwprovtype: u32, dwflags: u32) -> i32;
        fn CryptGenRandom(hprov: HCRYPTPROV, dwlen: u32, pbbuffer: *mut u8) -> i32;
        fn CryptReleaseContext(hprov: HCRYPTPROV, dwflags: u32) -> i32;
    }
    let mut nonce = [0u8; NONCE_BYTES];
    let mut prov: HCRYPTPROV = 0;
    unsafe {
        if CryptAcquireContextA(&mut prov, std::ptr::null(), std::ptr::null(), PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == 0 {
            return Err(io::Error::last_os_error());
        }
        let ok = CryptGenRandom(prov, NONCE_BYTES as u32, nonce.as_mut_ptr());
        let _ = CryptReleaseContext(prov, 0);
        if ok == 0 { return Err(io::Error::last_os_error()); }
    }
    Ok(nonce)
}

pub fn seal_auto_poly1305(key: &[u8; KEY_BYTES], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
    let nonce = random_nonce()?;
    let (ciphertext, tag) = seal_poly1305(key, &nonce, plaintext);
    let mut sealed = Vec::with_capacity(AUTO_OVERHEAD_BYTES + plaintext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

pub fn open_auto_poly1305(key: &[u8; KEY_BYTES], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < AUTO_OVERHEAD_BYTES { return None; }
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&sealed[..NONCE_BYTES]);
    let clen = sealed.len() - AUTO_OVERHEAD_BYTES;
    let ciphertext = &sealed[NONCE_BYTES..NONCE_BYTES + clen];
    let mut tag = [0u8; POLY_TAG_BYTES];
    tag.copy_from_slice(&sealed[NONCE_BYTES + clen..]);
    open_poly1305(key, &nonce, ciphertext, &tag)
}

const STREAM_CHUNK: usize = 4096;

fn poly1305_derive_keys(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> ([u8; 32], [u8; 32]) {
    let maciv = xor_domain16(nonce, b"V2-POLY1305-0001");
    let mut ctx = Volkenborn2::new(key, &maciv);
    let mut okm = [0u8; 64];
    okm[..32].copy_from_slice(&ctx.keystream_block());
    okm[32..].copy_from_slice(&ctx.keystream_block());
    let k0: [u8; 32] = okm[..32].try_into().unwrap();
    let k1: [u8; 32] = okm[32..].try_into().unwrap();
    (k0, k1)
}

fn poly1305_build_header(nonce: &[u8; NONCE_BYTES], total_len: usize) -> [u8; 40] {
    let mut hdr = [0u8; 40];
    hdr[..16].copy_from_slice(b"V2-P1305-SEAL001");
    hdr[16..32].copy_from_slice(nonce);
    hdr[32..40].copy_from_slice(&(total_len as u64).to_le_bytes());
    hdr
}

pub fn sealp_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES],
    input: &mut R, output: &mut W,
) -> std::io::Result<()> {
    let iv = derive_message_iv(key, nonce);
    let mut ctx = Volkenborn2::new(key, &iv);
    let (k0, k1) = poly1305_derive_keys(key, nonce);
    let hdr = poly1305_build_header(nonce, 0);

    let mut poly0 = donna_poly1305::Poly1305State::new(&k0);
    poly0.update(&hdr);
    let mut poly1 = donna_poly1305::Poly1305State::new(&k1);
    poly1.update(&hdr);

    let mut buf = [0u8; STREAM_CHUNK];
    let mut out = [0u8; STREAM_CHUNK];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 { break; }
        ctx.encrypt(&buf[..n], &mut out[..n]);
        output.write_all(&out[..n])?;
        poly0.update(&out[..n]);
        poly1.update(&out[..n]);
    }

    let mut tag = [0u8; 32];
    tag[..16].copy_from_slice(&poly0.finish());
    tag[16..].copy_from_slice(&poly1.finish());
    output.write_all(&tag)?;
    Ok(())
}

pub fn openp_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES],
    input: &mut R, output: &mut W,
) -> std::io::Result<bool> {
    let iv = derive_message_iv(key, nonce);
    let mut ctx = Volkenborn2::new(key, &iv);
    let (k0, k1) = poly1305_derive_keys(key, nonce);
    let hdr = poly1305_build_header(nonce, 0);

    let mut poly0 = donna_poly1305::Poly1305State::new(&k0);
    poly0.update(&hdr);
    let mut poly1 = donna_poly1305::Poly1305State::new(&k1);
    poly1.update(&hdr);

    /* Accumulate all input, then split: all but last 32 bytes = ciphertext, last 32 = tag.
       For streaming, use a sliding window that always keeps 32 bytes buffered. */
    let mut window = [0u8; 64];
    let mut win_len = 0usize;
    let mut out = [0u8; 64];
    let mut buf = [0u8; STREAM_CHUNK];

    loop {
        let n = input.read(&mut buf)?;
        if n == 0 { break; }

        let mut src = 0;
        while src < n {
            /* Fill window to 64 bytes if possible */
            let space = 64 - win_len;
            let copy = (n - src).min(space);
            window[win_len..win_len + copy].copy_from_slice(&buf[src..src + copy]);
            win_len += copy;
            src += copy;

            /* If window is full, update MAC with ciphertext BEFORE decrypting */
            if win_len == 64 {
                poly0.update(&window[..32]);
                poly1.update(&window[..32]);
                ctx.encrypt(&window[..32], &mut out[..32]);
                output.write_all(&out[..32])?;
                window.copy_within(32..64, 0);
                win_len = 32;
            }
        }
    }

    /* At EOF: window contains win_len bytes. Last 32 are the tag, rest is ciphertext. */
    if win_len < 32 { return Ok(false); }
    let cipher_bytes = win_len - 32;

    if cipher_bytes > 0 {
        poly0.update(&window[..cipher_bytes]);
        poly1.update(&window[..cipher_bytes]);
        ctx.encrypt(&window[..cipher_bytes], &mut out[..cipher_bytes]);
        output.write_all(&out[..cipher_bytes])?;
    }

    let received_tag: [u8; 32] = window[cipher_bytes..cipher_bytes + 32].try_into().unwrap();

    let mut expected = [0u8; 32];
    expected[..16].copy_from_slice(&poly0.finish());
    expected[16..].copy_from_slice(&poly1.finish());

    Ok(tag_equal(&expected, &received_tag))
}

pub fn seal_auto_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; KEY_BYTES], input: &mut R, output: &mut W,
) -> std::io::Result<()> {
    let nonce = random_nonce()?;
    output.write_all(&nonce)?;
    sealp_stream(key, &nonce, input, output)
}

pub fn open_auto_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; KEY_BYTES], input: &mut R, output: &mut W,
) -> std::io::Result<bool> {
    let mut nonce = [0u8; NONCE_BYTES];
    input.read_exact(&mut nonce)?;
    openp_stream(key, &nonce, input, output)
}

impl Volkenborn2 {
    pub fn new(key: &[u8; KEY_BYTES], iv: &[u8; IV_BYTES]) -> Self {
        let mut s = xof_init(key, iv);
        let mut coeff = [[0u64; 4]; COEFFS];
        for i in 0..COEFFS {
            let b = xof_squeeze(&mut s, 0x434f454646000000 | i as u64, i as u64);
            coeff[i] = load_u256(&b);
        }
        let b = xof_squeeze(&mut s, 0x524546524b455901, 0);
        let refresh_key = load_u256(&b);
        let mut precomp_inv = [[0u64; 4]; COEFFS];
        for i in 0..COEFFS {
            precomp_inv[i] = inverse_odd_u256(2 * i as u64 + 1);
        }
        Self { coeff, precomp_inv, refresh_key, block_counter: 0 }
    }

    fn refresh_coeff(&self, counter: u64) -> [u64; 4] {
        let mut s = [
            0x6d61686c65725f72,
            0x6566726573685f32,
            0x766f6c6b656e3231,
            0x70616469635f6b64,
            self.refresh_key[0],
            self.refresh_key[1],
            self.refresh_key[2],
            self.refresh_key[3],
        ];
        let b = xof_squeeze(&mut s, 0x5245465245534801, counter);
        load_u256(&b)
    }

    fn integrate_and_extract(&mut self) -> [u64; 4] {
        for i in 0..COEFFS {
            self.coeff[i] = mul256(self.coeff[i], self.precomp_inv[i]);
        }
        self.coeff_mds_mix();
        let mut acc = [0u64; 4];
        for i in 0..COEFFS {
            acc = add256(acc, self.coeff[i]);
        }
        acc
    }

    fn coeff_mds_mix(&mut self) {
        const ROT: [u32; COEFFS] = [
            3, 7, 11, 19, 29, 37, 43, 53,
            59, 5, 13, 23, 31, 41, 47, 61,
            2, 14, 22, 34, 38, 50, 58, 62,
            9, 17, 25, 33, 45, 51, 55, 1
        ];
        let tmp = self.coeff;
        for i in 0..COEFFS {
            let a = (i + 1) & 31;
            let b = (i + 7) & 31;
            let c = (i + 16) & 31;
            let rot = |x: [u64; 4], r: u32| -> [u64; 4] {
                let w = r & 63;
                if w == 0 { return x; }
                [
                    (x[0] << w) | (x[3] >> (64 - w)),
                    (x[1] << w) | (x[0] >> (64 - w)),
                    (x[2] << w) | (x[1] >> (64 - w)),
                    (x[3] << w) | (x[2] >> (64 - w)),
                ]
            };
            let ra = rot(tmp[a], ROT[a]);
            let rb = rot(tmp[b], ROT[b]);
            let rc = rot(tmp[c], ROT[c]);
            for j in 0..4 {
                self.coeff[i][j] ^= ra[j] ^ rb[j] ^ rc[j];
            }
        }
    }

    fn shift_state(&mut self) {
        let new_top = self.refresh_coeff(self.block_counter);
        for i in 0..COEFFS - 1 {
            self.coeff[i] = self.coeff[i + 1];
        }
        self.coeff[COEFFS - 1] = new_top;
        self.block_counter = self.block_counter.wrapping_add(1);
    }

    pub fn keystream_block(&mut self) -> [u8; BLOCK_BYTES] {
        let k = self.integrate_and_extract();
        let mut s = [0u64; 8];
        s[..4].copy_from_slice(&k);
        permute(&mut s);
        let mut mixed = [0u64; 4];
        for i in 0..4 { mixed[i] = k[i] ^ s[i] ^ s[i + 4]; }
        let mut out = [0u8; 32];
        store_u256(&mut out, &mixed);
        for i in 0..4 { self.refresh_key[i] ^= mixed[i]; }
        self.shift_state();
        out
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        assert_eq!(plaintext.len(), ciphertext.len(), "input/output length mismatch");
        self.crypt(plaintext, ciphertext);
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        assert_eq!(ciphertext.len(), plaintext.len(), "input/output length mismatch");
        self.crypt(ciphertext, plaintext);
    }

    fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        let mut offset = 0;
        while offset < input.len() {
            let take = (input.len() - offset).min(32);
            let kb = self.keystream_block();
            for i in 0..take {
                output[offset + i] = input[offset + i] ^ kb[i];
            }
            offset += take;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(buf: &mut [u8], seed: u8) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = seed.wrapping_add(31u8.wrapping_mul(i as u8)).wrapping_add((i >> 1) as u8);
        }
    }

    #[test]
    fn roundtrips_various_lengths() {
        for len in [0usize, 1, 7, 31, 32, 33, 64, 129, 257] {
            let mut key = [0u8; 32];
            let mut iv = [0u8; 16];
            fill(&mut key, 0x10);
            fill(&mut iv, 0x80);
            let mut plain = vec![0u8; len];
            fill(&mut plain, 0x33);
            let mut cipher = vec![0u8; len];
            let mut recovered = vec![0u8; len];
            Volkenborn2::new(&key, &iv).encrypt(&plain, &mut cipher);
            Volkenborn2::new(&key, &iv).decrypt(&cipher, &mut recovered);
            assert_eq!(plain, recovered, "failed length {len}");
        }
    }

    #[test]
    fn deterministic() {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        fill(&mut key, 1);
        fill(&mut iv, 2);
        let plain = [0u8; 64];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        Volkenborn2::new(&key, &iv).encrypt(&plain, &mut a);
        Volkenborn2::new(&key, &iv).encrypt(&plain, &mut b);
        assert_eq!(a, b);
    }

    fn next_u64(s: &mut u64) -> u64 {
        let mut x = *s;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *s = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn prng_fill(s: &mut u64, p: &mut [u8]) {
        for i in 0..p.len() {
            if (i & 7) == 0 { let _ = next_u64(s); }
            p[i] = (*s >> (8 * (i & 7))) as u8;
        }
    }

    #[test]
    fn official_fixed_vectors() {
        let key: [u8; 32] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let iv: [u8; 16] = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f];
        let plain: [u8; 64] = [0x09, 0x16, 0x23, 0x30, 0x3d, 0x4a, 0x57, 0x64, 0x71, 0x7e, 0x8b, 0x98, 0xa5, 0xb2, 0xbf, 0xcc, 0xd9, 0xe6, 0xf3, 0x00, 0x0d, 0x1a, 0x27, 0x34, 0x41, 0x4e, 0x5b, 0x68, 0x75, 0x82, 0x8f, 0x9c, 0xa9, 0xb6, 0xc3, 0xd0, 0xdd, 0xea, 0xf7, 0x04, 0x11, 0x1e, 0x2b, 0x38, 0x45, 0x52, 0x5f, 0x6c, 0x79, 0x86, 0x93, 0xa0, 0xad, 0xba, 0xc7, 0xd4, 0xe1, 0xee, 0xfb, 0x08, 0x15, 0x22, 0x2f, 0x3c];
        let stream: [u8; 64] = [0x72,0x14,0x07,0xe7,0x52,0x04,0xf1,0xc8,0x75,0xd0,0xd1,0x3a,0x86,0xab,0x83,0x23,0xb4,0x72,0x27,0x2c,0xc1,0x0c,0xc6,0xb0,0xb4,0x9e,0xab,0x07,0x48,0x32,0x96,0x59,0x25,0x82,0x74,0x33,0x4a,0x80,0x51,0x63,0x36,0x56,0x09,0x50,0x64,0x97,0x0a,0x6d,0x43,0x93,0x14,0x4e,0xe6,0x90,0x8a,0xe1,0xf7,0xa5,0x0e,0xba,0x8a,0x4b,0x19,0x7f];
        let cipher_expected: [u8; 64] = [0x7b,0x02,0x24,0xd7,0x6f,0x4e,0xa6,0xac,0x04,0xae,0x5a,0xa2,0x23,0x19,0x3c,0xef,0x6d,0x94,0xd4,0x2c,0xcc,0x16,0xe1,0x84,0xf5,0xd0,0xf0,0x6f,0x3d,0xb0,0x19,0xc5,0x8c,0x34,0xb7,0xe3,0x97,0x6a,0xa6,0x67,0x27,0x48,0x22,0x68,0x21,0xc5,0x55,0x01,0x3a,0x15,0x87,0xee,0x4b,0x2a,0x4d,0x35,0x16,0x4b,0xf5,0xb2,0x9f,0x69,0x36,0x43];
        let tag_expected: [u8; 32] = [0x9c,0x03,0x53,0x23,0x73,0x33,0x19,0xe6,0x21,0x06,0x79,0x70,0x52,0x2f,0xb9,0xd1,0xbf,0x96,0xbc,0xc2,0xb0,0x47,0x16,0xaa,0x89,0xcf,0x2b,0x00,0x67,0x55,0xde,0xf2];
        let mut ctx = Volkenborn2::new(&key, &iv);
        let mut got = [0u8; 64];
        got[..32].copy_from_slice(&ctx.keystream_block());
        got[32..].copy_from_slice(&ctx.keystream_block());
        assert_eq!(got, stream);
        let mut cipher = [0u8; 64];
        Volkenborn2::new(&key, &iv).encrypt(&plain, &mut cipher);
        assert_eq!(cipher, cipher_expected);
        let (sealed_cipher, tag) = seal(&key, &iv, &plain);
        assert_eq!(sealed_cipher, cipher_expected);
        assert_eq!(tag, tag_expected);
    }

    #[test]
    fn poly1305_roundtrip_and_tamper_rejection() {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 16];
        fill(&mut key, 0x44);
        fill(&mut nonce, 0x55);
        let mut plain = vec![0u8; 257];
        fill(&mut plain, 0x66);
        let (mut ciphertext, mut tag) = seal_poly1305(&key, &nonce, &plain);
        assert_eq!(open_poly1305(&key, &nonce, &ciphertext, &tag).unwrap(), plain);
        ciphertext[17] ^= 1;
        assert!(open_poly1305(&key, &nonce, &ciphertext, &tag).is_none());
        ciphertext[17] ^= 1;
        tag[0] ^= 1;
        assert!(open_poly1305(&key, &nonce, &ciphertext, &tag).is_none());
    }

    #[test]
    fn auto_nonce_roundtrip_and_tamper_rejection() {
        let mut key = [0u8; 32];
        fill(&mut key, 0x77);
        let mut plain = vec![0u8; 123];
        fill(&mut plain, 0x88);
        let mut sealed = seal_auto_poly1305(&key, &plain).expect("rng should work");
        assert_eq!(sealed.len(), plain.len() + AUTO_OVERHEAD_BYTES);
        assert_eq!(open_auto_poly1305(&key, &sealed).unwrap(), plain);
        sealed[20] ^= 1;
        assert!(open_auto_poly1305(&key, &sealed).is_none());
    }

    #[test]
    fn authenticated_roundtrip_and_tamper_rejection() {
        for i in 0..96u64 {
            let len = ((i * i + 17 * i) % 514) as usize;
            let mut s = 0xC0DEC0DEC0DE0001u64 + i;
            let mut key = [0u8; 32];
            let mut iv = [0u8; 16];
            let mut plain = vec![0u8; len];
            prng_fill(&mut s, &mut key);
            prng_fill(&mut s, &mut iv);
            prng_fill(&mut s, &mut plain);
            let (mut ciphertext, mut tag) = seal(&key, &iv, &plain);
            let recovered = open(&key, &iv, &ciphertext, &tag).expect("tag should verify");
            assert_eq!(plain, recovered);
            if len != 0 {
                let mid = len / 2;
                ciphertext[mid] ^= 1;
                assert!(open(&key, &iv, &ciphertext, &tag).is_none());
            } else {
                tag[0] ^= 1;
                assert!(open(&key, &iv, &ciphertext, &tag).is_none());
            }
        }
    }
}
