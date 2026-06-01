/* donna_poly1305.rs - Poly1305 donna32 streaming implementation
   Exact mirror of donna_poly1305.c — independent, no FFI. */

fn u8to32(p: &[u8]) -> u32 {
    (p[0] as u32) | ((p[1] as u32) << 8) | ((p[2] as u32) << 16) | ((p[3] as u32) << 24)
}

#[derive(Clone)]
pub struct Poly1305State {
    r0: u32, r1: u32, r2: u32, r3: u32, r4: u32,
    s1: u32, s2: u32, s3: u32, s4: u32,
    h0: u32, h1: u32, h2: u32, h3: u32, h4: u32,
    pad0: u32, pad1: u32, pad2: u32, pad3: u32,
    buf: [u8; 16],
    buf_len: usize,
}

fn poly1305_blocks(st: &mut Poly1305State, m: &[u8], bytes: usize) {
    let mut off = 0;
    let mut remaining = bytes;
    while remaining >= 16 {
        let t0 = u8to32(&m[off..off+4]);
        let t1 = u8to32(&m[off+4..off+8]);
        let t2 = u8to32(&m[off+8..off+12]);
        let t3 = u8to32(&m[off+12..off+16]);

        st.h0 = st.h0.wrapping_add(t0 & 0x3ffffff);
        st.h1 = st.h1.wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
        st.h2 = st.h2.wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
        st.h3 = st.h3.wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
        st.h4 = st.h4.wrapping_add((t3 >> 8) | (1 << 24));

        let d0 = (st.h0 as u64 * st.r0 as u64) + (st.h1 as u64 * st.s4 as u64) + (st.h2 as u64 * st.s3 as u64) + (st.h3 as u64 * st.s2 as u64) + (st.h4 as u64 * st.s1 as u64);
        let d1 = (st.h0 as u64 * st.r1 as u64) + (st.h1 as u64 * st.r0 as u64) + (st.h2 as u64 * st.s4 as u64) + (st.h3 as u64 * st.s3 as u64) + (st.h4 as u64 * st.s2 as u64);
        let d2 = (st.h0 as u64 * st.r2 as u64) + (st.h1 as u64 * st.r1 as u64) + (st.h2 as u64 * st.r0 as u64) + (st.h3 as u64 * st.s4 as u64) + (st.h4 as u64 * st.s3 as u64);
        let d3 = (st.h0 as u64 * st.r3 as u64) + (st.h1 as u64 * st.r2 as u64) + (st.h2 as u64 * st.r1 as u64) + (st.h3 as u64 * st.r0 as u64) + (st.h4 as u64 * st.s4 as u64);
        let d4 = (st.h0 as u64 * st.r4 as u64) + (st.h1 as u64 * st.r3 as u64) + (st.h2 as u64 * st.r2 as u64) + (st.h3 as u64 * st.r1 as u64) + (st.h4 as u64 * st.r0 as u64);

        /* C carry chain: d1 += (uint32_t)(d0 >> 32) */
        let d1 = d1 + ((d0 >> 32) as u32 as u64);
        let d2 = d2 + ((d1 >> 32) as u32 as u64);
        let d3 = d3 + ((d2 >> 32) as u32 as u64);
        let d4 = d4 + ((d3 >> 32) as u32 as u64);
        st.h0 = (d0 as u32) & 0x3ffffff;
        st.h1 = (d1 as u32) & 0x3ffffff;
        st.h2 = (d2 as u32) & 0x3ffffff;
        st.h3 = (d3 as u32) & 0x3ffffff;
        st.h4 = (d4 as u32) & 0x3ffffff;
        st.h0 = st.h0.wrapping_add(((d4 >> 32) as u32).wrapping_mul(5));
        st.h1 = st.h1.wrapping_add(st.h0 >> 26); st.h0 &= 0x3ffffff;

        off += 16;
        remaining -= 16;
    }
}

impl Poly1305State {
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = u8to32(&key[0..4]);
        let t1 = u8to32(&key[4..8]);
        let t2 = u8to32(&key[8..12]);
        let t3 = u8to32(&key[12..16]);

        let mut t0 = t0;
        let r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
        let r1 = t0 & 0x3ffff03; t0 >>= 26; t0 |= t2 << 12;
        let r2 = t0 & 0x3ffc0ff; t0 >>= 26; t0 |= t3 << 18;
        let r3 = t0 & 0x3f03fff; t0 >>= 26;
        let r4 = t0 & 0x00fffff;

        Self {
            r0, r1, r2, r3, r4,
            s1: r1 * 5, s2: r2 * 5, s3: r3 * 5, s4: r4 * 5,
            h0: 0, h1: 0, h2: 0, h3: 0, h4: 0,
            pad0: u8to32(&key[16..20]),
            pad1: u8to32(&key[20..24]),
            pad2: u8to32(&key[24..28]),
            pad3: u8to32(&key[28..32]),
            buf: [0u8; 16], buf_len: 0,
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        let mut off = 0;
        let mut bytes = m.len();

        if self.buf_len > 0 {
            let need = 16 - self.buf_len;
            if bytes < need {
                self.buf[self.buf_len..self.buf_len + bytes].copy_from_slice(&m[..bytes]);
                self.buf_len += bytes;
                return;
            }
            self.buf[self.buf_len..16].copy_from_slice(&m[..need]);
            let tmp = self.buf;
            poly1305_blocks(self, &tmp, 16);
            off += need;
            bytes -= need;
            self.buf_len = 0;
        }

        if bytes >= 16 {
            let full = bytes & !15;
            poly1305_blocks(self, &m[off..], full);
            off += full;
            bytes -= full;
        }

        if bytes > 0 {
            self.buf[..bytes].copy_from_slice(&m[off..off + bytes]);
            self.buf_len = bytes;
        }
    }

    pub fn finish(&mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 1;
            poly1305_blocks(self, &block, 16);
        }

        let (mut h0, mut h1, mut h2, mut h3, mut h4) = (self.h0, self.h1, self.h2, self.h3, self.h4);

        h2 = h2.wrapping_add(h1 >> 26); h1 &= 0x3ffffff;
        h3 = h3.wrapping_add(h2 >> 26); h2 &= 0x3ffffff;
        h4 = h4.wrapping_add(h3 >> 26); h3 &= 0x3ffffff;
        h0 = h0.wrapping_add((h4 >> 26).wrapping_mul(5)); h4 &= 0x3ffffff;
        h1 = h1.wrapping_add(h0 >> 26); h0 &= 0x3ffffff;

        let g0 = h0.wrapping_add(5);
        let g1 = h1.wrapping_add(g0 >> 26); let g0 = g0 & 0x3ffffff;
        let g2 = h2.wrapping_add(g1 >> 26); let g1 = g1 & 0x3ffffff;
        let g3 = h3.wrapping_add(g2 >> 26); let g2 = g2 & 0x3ffffff;
        let g4 = h4.wrapping_add(g3 >> 26).wrapping_sub(1 << 26); let g3 = g3 & 0x3ffffff;
        let mask = (g4 >> 31).wrapping_sub(1);
        let (g0, g1, g2, g3, g4) = (g0 & mask, g1 & mask, g2 & mask, g3 & mask, g4 & mask);
        let mask = !mask;
        h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

        /* Finalization — exact C mirror */
        let f0 = (h0 as u64 | ((h1 as u64) << 26)).wrapping_add(self.pad0 as u64);
        let carry0 = if f0 < self.pad0 as u64 { 1u32 } else { 0 };
        let f1 = ((h1 >> 6) as u64 | ((h2 as u64) << 20) | ((h3 as u64) << 46) | ((h4 as u64) << 8))
            .wrapping_add(self.pad1 as u64);
        let t0 = f0 as u32;
        let t1 = (f0 >> 32).wrapping_add(f1).wrapping_add(carry0 as u64) as u32;
        let t2 = ((f1 >> 32) as u32).wrapping_add(self.pad2).wrapping_add(if t1 < f1 as u32 { 1 } else { 0 });
        let t3 = self.pad3.wrapping_add(if t2 < self.pad2 { 1 } else { 0 });

        let mut out = [0u8; 16];
        out[0]  = t0 as u8;        out[1]  = (t0 >> 8) as u8;
        out[2]  = (t0 >> 16) as u8; out[3]  = (t0 >> 24) as u8;
        out[4]  = t1 as u8;        out[5]  = (t1 >> 8) as u8;
        out[6]  = (t1 >> 16) as u8; out[7]  = (t1 >> 24) as u8;
        out[8]  = t2 as u8;        out[9]  = (t2 >> 8) as u8;
        out[10] = (t2 >> 16) as u8; out[11] = (t2 >> 24) as u8;
        out[12] = t3 as u8;        out[13] = (t3 >> 8) as u8;
        out[14] = (t3 >> 16) as u8; out[15] = (t3 >> 24) as u8;
        out
    }
}

pub fn donna_poly1305_auth(out: &mut [u8; 16], m: &[u8], key: &[u8; 32]) {
    let mut st = Poly1305State::new(key);
    st.update(m);
    let tag = st.finish();
    out.copy_from_slice(&tag);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn donna_poly1305_direct() {
        let mut key = [0u8; 32];
        for i in 0..32u8 { key[i as usize] = i.wrapping_mul(37).wrapping_add(13); }
        let mut msg = [0u8; 16];
        msg[0] = 0x42; msg[1] = 1;
        let mut tag = [0u8; 16];
        donna_poly1305_auth(&mut tag, &msg, &key);
        assert_eq!(tag, [0xb1,0x2a,0x56,0x05,0x52,0x17,0x3d,0x7e,0x72,0xf0,0xfe,0xef,0x1a,0x3e,0x63,0x88]);
    }

    #[test]
    fn donna_poly1305_rfc_key() {
        let key: [u8; 32] = [0x8a,0xd5,0xa0,0x8b,0x90,0x5f,0x81,0xcc,
                             0x81,0x50,0x40,0x27,0x4a,0xb2,0x9a,0x71,
                             0x36,0xb0,0x47,0x61,0x5d,0x02,0x60,0x24,
                             0xb2,0x41,0x6e,0xa9,0x61,0x7f,0x61,0xc1];
        let msg = b"Cryptographic Forum Research Group";
        let mut tag = [0u8; 16];
        donna_poly1305_auth(&mut tag, msg, &key);
        assert_eq!(tag, [0x44,0x23,0xb5,0xb1,0x9d,0xf0,0x6f,0xe0,0xd5,0xa5,0x76,0x85,0x62,0x7f,0x61,0xc1]);
    }

    #[test]
    fn donna_poly1305_streaming() {
        let mut key = [0u8; 32];
        for i in 0..32u8 { key[i as usize] = i.wrapping_mul(37).wrapping_add(13); }
        let msg = vec![0x42u8; 100];
        let mut tag1 = [0u8; 16];
        donna_poly1305_auth(&mut tag1, &msg, &key);
        let mut tag2 = [0u8; 16];
        donna_poly1305_auth(&mut tag2, &msg, &key);
        assert_eq!(tag1, tag2, "determinism check");
    }

    #[test]
    fn donna_poly1305_derived_key() {
        use crate::{Volkenborn2, xor_domain16};
        let key: [u8; 32] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f];
        let nonce: [u8; 16] = [0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f];
        let maciv = xor_domain16(&nonce, b"V2-POLY1305-0001");
        let mut ctx = Volkenborn2::new(&key, &maciv);
        let mut okm = [0u8; 64];
        okm[..32].copy_from_slice(&ctx.keystream_block());
        okm[32..].copy_from_slice(&ctx.keystream_block());
        assert_eq!(&okm[0..32], &[0x87,0x83,0x4e,0xe2,0xf3,0x1d,0xa9,0x79,0x12,0x41,0xf4,0x8d,0xd3,0x56,0x95,0xfd,0x95,0x47,0x14,0xfb,0xa1,0x33,0x16,0xfa,0x3a,0x97,0x14,0x46,0x0c,0x07,0x06,0xfd]);
    }
}
