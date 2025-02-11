
#[derive(Clone)]
pub struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
}

impl Poly1305 {
    pub const KEY_LEN: usize = 32;
    pub const TAG_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;

    #[inline(always)]
    pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
        let t0 = u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
        let t1 = u64::from_le_bytes([key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]]);

        let r0 = t0 & 0xffc0fffffff;
        let r1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
        let r2 = (t1 >> 24) & 0x00ffffffc0f;

        let pad = [
            u64::from_le_bytes([key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23]]),
            u64::from_le_bytes([key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31]]),
        ];

        Self { r: [r0, r1, r2], h: [0, 0, 0], pad }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        Self::new(unsafe { crate::utils::slice_to_array(key).clone() })
    }

    #[inline(always)]
    pub(crate) fn block(&mut self, m: &[u8; Self::BLOCK_LEN], hibit: u64) {
        let mut c;
        let (mut d0, mut d1, mut d2, mut d);

        let s1 = self.r[1] * (5 << 2);
        let s2 = self.r[2] * (5 << 2);

        /* h += m[i] */
        let t0 = u64::from_le_bytes([m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]]);
        let t1 = u64::from_le_bytes([m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]]);

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        h0 += t0 & 0xfffffffffff;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
        h2 += ((t1 >> 24) & 0x3ffffffffff) | hibit;

        /* h *= r */
        d0 = h0 as u128 * self.r[0] as u128;
        d = h1 as u128 * s2 as u128;
        d0 = d0 + d;
        d = h2 as u128 * s1 as u128;
        d0 = d0 + d;

        d1 = h0 as u128 * self.r[1] as u128;
        d = h1 as u128 * self.r[0] as u128;
        d1 = d1 + d;
        d = h2 as u128 * s2 as u128;
        d1 = d1 + d;

        d2 = h0 as u128 * self.r[2] as u128;
        d = h1 as u128 * self.r[1] as u128;
        d2 = d2 + d;
        d = h2 as u128 * self.r[0] as u128;
        d2 = d2 + d;

        /* (partial) h %= p */
        c = (d0 >> 44) as u64;
        h0 = d0 as u64 & 0xfffffffffff;
        d1 += c as u128;
        c = (d1 >> 44) as u64;
        h1 = d1 as u64 & 0xfffffffffff;
        d2 += c as u128;
        c = (d2 >> 42) as u64;
        h2 = d2 as u64 & 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
    }

    fn update_for_test(&mut self, m: &[u8]) {
        let chunks = m.chunks_exact(Self::BLOCK_LEN);

        let rem = chunks.remainder();
        let rlen = rem.len();

        for chunk in chunks {
            let chunk = unsafe { crate::utils::slice_to_array(chunk) };
            self.block(&chunk, 1 << 40);
        }

        if rlen > 0 {
            let mut padding_block = [0u8; Self::BLOCK_LEN];
            padding_block[..rlen].copy_from_slice(rem);
            padding_block[rlen] = 1;

            self.block(&padding_block, 0);
        }
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        let mut start = 0;
        let mut mlen = m.len();

        while mlen >= Self::BLOCK_LEN * 4 {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.block(&chunk, 1 << 40);
            start += Self::BLOCK_LEN;

            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.block(&chunk, 1 << 40);
            start += Self::BLOCK_LEN;

            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.block(&chunk, 1 << 40);
            start += Self::BLOCK_LEN;

            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.block(&chunk, 1 << 40);
            start += Self::BLOCK_LEN;

            mlen -= Self::BLOCK_LEN * 4;
        }

        while mlen >= Self::BLOCK_LEN {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.block(chunk, 1 << 40);
            mlen -= Self::BLOCK_LEN;
            start += Self::BLOCK_LEN;
        }

        if mlen > 0 {
            let mut padding_block = [0u8; Self::BLOCK_LEN];
            padding_block[..mlen].copy_from_slice(&m[start..]);
            self.block(&padding_block, 1 << 40);
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        
        /* fully carry h */
        let mut c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += c;
        c = h2 >> 42;
        h2 &= 0x3ffffffffff;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;

        /* compute h + -p */
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 44;
        g0 &= 0xfffffffffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 44;
        g1 &= 0xfffffffffff;
        let mut g2 = h2.wrapping_add(c).wrapping_sub(1 << 42);

        /* select h if h < p, or h + -p if h >= p */
        let mut mask = (g2 >> (64 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;

        /* h = (h + pad) */
        let t0 = self.pad[0];
        let t1 = self.pad[1];

        h0 += t0 & 0xfffffffffff;
        c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
        c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += ((t1 >> 24) & 0x3ffffffffff) + c;
        h2 &= 0x3ffffffffff;

        /* mac = h % (2^128) */
        h0 |= h1 << 44;
        h1 = (h1 >> 20) | (h2 << 24);

        let mut tag = [0u8; Self::TAG_LEN];
        tag[0..8].copy_from_slice(&h0.to_le_bytes());
        tag[8..16].copy_from_slice(&h1.to_le_bytes());
        tag

    }
}