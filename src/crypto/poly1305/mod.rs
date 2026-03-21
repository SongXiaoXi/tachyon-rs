use crate::utils::IntTraits;

#[cfg(avx512_feature)]
#[cfg(any(target_arch = "x86_64"))]
pub mod x86_avx512;

#[derive(Clone)]
pub struct Poly1305 {
    r: [u64; 2],
    h: [u64; 3],
    pad: [u64; 2],
}

impl Poly1305 {
    pub const KEY_LEN: usize = 32;
    pub const TAG_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;

    const HIT_BITS: u64 = 1;

    #[inline(always)]
    pub const fn new(key: [u8; Self::KEY_LEN]) -> Self {
        let t0 = u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
        let t1 = u64::from_le_bytes([key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]]);

        let r0 = t0 & 0x0FFFFFFC0FFFFFFF;
        let r1 = t1 & 0x0FFFFFFC0FFFFFFC;

        let pad = [
            u64::from_le_bytes([key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23]]),
            u64::from_le_bytes([key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31]]),
        ];

        Self { r: [r0, r1], h: [0, 0, 0], pad }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        Self::new(unsafe { crate::utils::slice_to_array(key).clone() })
    }

    #[inline(always)]
    pub(crate) fn block(&mut self, m: &[u8; Self::BLOCK_LEN], hibit: u64) {
        let (mut d0, d1, mut d2, mut d3);

        /* h += m[i] */
        let t0 = u64::from_le_bytes([m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]]);
        let t1 = u64::from_le_bytes([m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]]);

        let h0 = self.h[0];
        let h1 = self.h[1];
        let h2 = self.h[2];

        let (mut h0, carry) = h0.overflowing_add(t0);
        let (mut h1, carry) = adcs(h1, t1, carry);
        let mut h2 = adc(h2, hibit, carry); // the 128th bit

        /* h *= r */
        (d0, d1) = umul128(h0, self.r[0]);
        (d2, d3) = umul128(h1, self.r[0]);
        let (d1, carry) = d1.overflowing_add(d2);
        d2 = h2.wrapping_mul(self.r[0]);
        d2 = adc(d2, d3, carry);

        (d3, h0) = umul128(h0, self.r[1]);
        let (d1, carry) = d1.overflowing_add(d3);
        (d3, h1) = umul128(h1, self.r[1]);
        h2 = h2.wrapping_mul(self.r[1]);
        let (mut d3, carry) = adcs(d3, h0, carry);
        h2 = adc(h2, h1, carry);
        let (mut d2, carry) = d2.overflowing_add(d3);
        d3 = adc(h2, 0, carry);

        /* (partial) h %= p */
        h2 = d2 & 3;
        h0 = d2 & ((-4i32) as u64);
        // d2 = (d2 >> 2) | (d3 << 62);
        d2 = unsafe { crate::utils::disjoint_or(d2 >> 2, d3 << 62) };
        let (h0, carry) = h0.overflowing_add(d0);
        d0 = d3 >> 2;
        h1 = adc(d3, d0, carry);
        let (h0, carry) = h0.overflowing_add(d2);
        let (h1, carry) = adcs(h1, d1, carry);
        h2 = adc(h2, 0, carry);
        
        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        let mut start = 0;
        let mut mlen = m.len();

        while mlen >= Self::BLOCK_LEN * 4 {
            crate::const_loop!(_, 0, 4, {
                let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
                self.block(&chunk, Self::HIT_BITS);
                start += Self::BLOCK_LEN;
            });

            mlen -= Self::BLOCK_LEN * 4;
        }

        while mlen >= Self::BLOCK_LEN {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.block(chunk, Self::HIT_BITS);
            mlen -= Self::BLOCK_LEN;
            start += Self::BLOCK_LEN;
        }

        if mlen > 0 {
            let mut padding_block = [0u8; Self::BLOCK_LEN];
            // Magic: black_box is used to prevent the compiler from using bzero
            core::hint::black_box(padding_block.as_mut_ptr());
            // padding_block[..mlen].copy_from_slice(unsafe {m.get_unchecked(start..start + mlen) });
            unsafe {
                crate::utils::copy_chunks_u8(
                    padding_block.as_mut_ptr(),
                    m.as_ptr().add(start),
                    mlen,
                );
            }
            self.block(&padding_block, Self::HIT_BITS);
        }
    }

    #[inline(always)]
    pub(crate) fn update_16_blocks(&mut self, m: &[u8; 256]) {
        #[crate::loop_unroll(i, 0, 16, 16)]
        fn loop_unroll() {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, i) };
            self.block(&chunk, Self::HIT_BITS);
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let h2 = self.h[2];

        /* compute h + -p */
        let (g0, carry) = h0.overflowing_add(5);
        let (g1, carry) = h1.overflowing_add(carry as u64);
        let g2 = h2.wrapping_add(carry as u64);
        let g2 = g2.wrapping_sub(1 << 2);

        /* select h if h < p, or h + -p if h >= p */
        let sign_bit = !g2.sign_bit();
        h0 = if sign_bit { g0 } else { h0 };
        h1 = if sign_bit { g1 } else { h1 };
        // h2 = if sign_bit == 0 { g2 } else { h2 };

        /* h = (h + pad) */
        let t0 = self.pad[0];
        let t1 = self.pad[1];

        let (h0, carry) = h0.overflowing_add(t0);
        /* mac = h % (2^128) */
        let h1 = adc(h1, t1, carry);

        let mut tag = [0u8; Self::TAG_LEN];
        tag[0..8].copy_from_slice(&h0.to_le_bytes());
        tag[8..16].copy_from_slice(&h1.to_le_bytes());
        tag
    }
}

#[inline(always)]
fn umulh64(a: u64, b: u64) -> u64 {
    ((a as u128).wrapping_mul(b as u128) >> 64) as u64
}

/// Returns the low and high 64 bits of the 128-bit product of a and b
#[inline(always)]
fn umul128(a: u64, b: u64) -> (u64, u64) {
    let res = (a as u128).wrapping_mul(b as u128);
    (res as u64, (res >> 64) as u64)
}

// Use carrying_add if bigint_helper_methods feature is available
#[inline(always)]
fn adcs(a: u64, b: u64, c: bool) -> (u64, bool) {
    let res = a;
    let (res, carry0) = res.overflowing_add(b);
    let (res, carry1) = res.overflowing_add(c as u64);
    // SAFETY: Only one of carry0 and carry1 can be true
    (res, unsafe { crate::utils::disjoint_or(carry0, carry1) })
}

#[inline(always)]
fn adc(a: u64, b: u64, c: bool) -> u64 {
    a.wrapping_add(b).wrapping_add(c as u64)
}
