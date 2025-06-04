#[derive(Clone, Copy)]
pub struct GHash {
    hh: [u64; Self::BLOCK_LEN],
    hl: [u64; Self::BLOCK_LEN],
    buf: [u8; Self::BLOCK_LEN],
}

impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = true;

    #[inline]
    pub fn new(h: &[u8; Self::BLOCK_LEN]) -> Self {
        // pack h as two 64-bits ints, big-endian
        let mut vh = u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
        let mut vl = u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);

        let mut hl = [0u64; Self::BLOCK_LEN];
        let mut hh = [0u64; Self::BLOCK_LEN];

        // 8 = 1000 corresponds to 1 in GF(2^128)
        hl[8] = vl;
        hh[8] = vh;

        let mut i = 4usize;
        while i > 0 {
            // 4, 2, 1
            let t = (vl & 1) * 0xe1000000;
            vl = (vh << 63) | (vl >> 1);
            vh = (vh >> 1) ^ (t << 32);

            hl[i] = vl;
            hh[i] = vh;

            i >>= 1;
        }

        i = 2usize;
        while i <= 8 {
            // 2, 4, 8
            vh = hh[i];
            vl = hl[i];
            for j in 1usize..i {
                hh[i + j] = vh ^ hh[j];
                hl[i + j] = vl ^ hl[j];
            }
            i *= 2;
        }

        let buf = [0u8; 16];

        Self { hh, hl, buf }
    }

    // Multiplication operation in GF(2^128)
    #[inline(always)]
    fn gf_mul(&mut self, x: &[u8; 16]) {
        // Reduction table
        //
        // Shoup's method for multiplication use this table with
        //     last4[x] = x times P^128
        // where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
        static LAST4: [u32; 16] = [
            0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940,
            0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
        ];

        let hh = &self.hh;
        let hl = &self.hl;

        crate::const_loop!(i, 0, 16, {
            self.buf[i] ^= x[i];
        });
        let x = &mut self.buf;

        let mut lo: u8 = x[15] & 0xf;
        let mut hi: u8;
        let mut zh: u64 = hh[lo as usize];
        let mut zl: u64 = hl[lo as usize];
        let mut rem: u8;

        crate::const_loop!(i, 0, 16, {
            lo = x[16 - 1 - i] & 0xf;
            hi = (x[16 - 1 - i] >> 4) & 0xf;

            if i != 0 {
                rem = (zl & 0xf) as u8;
                zl = (zh << 60) | (zl >> 4);
                zh = zh >> 4;
                zh ^= (LAST4[rem as usize] as u64) << 48;
                zh ^= hh[lo as usize];
                zl ^= hl[lo as usize];
            }

            rem = (zl & 0xf) as u8;
            zl = (zh << 60) | (zl >> 4);
            zh = zh >> 4;

            zh ^= (LAST4[rem as usize] as u64) << 48;
            zh ^= hh[hi as usize];
            zl ^= hl[hi as usize];
        });

        let a = zh.to_be_bytes();
        let b = zl.to_be_bytes();

        x[0..8].copy_from_slice(&a);
        x[8..16].copy_from_slice(&b);
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        let mlen = m.len();

        let n = mlen / Self::BLOCK_LEN;
        for i in 0..n {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, i * Self::BLOCK_LEN) };
            self.gf_mul(chunk);
        }

        if mlen % Self::BLOCK_LEN != 0 {
            let rem = &m[n * Self::BLOCK_LEN..];
            let rlen = rem.len();

            let mut last_block = [0u8; Self::BLOCK_LEN];
            // Magic: black_box is used to prevent the compiler from using bzero
            std::hint::black_box(last_block.as_mut_ptr());
            last_block[..rlen].copy_from_slice(rem);
            self.gf_mul(&last_block);
        }
    }

    #[inline(always)]
    pub(crate) fn update_4block_for_aes(&mut self, m0: &[u8; 16], m1: &[u8; 16], m2: &[u8; 16], m3: &[u8; 16]) {
        self.gf_mul(m0);
        self.gf_mul(m1);
        self.gf_mul(m2);
        self.gf_mul(m3);
    }

    #[inline(always)]
    pub(crate) fn update_6block_for_aes(&mut self, m0: &[u8; 16], m1: &[u8; 16], m2: &[u8; 16], m3: &[u8; 16], m4: &[u8; 16], m5: &[u8; 16]) {
        self.gf_mul(m0);
        self.gf_mul(m1);
        self.gf_mul(m2);
        self.gf_mul(m3);
        self.gf_mul(m4);
        self.gf_mul(m5);
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        self.buf
    }
}

#[cfg(test)]
macro_rules! ghash_test_case {
    ($name:ty) => {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f,
        ];
        let data0 = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f,
        ];
        let expected = [
            0x8A, 0x49, 0x00, 0xE0, 0x84, 0xE7, 0x10, 0xE6, 0x94, 0xF9, 0x40, 0xF8, 0xC4,
            0xFF, 0x50, 0xFE,
        ];
        // convert expected

        let mut ghash = <$name>::new(&key);
        ghash.update(&data0);
        let tag = ghash.finalize();

        assert_eq!(tag, expected);

        // repeat data 1000 times
        let data1 = data0.to_vec().repeat(1000);
        let expected = [
            179, 21, 154, 241, 63, 177, 77, 42, 227, 157, 34, 36, 102, 184, 65, 233,
        ];
        
        let mut ghash = <$name>::new(&key);
        ghash.update(&data1);
        let tag = ghash.finalize();

        assert_eq!(tag, expected);

        // random
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ];
        let expected = [
            176, 24, 123, 216, 27, 125, 50, 71, 175, 224, 190, 24, 153, 70, 221, 180,
        ];

        let mut ghash = <$name>::new(&key);
        ghash.update(&data0);
        let tag = ghash.finalize();
        assert_eq!(tag, expected);

        let expected = [
            243, 127, 198, 51, 107, 2, 215, 129, 110, 255, 71, 236, 119, 210, 101, 92,
        ];

        let mut ghash = <$name>::new(&key);
        ghash.update(&data1);
        let tag = ghash.finalize();
        assert_eq!(tag, expected);

    };
    () => {
        ghash_test_case!(GHash);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ghash() {
        ghash_test_case!();
    }
}