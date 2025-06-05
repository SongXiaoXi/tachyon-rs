#[derive(Clone, Copy)]
pub struct Sha512 {
    state: [u64; 8],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

macro_rules! sha512_define_const {
    () => {
        pub const BLOCK_LEN: usize = 128;
        pub const DIGEST_LEN: usize = 64;
    
        const BLOCK_LEN_BITS: u128 = Self::BLOCK_LEN as u128 * 8;
        const MLEN_SIZE: usize = core::mem::size_of::<u128>();
        const MLEN_SIZE_BITS: u128 = Self::MLEN_SIZE as u128 * 8;
        const MAX_PAD_LEN: usize = Self::BLOCK_LEN + Self::MLEN_SIZE as usize;
    };
}

impl Sha512 {
    sha512_define_const!();

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 128],
            offset: 0,
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;

        if self.offset > 0 {
            while i < data.len() {
                if self.offset < Self::BLOCK_LEN {
                    unsafe { crate::utils::assume(i < data.len()) };
                    self.buffer[self.offset] = data[i];
                    self.offset += 1;
                    i += 1;
                }
                if self.offset == Self::BLOCK_LEN {
                    self.offset = 0;
                    self.process_block();
                    self.len += Self::BLOCK_LEN as u64;
                    break;
                }
            }
        }
        while i + Self::BLOCK_LEN <= data.len() {
            self.process_block_with(unsafe { crate::utils::slice_to_array_at(data, i) });
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            self.offset = remain;
            // SAFETY: remain is less than BLOCK_LEN
            unsafe {
                self.buffer.get_unchecked_mut(..remain).copy_from_slice(&data[i..]);
            }
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        let mlen = self.len as u128 + self.offset as u128; // in bytes
        let mlen_bits = mlen * 8; // in bits

        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert!(plen > 1);
        debug_assert_eq!(
            (mlen + plen + Self::MLEN_SIZE as u128) % Self::BLOCK_LEN as u128,
            0
        );

        let plen = plen as usize;

        let mut padding: [u8; Self::MAX_PAD_LEN] = [0u8; Self::MAX_PAD_LEN];
        // Magic: black_box is used to prevent the compiler from using bzero
        std::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha512 = self;
        sha512.update(data);

        debug_assert_eq!(sha512.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..8].copy_from_slice(&sha512.state[0].to_be_bytes());
        output[8..16].copy_from_slice(&sha512.state[1].to_be_bytes());
        output[16..24].copy_from_slice(&sha512.state[2].to_be_bytes());
        output[24..32].copy_from_slice(&sha512.state[3].to_be_bytes());
        output[32..40].copy_from_slice(&sha512.state[4].to_be_bytes());
        output[40..48].copy_from_slice(&sha512.state[5].to_be_bytes());
        output[48..56].copy_from_slice(&sha512.state[6].to_be_bytes());
        output[56..64].copy_from_slice(&sha512.state[7].to_be_bytes());
        output
    }

    #[inline(always)]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline(always)]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; Self::BLOCK_LEN], &[u8; Self::BLOCK_LEN]>(&self.buffer) };
        self.process_block_with(block);
    }

    #[inline(always)]
    fn process_block_with(&mut self, block: &[u8; Self::BLOCK_LEN]) {
        let mut w = [0u64; 80];

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        static _K: [u64; 80] = super::K;
        #[allow(non_snake_case)]
        let mut K = _K.as_ptr();
        // Magic: black_box is used to prevent the compiler from using load immediate instructions
        std::hint::black_box(&mut K);

        macro_rules! sha512_round {
            ($i:expr) => {
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let ch = (e & f) ^ ((!e) & g);
                let t2 = s0.wrapping_add(maj);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(unsafe { *K.add($i) })
                    .wrapping_add(w[$i]);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            };
        }

        crate::const_loop!(i, 0, 16, {
            w[i] = u64::from_be_bytes(unsafe { *crate::utils::slice_to_array_at(block, i * 8) });
            sha512_round!(i);
        });

        crate::const_loop!(i, 16, 64, {
            let s0 = w[i - 15].rotate_right(1)
                ^ w[i - 15].rotate_right(8)
                ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19)
                ^ w[i - 2].rotate_right(61)
                ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);

            sha512_round!(i);
        });

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

#[cfg(test)]
macro_rules! sha512_test_case {
    ($name:ty) => {
        let mut sha512 = <$name>::new();
        let zero = [0u8; 0];
        sha512.update(&zero);
        let digit = sha512.finalize();
        assert_eq!(
            digit,
            [
                0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
            ]
        );
        let mut sha512 = <$name>::new();
        sha512.update(b"abc");
        let digit = sha512.finalize();
        assert_eq!(
            digit,
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
                0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
                0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
                0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
                0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
                0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
                0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
            ]
        );
        let mut sha512 = <$name>::new();
        sha512.update(b"abcdefghijklmnopqrstuvwxyz");
        let digit = sha512.finalize();
        assert_eq!(
            digit,
            [
                0x4d, 0xbf, 0xf8, 0x6c, 0xc2, 0xca, 0x1b, 0xae,
                0x1e, 0x16, 0x46, 0x8a, 0x05, 0xcb, 0x98, 0x81,
                0xc9, 0x7f, 0x17, 0x53, 0xbc, 0xe3, 0x61, 0x90,
                0x34, 0x89, 0x8f, 0xaa, 0x1a, 0xab, 0xe4, 0x29,
                0x95, 0x5a, 0x1b, 0xf8, 0xec, 0x48, 0x3d, 0x74,
                0x21, 0xfe, 0x3c, 0x16, 0x46, 0x61, 0x3a, 0x59,
                0xed, 0x54, 0x41, 0xfb, 0x0f, 0x32, 0x13, 0x89,
                0xf7, 0x7f, 0x48, 0xa8, 0x79, 0xc7, 0xb1, 0xf1,
            ]
        );
    };
    () => {
        sha512_test_case!(Sha512);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha512() {
        sha512_test_case!();
    }
}