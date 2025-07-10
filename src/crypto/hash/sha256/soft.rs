
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

macro_rules! sha256_define_const {
    () => {
        pub const BLOCK_LEN: usize = 64;
        pub const DIGEST_LEN: usize = 32;

        const BLOCK_LEN_BITS: u64 = Self::BLOCK_LEN as u64 * 8;
        const MLEN_SIZE: usize = core::mem::size_of::<u64>();
        const MLEN_SIZE_BITS: u64 = Self::MLEN_SIZE as u64 * 8;
        const MAX_PAD_LEN: usize = Self::BLOCK_LEN + Self::MLEN_SIZE as usize;
    };
}

impl Sha256 {
    sha256_define_const!();
    
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
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
            self.buffer[..remain].copy_from_slice(&data[i..]);
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; 32] {
        let mlen = self.len + self.offset as u64; // in bytes
        let mlen_bits = mlen * 8; // in bits

        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert_eq!(
            (mlen + plen + Self::MLEN_SIZE as u64) % Self::BLOCK_LEN as u64,
            0
        );

        let plen = plen as usize;

        let mut padding: [u8; Self::MAX_PAD_LEN] = [0u8; Self::MAX_PAD_LEN];
        // Magic: black_box is used to prevent the compiler from using bzero
        core::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha256 = self;
        sha256.update(data);

        debug_assert_eq!(sha256.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&sha256.state[0].to_be_bytes());
        output[4..8].copy_from_slice(&sha256.state[1].to_be_bytes());
        output[8..12].copy_from_slice(&sha256.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&sha256.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&sha256.state[4].to_be_bytes());
        output[20..24].copy_from_slice(&sha256.state[5].to_be_bytes());
        output[24..28].copy_from_slice(&sha256.state[6].to_be_bytes());
        output[28..32].copy_from_slice(&sha256.state[7].to_be_bytes());
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
    fn process_block_with(&mut self, block: &[u8; 64]) {
        transform(&mut self.state, block);
    }
}

#[inline(always)]
fn transform(state: &mut [u32; 8], block: &[u8; Sha256::BLOCK_LEN]) {
    use crate::utils::merge_bits;
    #[allow(non_snake_case)]
    #[inline(always)]
    fn CH(x: u32, y: u32, z: u32) -> u32 {
        merge_bits(z, y, x)
    }

    #[allow(non_snake_case)]
    #[inline(always)]
    fn MAJ(x: u32, y: u32, z: u32) -> u32 {
        // (x & y) ^ (x & z) ^ (y & z)
        (x & (y ^ z)) | (y & z)
    }

    #[allow(non_snake_case)]
    #[inline(always)]
    fn EP0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    
    #[allow(non_snake_case)]
    #[inline(always)]
    fn EP1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[allow(non_snake_case)]
    #[inline(always)]
    fn SIG0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[allow(non_snake_case)]
    #[inline(always)]
    fn SIG1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Sha256::BLOCK_LEN);

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    #[allow(non_snake_case)]
    let K32 = crate::utils::black_box(super::K32.as_ptr());

    let mut w = [0u32; 16];
    #[crate::loop_unroll(i, 0, 16)]
    fn loop_unroll() {
        w[i] = u32::from_be_bytes([
            block[i * 4 + 0],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);

        let t1 = h
            .wrapping_add(EP1(e))
            .wrapping_add(CH(e, f, g))
            .wrapping_add(unsafe { *K32.add(i) })
            .wrapping_add(w[i]);
        let t2 = EP0(a).wrapping_add(MAJ(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    #[crate::loop_unroll(i, 16, 48)]
    fn loop_unroll() {
        w[i % 16] = SIG1(w[(i - 2) % 16])
            .wrapping_add(w[(i - 7) % 16])
            .wrapping_add(SIG0(w[(i - 15) % 16]))
            .wrapping_add(w[(i - 16) % 16]);
        let t1 = h
            .wrapping_add(EP1(e))
            .wrapping_add(CH(e, f, g))
            .wrapping_add(unsafe { *K32.add(i) })
            .wrapping_add(w[i % 16]);
        let t2 = EP0(a).wrapping_add(MAJ(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
macro_rules! sha256_test_case {
    ($name:ty) => {
        assert_eq!(
            <$name>::oneshot(&[]),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
            ]
        );

        assert_eq!(
            <$name>::oneshot(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(
            <$name>::oneshot(b"abcdefghijklmnopqrstuvwxyz"),
            [
                0x71, 0xc4, 0x80, 0xdf, 0x93, 0xd6, 0xae, 0x2f,
                0x1e, 0xfa, 0xd1, 0x44, 0x7c, 0x66, 0xc9, 0x52,
                0x5e, 0x31, 0x62, 0x18, 0xcf, 0x51, 0xfc, 0x8d,
                0x9e, 0xd8, 0x32, 0xf2, 0xda, 0xf1, 0x8b, 0x73,
            ]
        );
        let random_data = (0..1000).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        for _ in 0..100 {
            let length = (rand::random::<u32>() % 1000) as usize;
            let data = &random_data[..length];
            let expected = ring::digest::digest(
                &ring::digest::SHA256,
                &data,
            );
            assert_eq!(
                <$name>::oneshot(data),
                expected.as_ref(),
            );
        }
        let expected = ring::digest::digest(
            &ring::digest::SHA256,
            &random_data,
        );
        assert_eq!(
            <$name>::oneshot(&random_data),
            expected.as_ref(),
        );
    };
    () => {
        sha256_test_case!(Sha256);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        sha256_test_case!();
    }
}