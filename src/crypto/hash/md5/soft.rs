
#[derive(Clone, Copy)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    len: u64,
    offset: usize,
}

impl Md5 {
    pub const BLOCK_LEN: usize = 64;
    pub const DIGEST_LEN: usize = 16;

    const BLOCK_LEN_BITS: u64 = Self::BLOCK_LEN as u64 * 8;
    const MLEN_SIZE: usize = core::mem::size_of::<u64>();
    const MLEN_SIZE_BITS: u64 = Self::MLEN_SIZE as u64 * 8;
    const MAX_PAD_LEN: usize = Self::BLOCK_LEN + Self::MLEN_SIZE as usize;

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            buffer: [0; Self::BLOCK_LEN],
            len: 0,
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
                    self.process_block();
                    self.offset = 0;
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
        let mlen = self.len + self.offset as u64;
        let mlen_bits = mlen * 8;

        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
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

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_le_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut md5 = self;
        md5.update(data);

        debug_assert_eq!(md5.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&md5.state[0].to_le_bytes());
        output[4..8].copy_from_slice(&md5.state[1].to_le_bytes());
        output[8..12].copy_from_slice(&md5.state[2].to_le_bytes());
        output[12..16].copy_from_slice(&md5.state[3].to_le_bytes());
        output
    }

    #[inline(never)]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; 64], &[u8; 64]>(&self.buffer) };
        self.process_block_with(block);
    }

    #[inline(always)]
    fn process_block_with(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 16];
        crate::const_loop!(i, 0, 16, {
            w[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        });

        #[inline(always)]
        fn merge_bits(a: u32, b: u32, mask: u32) -> u32 {
            (a & !mask).wrapping_add(b & mask)
        }

        let k64 = crate::utils::black_box(super::K64.as_ptr());

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        crate::const_loop!(i, 0, 4, {
            a = a.wrapping_add(merge_bits(d, c, b)).wrapping_add(w[4 * i + 0]).wrapping_add(unsafe { *k64.add(4 * i + 0) }).rotate_left(7).wrapping_add(b);
            d = d.wrapping_add(merge_bits(c, b, a)).wrapping_add(w[4 * i + 1]).wrapping_add(unsafe { *k64.add(4 * i + 1) }).rotate_left(12).wrapping_add(a);
            c = c.wrapping_add(merge_bits(b, a, d)).wrapping_add(w[4 * i + 2]).wrapping_add(unsafe { *k64.add(4 * i + 2) }).rotate_left(17).wrapping_add(d);
            b = b.wrapping_add(merge_bits(a, d, c)).wrapping_add(w[4 * i + 3]).wrapping_add(unsafe { *k64.add(4 * i + 3) }).rotate_left(22).wrapping_add(c);
        });

        crate::const_loop!(i, 4, 4, {
            a = a.wrapping_add(merge_bits(c, b, d)).wrapping_add(w[(5 * (4 * (i - 4) + 0) + 1) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 0) }).rotate_left(5).wrapping_add(b);
            d = d.wrapping_add(merge_bits(b, a, c)).wrapping_add(w[(5 * (4 * (i - 4) + 1) + 1) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 1) }).rotate_left(9).wrapping_add(a);
            c = c.wrapping_add(merge_bits(a, d, b)).wrapping_add(w[(5 * (4 * (i - 4) + 2) + 1) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 2) }).rotate_left(14).wrapping_add(d);
            b = b.wrapping_add(merge_bits(d, c, a)).wrapping_add(w[(5 * (4 * (i - 4) + 3) + 1) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 3) }).rotate_left(20).wrapping_add(c);
        });

        crate::const_loop!(i, 8, 4, {
            a = a.wrapping_add(b ^ c ^ d).wrapping_add(w[(3 * (4 * (i - 8) + 0) + 5) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 0) }).rotate_left(4).wrapping_add(b);
            d = d.wrapping_add(a ^ b ^ c).wrapping_add(w[(3 * (4 * (i - 8) + 1) + 5) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 1) }).rotate_left(11).wrapping_add(a);
            c = c.wrapping_add(d ^ a ^ b).wrapping_add(w[(3 * (4 * (i - 8) + 2) + 5) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 2) }).rotate_left(16).wrapping_add(d);
            b = b.wrapping_add(c ^ d ^ a).wrapping_add(w[(3 * (4 * (i - 8) + 3) + 5) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 3) }).rotate_left(23).wrapping_add(c);
        });

        crate::const_loop!(i, 12, 4, {
            a = a.wrapping_add(c ^ (b | !d)).wrapping_add(w[(7 * (4 * (i - 12) + 0)) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 0) }).rotate_left(6).wrapping_add(b);
            d = d.wrapping_add(b ^ (a | !c)).wrapping_add(w[(7 * (4 * (i - 12) + 1)) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 1) }).rotate_left(10).wrapping_add(a);
            c = c.wrapping_add(a ^ (d | !b)).wrapping_add(w[(7 * (4 * (i - 12) + 2)) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 2) }).rotate_left(15).wrapping_add(d);
            b = b.wrapping_add(d ^ (c | !a)).wrapping_add(w[(7 * (4 * (i - 12) + 3)) % 16]).wrapping_add(unsafe { *k64.add(4 * i + 3) }).rotate_left(21).wrapping_add(c);
        });

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    #[inline(always)]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut md5 = Self::new();
        md5.update(data.as_ref());
        md5.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        assert_eq!(
            Md5::oneshot(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
            ],
        );
        assert_eq!(
            Md5::oneshot(b"hello world"),
            [
                0x5e, 0xb6, 0x3b, 0xbb, 0xe0, 0x1e, 0xee, 0xd0,
                0x93, 0xcb, 0x22, 0xbb, 0x8f, 0x5a, 0xcd, 0xc3,
            ],
        );
        assert_eq!(
            Md5::oneshot(b"1234567890123456789012345678901234567890"),
            [
                0xf5, 0xbf, 0x3e, 0x98, 0x44, 0x32, 0xae, 0x6f,
                0x9f, 0x98, 0x84, 0x09, 0x51, 0xe5, 0xce, 0xf3,
            ],
        );
        let random_data = (0..1000).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
        for _ in 0..100 {
            let length = (rand::random::<u32>() % 1000) as usize;
            let data = &random_data[..length];
            assert_eq!(
                Md5::oneshot(data),
                md5::compute(data).0,
                "Failed for data length: {}",
                length
            );
        }
    }
}