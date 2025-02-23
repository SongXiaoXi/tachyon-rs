#[derive(Clone, Copy)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    buffer: [u8; 64],
    offset: usize,
}

impl Sha1 {
    pub const BLOCK_LEN: usize = 64;
    pub const DIGEST_LEN: usize = 20;

    const BLOCK_LEN_BITS: u64 = Self::BLOCK_LEN as u64 * 8;
    const MLEN_SIZE: usize = core::mem::size_of::<u64>();
    const MLEN_SIZE_BITS: u64 = Self::MLEN_SIZE as u64 * 8;
    const MAX_PAD_LEN: usize = Self::BLOCK_LEN + Self::MLEN_SIZE as usize;

    #[inline(always)]
    pub fn new() -> Self {
        Self {
            state: [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476,
                0xc3d2e1f0,
            ],
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;

        if self.offset > 0 {
            self.len += self.offset as u64;
            while i < data.len() {
                if self.offset < Self::BLOCK_LEN {
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
            self.process_block_with(&data[i..i + Self::BLOCK_LEN]);
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            self.buffer[..remain].copy_from_slice(&data[i..]);
            self.offset = remain;
        }
    }

    #[inline]
    pub fn finalize(mut self) -> [u8; Self::DIGEST_LEN] {
        let mlen = self.len + self.offset as u64; // in bytes
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
            (mlen + plen + Self::MLEN_SIZE as u64) % Self::BLOCK_LEN as u64,
            0
        );

        let plen = plen as usize;

        let mut padding: [u8; Self::MAX_PAD_LEN] = [0u8; Self::MAX_PAD_LEN];
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        self.update(data);

        debug_assert_eq!(self.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&self.state[0].to_be_bytes());
        output[4..8].copy_from_slice(&self.state[1].to_be_bytes());
        output[8..12].copy_from_slice(&self.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&self.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&self.state[4].to_be_bytes());
        output
    }

    #[inline(always)]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; 64], &[u8; 64]>(&self.buffer) };
        self.process_block_with(block);
    }

    #[inline(always)]
    fn process_block_with(&mut self, block: &[u8]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        for i in 16..80 {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = w[i].rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                60..=79 => (b ^ c ^ d, 0xca62c1d6),
                _ => unreachable!(),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        let mut sha1 = Sha1::new();
        let zero_x64 = [0u8; 0];
        sha1.update(&zero_x64);
        let digest = sha1.finalize();
        assert_eq!(digest, [
            0xda, 0x39, 0xa3, 0xee, 0x5e,
            0x6b, 0x4b, 0x0d, 0x32, 0x55,
            0xbf, 0xef, 0x95, 0x60, 0x18,
            0x90, 0xaf, 0xd8, 0x07, 0x09,
        ]);
        let mut sha1 = Sha1::new();
        sha1.update(b"abc");
        let digest = sha1.finalize();
        assert_eq!(digest, [
            0xa9, 0x99, 0x3e, 0x36, 0x47,
            0x06, 0x81, 0x6a, 0xba, 0x3e,
            0x25, 0x71, 0x78, 0x50, 0xc2,
            0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ]);

        let mut sha1 = Sha1::new();
        sha1.update(b"abcdefghijklmnopqrstuvwxyz");
        let digest = sha1.finalize();
        assert_eq!(digest, [
            0x32, 0xd1, 0x0c, 0x7b, 0x8c,
            0xf9, 0x65, 0x70, 0xca, 0x04,
            0xce, 0x37, 0xf2, 0xa1, 0x9d,
            0x84, 0x24, 0x0d, 0x3a, 0x89,
        ]);
    }
}