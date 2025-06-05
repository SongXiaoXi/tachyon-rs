#[cfg(target_arch = "arm")]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha512 {
    state: [u64; 8],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha512 {
    sha512_define_const!();

    #[inline]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 128],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("neon,sha3")]
impl Sha512 {
    #[inline]
    pub fn finalize(self) -> [u8; 64] {
        let mlen = self.len as u128 + self.offset as u128;
        let mlen_bits = mlen * 8;

        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
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

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 64] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
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
            let block = unsafe { crate::utils::slice_to_array_at::<_, {Self::BLOCK_LEN}>(data, i) };
            process_block_with!(self.state, block);
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
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; Self::BLOCK_LEN], &[u8; Self::BLOCK_LEN]>(&self.buffer) };
        process_block_with!(self.state, block);
    }
}

#[macro_use]
mod macros {
macro_rules! process_block_with {
    ($state:expr, $block:expr) => {
        {
            let block = $block;

            let mut ab = vld1q_u64(($state).as_ptr().add(0));
            let mut cd = vld1q_u64(($state).as_ptr().add(2));
            let mut ef = vld1q_u64(($state).as_ptr().add(4));
            let mut gh = vld1q_u64(($state).as_ptr().add(6));

            let ab_orig = ab;
            let cd_orig = cd;
            let ef_orig = ef;
            let gh_orig = gh;

            let mut s0 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(0 * 16)));
            let mut s1 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(1 * 16)));
            let mut s2 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(2 * 16)));
            let mut s3 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(3 * 16)));
            let mut s4 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(4 * 16)));
            let mut s5 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(5 * 16)));
            let mut s6 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(6 * 16)));
            let mut s7 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(7 * 16)));

            if cfg!(target_endian = "little") {
                s0 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s0)));
                s1 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s1)));
                s2 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s2)));
                s3 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s3)));
                s4 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s4)));
                s5 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s5)));
                s6 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s6)));
                s7 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s7)));
            }

            #[allow(non_snake_case)]
            let mut K = super::K.as_ptr();
            // Magic: black_box is used to prevent the compiler from using load immediate instructions
            std::hint::black_box(&mut K);

            // Rounds 0, 1
            let mut initial_sum = vaddq_u64(s0, vld1q_u64(K.add(0)));
            let mut sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
            let mut intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
            gh = vsha512h2q_u64(intermed, cd, ab);
            cd = vaddq_u64(cd, intermed);

            // Rounds 2, 3
            initial_sum = vaddq_u64(s1, vld1q_u64(K.add(2)));
            sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
            intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
            ef = vsha512h2q_u64(intermed, ab, gh);
            ab = vaddq_u64(ab, intermed);

            // Rounds 4, 5
            initial_sum = vaddq_u64(s2, vld1q_u64(K.add(4)));
            sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
            intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
            cd = vsha512h2q_u64(intermed, gh, ef);
            gh = vaddq_u64(gh, intermed);

            // Rounds 6, 7
            initial_sum = vaddq_u64(s3, vld1q_u64(K.add(6)));
            sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
            intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
            ab = vsha512h2q_u64(intermed, ef, cd);
            ef = vaddq_u64(ef, intermed);

            // Rounds 8, 9
            initial_sum = vaddq_u64(s4, vld1q_u64(K.add(8)));
            sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
            intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
            gh = vsha512h2q_u64(intermed, cd, ab);
            cd = vaddq_u64(cd, intermed);

            // Rounds 10, 11
            initial_sum = vaddq_u64(s5, vld1q_u64(K.add(10)));
            sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
            intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
            ef = vsha512h2q_u64(intermed, ab, gh);
            ab = vaddq_u64(ab, intermed);

            // Rounds 12, 13
            initial_sum = vaddq_u64(s6, vld1q_u64(K.add(12)));
            sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
            intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
            cd = vsha512h2q_u64(intermed, gh, ef);
            gh = vaddq_u64(gh, intermed);

            // Rounds 14, 15
            initial_sum = vaddq_u64(s7, vld1q_u64(K.add(14)));
            sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
            intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
            ab = vsha512h2q_u64(intermed, ef, cd);
            ef = vaddq_u64(ef, intermed);

            crate::const_loop!(t, 16, 4, 16, {
                // Rounds t + 0, t + 1
                s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
                initial_sum = vaddq_u64(s0, vld1q_u64(K.add(t)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
                intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
                gh = vsha512h2q_u64(intermed, cd, ab);
                cd = vaddq_u64(cd, intermed);

                // Rounds t + 2, t + 3
                s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
                initial_sum = vaddq_u64(s1, vld1q_u64(K.add(t + 2)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
                intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
                ef = vsha512h2q_u64(intermed, ab, gh);
                ab = vaddq_u64(ab, intermed);

                // Rounds t + 4, t + 5
                s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
                initial_sum = vaddq_u64(s2, vld1q_u64(K.add(t + 4)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
                intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
                cd = vsha512h2q_u64(intermed, gh, ef);
                gh = vaddq_u64(gh, intermed);

                // Rounds t + 6, t + 7
                s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
                initial_sum = vaddq_u64(s3, vld1q_u64(K.add(t + 6)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
                intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
                ab = vsha512h2q_u64(intermed, ef, cd);
                ef = vaddq_u64(ef, intermed);

                // Rounds t + 8, t + 9
                s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
                initial_sum = vaddq_u64(s4, vld1q_u64(K.add(t + 8)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
                intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
                gh = vsha512h2q_u64(intermed, cd, ab);
                cd = vaddq_u64(cd, intermed);

                // Rounds t + 10, t + 11
                s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
                initial_sum = vaddq_u64(s5, vld1q_u64(K.add(t + 10)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
                intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
                ef = vsha512h2q_u64(intermed, ab, gh);
                ab = vaddq_u64(ab, intermed);

                // Rounds t + 12, t + 13
                s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
                initial_sum = vaddq_u64(s6, vld1q_u64(K.add(t + 12)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
                intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
                cd = vsha512h2q_u64(intermed, gh, ef);
                gh = vaddq_u64(gh, intermed);

                // Rounds t + 14, t + 15
                s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
                initial_sum = vaddq_u64(s7, vld1q_u64(K.add(t + 14)));
                sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
                intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
                ab = vsha512h2q_u64(intermed, ef, cd);
                ef = vaddq_u64(ef, intermed);
            });

            ab = vaddq_u64(ab, ab_orig);
            cd = vaddq_u64(cd, cd_orig);
            ef = vaddq_u64(ef, ef_orig);
            gh = vaddq_u64(gh, gh_orig);

            vst1q_u64(($state).as_mut_ptr().add(0), ab);
            vst1q_u64(($state).as_mut_ptr().add(2), cd);
            vst1q_u64(($state).as_mut_ptr().add(4), ef);
            vst1q_u64(($state).as_mut_ptr().add(6), gh);
        }
    };
}
}

use process_block_with;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha512() {
        if std::arch::is_aarch64_feature_detected!("neon") && std::arch::is_aarch64_feature_detected!("sha3") {
            sha512_test_case!();
        }
    }
}