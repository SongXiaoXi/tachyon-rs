#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    buffer: [u8; 64],
    offset: usize,
}

impl Sha1 {
    sha1_define_const!();

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("sse2,ssse3,sha")]
impl Sha1 {
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
    pub fn finalize(self) -> [u8; 20] {
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
        std::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha1 = self;
        sha1.update(data);

        debug_assert_eq!(sha1.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&sha1.state[0].to_be_bytes());
        output[4..8].copy_from_slice(&sha1.state[1].to_be_bytes());
        output[8..12].copy_from_slice(&sha1.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&sha1.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&sha1.state[4].to_be_bytes());
        output
    }

    #[inline]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; 64], &[u8; 64]>(&self.buffer) };
        self.process_block_with(block);
    }

    #[inline]
    pub(crate) fn process_block_with(&mut self, block: &[u8; 64]) {
        let mut abcd = _mm_loadu_si128(self.state.as_ptr() as _);
        abcd = _mm_shuffle_epi32(abcd, 0x1B);
        let abcd_saved = abcd;
        let mut e0 = _mm_set_epi32(self.state[4] as _, 0, 0, 0);
        let e0_saved = e0;
        let mask = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);

        // Rounds 0-3
        let mut msg0 = _mm_loadu_si128(block.as_ptr() as _);
        msg0 = _mm_shuffle_epi8(msg0, mask);
        e0 = _mm_add_epi32(e0, msg0);
        let mut e1 = crate::utils::black_box(abcd);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);

        // Rounds 4-7
        let mut msg1 = _mm_loadu_si128(block.as_ptr().add(16) as _);
        msg1 = _mm_shuffle_epi8(msg1, mask);
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = crate::utils::black_box(abcd);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);

        // Rounds 8-11
        let mut msg2 = _mm_loadu_si128(block.as_ptr().add(32) as _);
        msg2 = _mm_shuffle_epi8(msg2, mask);
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = crate::utils::black_box(abcd);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 12-15
        let mut msg3 = _mm_loadu_si128(block.as_ptr().add(48) as _);
        msg3 = _mm_shuffle_epi8(msg3, mask);
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = crate::utils::black_box(abcd);
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 16-19
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = crate::utils::black_box(abcd);
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 20-23
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = crate::utils::black_box(abcd);
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 24-27
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = crate::utils::black_box(abcd);
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 28-31
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = crate::utils::black_box(abcd);
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 32-35
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = crate::utils::black_box(abcd);
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 1);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 36-39
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = crate::utils::black_box(abcd);
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 40-43
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = crate::utils::black_box(abcd);
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 44-47
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = crate::utils::black_box(abcd);
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 48-51
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = crate::utils::black_box(abcd);
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 52-55
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = crate::utils::black_box(abcd);
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 2);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 56-59
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = crate::utils::black_box(abcd);
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 2);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 60-63
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = crate::utils::black_box(abcd);
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 64-67
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = crate::utils::black_box(abcd);
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 68-71
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = crate::utils::black_box(abcd);
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 72-75
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = crate::utils::black_box(abcd);
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32(abcd, e0, 3);

        // Rounds 76-79
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = crate::utils::black_box(abcd);
        abcd = _mm_sha1rnds4_epu32(abcd, e1, 3);

        // Combine state
        let e0 = _mm_sha1nexte_epu32(e0, e0_saved);
        abcd = _mm_add_epi32(abcd, abcd_saved);
        
        abcd = _mm_shuffle_epi32(abcd, 0x1B);
        _mm_storeu_si128(self.state.as_mut_ptr() as _, abcd);

        self.state[4] = _mm_extract_epi32(e0, 3) as _;

    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 20] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use std::arch::is_x86_feature_detected as is_target_feature_detected;

    #[test]
    fn test_sha1() {
        if !(is_target_feature_detected!("sha") && is_target_feature_detected!("ssse3") && is_target_feature_detected!("sse2")) {
            eprintln!("sha feature is not detected on this machine.");
            return;
        }
        sha1_test_case!();
    }
}