#[cfg(target_arch = "arm")]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use unsafe_target_feature::unsafe_target_feature;

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
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("neon,sha2")]
impl Sha1 {
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        if self.offset > 0 {
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
            self.process_block_with(unsafe { crate::utils::slice_to_array_at(data, i) });
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            // SAFETY: remain is less than BLOCK_LEN
            unsafe {
                self.buffer.get_unchecked_mut(..remain).copy_from_slice(&data[i..]);
            }
            self.offset = remain;
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
        debug_assert!(plen > 1);
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
        let mut abcd = vld1q_u32(self.state.as_ptr());
        let abcd_saved = abcd;
        let mut e0 = self.state[4];

        let mut msg0 = vld1q_u32(block.as_ptr() as *const u32);
        let mut msg1 = vld1q_u32(block.as_ptr().add(16) as *const u32);
        let mut msg2 = vld1q_u32(block.as_ptr().add(32) as *const u32);
        let mut msg3 = vld1q_u32(block.as_ptr().add(48) as *const u32);

        // if little endian
        if cfg!(target_endian = "little") {
            msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
            msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
            msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
            msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));
        }

        let mut tmp0 = vaddq_u32(msg0, vdupq_n_u32(0x5a827999));
        let mut tmp1 = vaddq_u32(msg1, vdupq_n_u32(0x5a827999));

        // Rounds 0-3
        let mut e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg2, vdupq_n_u32(0x5a827999));
        msg0 = vsha1su0q_u32(msg0, msg1, msg2);

        // Rounds 4-7
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg3, vdupq_n_u32(0x5a827999));
        msg0 = vsha1su1q_u32(msg0, msg3);
        msg1 = vsha1su0q_u32(msg1, msg2, msg3);

        // Rounds 8-11
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg0, vdupq_n_u32(0x5a827999));
        msg1 = vsha1su1q_u32(msg1, msg0);
        msg2 = vsha1su0q_u32(msg2, msg3, msg0);

        // Rounds 12-15
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg1, vdupq_n_u32(0x6ed9eba1));
        msg2 = vsha1su1q_u32(msg2, msg1);
        msg3 = vsha1su0q_u32(msg3, msg0, msg1);

        // Rounds 16-19
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1cq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg2, vdupq_n_u32(0x6ed9eba1));
        msg3 = vsha1su1q_u32(msg3, msg2);
        msg0 = vsha1su0q_u32(msg0, msg1, msg2);

        // Rounds 20-23
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg3, vdupq_n_u32(0x6ed9eba1));
        msg0 = vsha1su1q_u32(msg0, msg3);
        msg1 = vsha1su0q_u32(msg1, msg2, msg3);

        // Rounds 24-27
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg0, vdupq_n_u32(0x6ed9eba1));
        msg1 = vsha1su1q_u32(msg1, msg0);
        msg2 = vsha1su0q_u32(msg2, msg3, msg0);

        // Rounds 28-31
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg1, vdupq_n_u32(0x6ed9eba1));
        msg2 = vsha1su1q_u32(msg2, msg1);
        msg3 = vsha1su0q_u32(msg3, msg0, msg1);

        // Rounds 32-35
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg2, vdupq_n_u32(0x8F1BBCDC));
        msg3 = vsha1su1q_u32(msg3, msg2);
        msg0 = vsha1su0q_u32(msg0, msg1, msg2);

        // Rounds 36-39
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg3, vdupq_n_u32(0x8F1BBCDC));
        msg0 = vsha1su1q_u32(msg0, msg3);
        msg1 = vsha1su0q_u32(msg1, msg2, msg3);

        // Rounds 40-43
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg0, vdupq_n_u32(0x8F1BBCDC));
        msg1 = vsha1su1q_u32(msg1, msg0);
        msg2 = vsha1su0q_u32(msg2, msg3, msg0);

        // Rounds 44-47
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg1, vdupq_n_u32(0x8F1BBCDC));
        msg2 = vsha1su1q_u32(msg2, msg1);
        msg3 = vsha1su0q_u32(msg3, msg0, msg1);

        // Rounds 48-51
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg2, vdupq_n_u32(0x8F1BBCDC));
        msg3 = vsha1su1q_u32(msg3, msg2);
        msg0 = vsha1su0q_u32(msg0, msg1, msg2);

        // Rounds 52-55
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg3, vdupq_n_u32(0xCA62C1D6));
        msg0 = vsha1su1q_u32(msg0, msg3);
        msg1 = vsha1su0q_u32(msg1, msg2, msg3);

        // Rounds 56-59
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1mq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg0, vdupq_n_u32(0xCA62C1D6));
        msg1 = vsha1su1q_u32(msg1, msg0);
        msg2 = vsha1su0q_u32(msg2, msg3, msg0);

        // Rounds 60-63
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg1, vdupq_n_u32(0xCA62C1D6));
        msg2 = vsha1su1q_u32(msg2, msg1);
        msg3 = vsha1su0q_u32(msg3, msg0, msg1);

        // Rounds 64-67
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, tmp0);
        tmp0 = vaddq_u32(msg2, vdupq_n_u32(0xCA62C1D6));
        msg3 = vsha1su1q_u32(msg3, msg2);

        // Rounds 68-71
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, tmp1);
        tmp1 = vaddq_u32(msg3, vdupq_n_u32(0xCA62C1D6));

        // Rounds 72-75
        e1 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e0, tmp0);

        // Rounds 76-79
        e0 = vsha1h_u32(vgetq_lane_u32(abcd, 0));
        abcd = vsha1pq_u32(abcd, e1, tmp1);

        // Combine state
        vst1q_u32(self.state.as_mut_ptr(), vaddq_u32(abcd, abcd_saved));
        self.state[4] = self.state[4].wrapping_add(e0);
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

    #[cfg(target_arch = "arm")]
    use std::arch::is_arm_feature_detected as is_target_feature_detected;
    #[cfg(target_arch = "aarch64")]
    use std::arch::is_aarch64_feature_detected as is_target_feature_detected;

    #[test]
    fn test_sha1() {
        if !is_target_feature_detected!("neon") || !is_target_feature_detected!("sha2") {
            return;
        }
        sha1_test_case!();
    }
}