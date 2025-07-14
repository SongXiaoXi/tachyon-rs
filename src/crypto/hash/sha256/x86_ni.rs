#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [__m128i; 2],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha256 {
    sha256_define_const!();
}

#[unsafe_target_feature("ssse3,sse4.1,sha")]
impl Sha256 {
    #[inline(always)]
    pub fn new() -> Self {
        let mut t = _mm_loadu_si128(super::INITIAL_STATE.as_ptr() as _);
        let mut state1 = _mm_loadu_si128(super::INITIAL_STATE.as_ptr().add(4) as _);
        t = _mm_shuffle_epi32(t, 0xb1);
        state1 = _mm_shuffle_epi32(state1, 0x1b);
        let state0 = _mm_alignr_epi8(t, state1, 8);
        state1 = _mm_blend_epi16(state1, t, 0xf0);

        Self {
            state: [state0, state1],
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
            let block = unsafe { crate::utils::slice_to_array_at::<u8, 64>(data, i) };
            self.process_block_with(block);
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
        std::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha256 = self;
        sha256.update(data);

        let tmp = _mm_shuffle_epi32(sha256.state[0], 0x1b);
        sha256.state[1] = _mm_shuffle_epi32(sha256.state[1], 0xb1);
        sha256.state[0] = _mm_blend_epi16(tmp, sha256.state[1], 0xf0);
        sha256.state[1] = _mm_alignr_epi8(sha256.state[1], tmp, 8);

        debug_assert_eq!(sha256.offset, 0);

        let mut state = [0u32; 8];
        _mm_storeu_si128(state.as_mut_ptr() as _, sha256.state[0]);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as _, sha256.state[1]);
        
        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&state[0].to_be_bytes());
        output[4..8].copy_from_slice(&state[1].to_be_bytes());
        output[8..12].copy_from_slice(&state[2].to_be_bytes());
        output[12..16].copy_from_slice(&state[3].to_be_bytes());
        output[16..20].copy_from_slice(&state[4].to_be_bytes());
        output[20..24].copy_from_slice(&state[5].to_be_bytes());
        output[24..28].copy_from_slice(&state[6].to_be_bytes());
        output[28..32].copy_from_slice(&state[7].to_be_bytes());
        output
    }

    #[inline(always)]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
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
unsafe fn transform(state: &mut [__m128i; 2], block: &[u8; Sha256::BLOCK_LEN]) {
    let mut state0 = state[0];
    let mut state1 = state[1];

    let mut msg0 = _mm_loadu_si128(block.as_ptr().add(0) as _);
    let mut msg1 = _mm_loadu_si128(block.as_ptr().add(16) as _);
    let mut msg2 = _mm_loadu_si128(block.as_ptr().add(32) as _);
    let mut msg3 = _mm_loadu_si128(block.as_ptr().add(48) as _);

    if cfg!(target_endian = "little") {
        let mask = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);
        msg0 = _mm_shuffle_epi8(msg0, mask);
        msg1 = _mm_shuffle_epi8(msg1, mask);
        msg2 = _mm_shuffle_epi8(msg2, mask);
        msg3 = _mm_shuffle_epi8(msg3, mask);
    }

    #[allow(non_snake_case)]
    let K32 = crate::utils::black_box(super::K32.as_ptr());

    // Rounds 0-3
    let mut msg = _mm_add_epi32(msg0, _mm_loadu_si128(K32.add(0) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 4-7
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K32.add(4) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 8-11
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K32.add(8) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 12-15
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K32.add(12) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    let mut tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 16-19
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K32.add(16) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 20-23
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K32.add(20) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 24-27
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K32.add(24) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 28-31
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K32.add(28) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 32-35
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K32.add(32) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 36-39
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K32.add(36) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 40-43
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K32.add(40) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 44-47
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K32.add(44) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 48-51
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K32.add(48) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 52-55
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K32.add(52) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 56-59
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K32.add(56) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 60-63
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K32.add(60) as _));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_srli_si128(msg, 8);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    
    state[0] = _mm_add_epi32(state0, state[0]);
    state[1] = _mm_add_epi32(state1, state[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        if !std::arch::is_x86_feature_detected!("sha") {
            return;
        }
        sha256_test_case!();
    }
}