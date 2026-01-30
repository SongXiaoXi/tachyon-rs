#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "arm")]
use core::arch::arm::*;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [uint32x4_t; 2],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha256 {
    sha256_define_const!();
    
    #[inline(always)]
    pub fn new() -> Self {
        let state = unsafe {[
            vld1q_u32(super::INITIAL_STATE.as_ptr()),
            vld1q_u32(super::INITIAL_STATE.as_ptr().add(4)),
        ]};
        Self {
            state,
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("neon,sha2")]
impl Sha256 {
    #[inline(always)]
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
            // crate::utils::copy_chunks_u8(self.buffer.as_mut_ptr(), data.as_ptr().add(i), remain);
        }
    }

    #[inline(always)]
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

        let mut state = [0; 8];
        unsafe {
            vst1q_u32(state.as_mut_ptr(), sha256.state[0]);
            vst1q_u32(state.as_mut_ptr().add(4), sha256.state[1]);
        }
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

#[inline]
#[target_feature(enable = "neon,sha2")]
unsafe fn transform(state: &mut [uint32x4_t; 2], block: &[u8; Sha256::BLOCK_LEN]) {
    let mut state0 = state[0];
    let mut state1 = state[1];

    let mut block0 = vld1q_u8(block.as_ptr().add(0));
    let mut block1 = vld1q_u8(block.as_ptr().add(16));
    let mut block2 = vld1q_u8(block.as_ptr().add(32));
    let mut block3 = vld1q_u8(block.as_ptr().add(48));

    if cfg!(target_endian = "little") {
        block0 = vrev32q_u8(block0);
        block1 = vrev32q_u8(block1);
        block2 = vrev32q_u8(block2);
        block3 = vrev32q_u8(block3);
    }

    let mut msg0 = vreinterpretq_u32_u8(block0);
    let mut msg1 = vreinterpretq_u32_u8(block1);
    let mut msg2 = vreinterpretq_u32_u8(block2);
    let mut msg3 = vreinterpretq_u32_u8(block3);

    // #[cfg(target_arch = "aarch64")]
    // let mut round_tmp = vdupq_n_u32(0);

    macro_rules! sha256_round {
        ($state0:expr, $state1:expr, $tmp:expr) => {{
            /*
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!(
                "mov.16b {round_tmp:v}, {state0:v}",
                "sha256h.4s {state0:q}, {state1:q}, {tmp:v}",
                "sha256h2.4s {state1:q}, {round_tmp:q}, {tmp:v}",
                state0 = inout(vreg) $state0,
                state1 = inout(vreg) $state1,
                round_tmp = inout(vreg) round_tmp,
                tmp = in(vreg) $tmp,
                options(nostack, preserves_flags, nomem, pure)
            );
            _ = round_tmp; // Prevent unused variable warning
            ($state0, $state1)
            */
            let s0: uint32x4_t = crate::utils::black_box($state0);
            (vsha256hq_u32($state0, $state1, $tmp), vsha256h2q_u32($state1, s0, $tmp))
        }};
    }

    // Magic: black_box is used to prevent the compiler from using load immediate instructions
    #[allow(non_snake_case)]
    let K32 = crate::utils::black_box(super::K32.as_ptr());

    let mut tmp0 = vaddq_u32(msg0, vld1q_u32(K32.add(0)));

    // Rounds 0-3
    msg0 = vsha256su0q_u32(msg0, msg1);
    let mut tmp1 = vaddq_u32(msg1, vld1q_u32(K32.add(4)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // Rounds 4-7
    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp0 = vaddq_u32(msg2, vld1q_u32(K32.add(0x08)));
    (state0, state1) = sha256_round!(state0, state1, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // Rounds 8-11
    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp1 = vaddq_u32(msg3, vld1q_u32(K32.add(0x0c)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // Rounds 12-15
    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp0 = vaddq_u32(msg0, vld1q_u32(K32.add(0x10)));
    (state0, state1) = sha256_round!(state0, state1, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // Rounds 16-19
    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp1 = vaddq_u32(msg1, vld1q_u32(K32.add(0x14)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // Rounds 20-23
    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp0 = vaddq_u32(msg2, vld1q_u32(K32.add(0x18)));
    (state0, state1) = sha256_round!(state0, state1, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // Rounds 24-27
    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp1 = vaddq_u32(msg3, vld1q_u32(K32.add(0x1c)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // Rounds 28-31
    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp0 = vaddq_u32(msg0, vld1q_u32(K32.add(0x20)));
    (state0, state1) = sha256_round!(state0, state1, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // Rounds 32-35
    msg0 = vsha256su0q_u32(msg0, msg1);
    tmp1 = vaddq_u32(msg1, vld1q_u32(K32.add(0x24)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);

    // Rounds 36-39
    msg1 = vsha256su0q_u32(msg1, msg2);
    tmp0 = vaddq_u32(msg2, vld1q_u32(K32.add(0x28)));
    (state0, state1) = sha256_round!(state0, state1, tmp1);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);

    // Rounds 40-43
    msg2 = vsha256su0q_u32(msg2, msg3);
    tmp1 = vaddq_u32(msg3, vld1q_u32(K32.add(0x2c)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);

    // Rounds 44-47
    msg3 = vsha256su0q_u32(msg3, msg0);
    tmp0 = vaddq_u32(msg0, vld1q_u32(K32.add(0x30)));
    (state0, state1) = sha256_round!(state0, state1, tmp1);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    // Rounds 48-51
    tmp1 = vaddq_u32(msg1, vld1q_u32(K32.add(0x34)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);

    // Rounds 52-55
    tmp0 = vaddq_u32(msg2, vld1q_u32(K32.add(0x38)));
    (state0, state1) = sha256_round!(state0, state1, tmp1);

    // Rounds 56-59
    tmp1 = vaddq_u32(msg3, vld1q_u32(K32.add(0x3c)));
    (state0, state1) = sha256_round!(state0, state1, tmp0);

    // Rounds 60-63
    (state0, state1) = sha256_round!(state0, state1, tmp1);
    
    state[0] = vaddq_u32(state0, state[0]);
    state[1] = vaddq_u32(state1, state[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        #[cfg(target_arch = "aarch64")]
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            return;
        }
        #[cfg(target_arch = "arm")]
        if !std::arch::is_arm_feature_detected!("sha2") {
            return;
        }
        sha256_test_case!();
    }
}