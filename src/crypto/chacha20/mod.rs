pub(crate) const PARALLEL_BLOCKS: usize = 4;

macro_rules! impl_chacha20_for_target {
    ($name:tt, $key_len:literal, $block_len:literal, $nonce_len:literal, $counter_len:literal$(, $feature:literal)?) => {
#[derive(Clone, Copy)]
pub struct $name {
    pub(crate) initial_state: [u32; 16],
}

$(#[unsafe_target_feature::unsafe_target_feature($feature)])?
impl $name {
    pub const KEY_LEN: usize = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 12;
    pub const COUNTER_LEN: usize = 4;

    const STATE_LEN: usize = 16; // len in doubleword (32-bits)

    //
    // sigma constant b"expand 16-byte k" in little-endian encoding
    // const K16: [u32; 4] = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];

    // sigma constant b"expand 32-byte k" in little-endian encoding
    const K32: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    #[inline(always)]
    pub fn new(key: [u8; $key_len]) -> Self {
        let mut initial_state = [0u32; Self::STATE_LEN];

        // The ChaCha20 state is initialized as follows:
        initial_state[0] = Self::K32[0];
        initial_state[1] = Self::K32[1];
        initial_state[2] = Self::K32[2];
        initial_state[3] = Self::K32[3];

        // A 256-bit key (32 Bytes)
        initial_state[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        initial_state[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        initial_state[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        initial_state[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        initial_state[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        initial_state[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        initial_state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        initial_state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        Self { initial_state }
    }
    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        let key: &[u8; Self::KEY_LEN] = unsafe {
            crate::utils::slice_to_array(key)
        };
        Self::new(*key)
    }

    #[inline(always)]
    pub(crate) fn block_op(initial_state: &mut [u32; 16], keystream: &mut [u8; $block_len]) {
        let mut state = *initial_state;
        // 20 rounds
        diagonal_rounds(&mut state);
        add_si512(&mut state, initial_state);

        keystream[0..4].copy_from_slice(&state[0].to_le_bytes());
        keystream[4..8].copy_from_slice(&state[1].to_le_bytes());
        keystream[8..12].copy_from_slice(&state[2].to_le_bytes());
        keystream[12..16].copy_from_slice(&state[3].to_le_bytes());
        keystream[16..20].copy_from_slice(&state[4].to_le_bytes());
        keystream[20..24].copy_from_slice(&state[5].to_le_bytes());
        keystream[24..28].copy_from_slice(&state[6].to_le_bytes());
        keystream[28..32].copy_from_slice(&state[7].to_le_bytes());
        keystream[32..36].copy_from_slice(&state[8].to_le_bytes());
        keystream[36..40].copy_from_slice(&state[9].to_le_bytes());
        keystream[40..44].copy_from_slice(&state[10].to_le_bytes());
        keystream[44..48].copy_from_slice(&state[11].to_le_bytes());
        keystream[48..52].copy_from_slice(&state[12].to_le_bytes());
        keystream[52..56].copy_from_slice(&state[13].to_le_bytes());
        keystream[56..60].copy_from_slice(&state[14].to_le_bytes());
        keystream[60..64].copy_from_slice(&state[15].to_le_bytes());
    }

    #[inline(always)]
    pub(crate) fn op_4blocks(&self, init_block_counter: u32, nonce: &[u8; $nonce_len], plaintext_or_ciphertext: &mut [u8; 256]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut initial_state = self.initial_state;
        // Counter (32-bits, little-endian)
        initial_state[12] = init_block_counter;
        // Nonce (96-bits, little-endian)
        initial_state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        initial_state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        initial_state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

        let mut start = 0;
        cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            unsafe {
                let state = [
                    _mm_set1_epi32(initial_state[0] as _),
                    _mm_set1_epi32(initial_state[1] as _),
                    _mm_set1_epi32(initial_state[2] as _),
                    _mm_set1_epi32(initial_state[3] as _),
                    _mm_set1_epi32(initial_state[4] as _),
                    _mm_set1_epi32(initial_state[5] as _),
                    _mm_set1_epi32(initial_state[6] as _),
                    _mm_set1_epi32(initial_state[7] as _),
                    _mm_set1_epi32(initial_state[8] as _),
                    _mm_set1_epi32(initial_state[9] as _),
                    _mm_set1_epi32(initial_state[10] as _),
                    _mm_set1_epi32(initial_state[11] as _),
                    _mm_set1_epi32(initial_state[12] as _),
                    _mm_set1_epi32(initial_state[13] as _),
                    _mm_set1_epi32(initial_state[14] as _),
                    _mm_set1_epi32(initial_state[15] as _),
                ];
                // state[12] = _mm_add_epi32(state[12], _mm_set_epi32(3, 2, 1, 0));
                let res = rounds_vertical(&state);
                // state[12] = _mm_add_epi32(state[12], _mm_set1_epi32(PARALLEL_BLOCKS as _));
                
                for block in 0..4 {
                    let block = &res[block];
                    let block00 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start) as _);
                    let block01 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start + 16) as _);
                    let block02 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start + 32) as _);
                    let block03 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start + 48) as _);

                    _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start) as _, _mm_xor_si128(block00, block[0]));
                    _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start + 16) as _, _mm_xor_si128(block01, block[1]));
                    _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start + 32) as _, _mm_xor_si128(block02, block[2]));
                    _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start + 48) as _, _mm_xor_si128(block03, block[3]));
                    start += Self::BLOCK_LEN;
                }

                // initial_state[12] += (start / Self::BLOCK_LEN) as u32;
            }
        }
        else if #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            unsafe {
                let state = [
                    vdupq_n_u32(initial_state[0]),
                    vdupq_n_u32(initial_state[1]),
                    vdupq_n_u32(initial_state[2]),
                    vdupq_n_u32(initial_state[3]),
                    vdupq_n_u32(initial_state[4]),
                    vdupq_n_u32(initial_state[5]),
                    vdupq_n_u32(initial_state[6]),
                    vdupq_n_u32(initial_state[7]),
                    vdupq_n_u32(initial_state[8]),
                    vdupq_n_u32(initial_state[9]),
                    vdupq_n_u32(initial_state[10]),
                    vdupq_n_u32(initial_state[11]),
                    vdupq_n_u32(initial_state[12]),
                    vdupq_n_u32(initial_state[13]),
                    vdupq_n_u32(initial_state[14]),
                    vdupq_n_u32(initial_state[15]),
                ];

                let res = rounds_vertical(&state);

                for i in 0..PARALLEL_BLOCKS {
                    let block = &res[i];
                    let mut block00 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start) as _);
                    let mut block01 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 16) as _);
                    let mut block02 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 32) as _);
                    let mut block03 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 48) as _);

                    block00 = veorq_u32(block00, block[0]);
                    block01 = veorq_u32(block01, block[1]);
                    block02 = veorq_u32(block02, block[2]);
                    block03 = veorq_u32(block03, block[3]);

                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start) as _, block00);
                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 16) as _, block01);
                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 32) as _, block02);
                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 48) as _, block03);
                    start += Self::BLOCK_LEN;
                }
            }
        }
        else if #[cfg(all(target_arch = "arm", target_feature = "neon"))]
        {
            unsafe {
                let initial_state_neon = [
                    vld1q_u32(initial_state.as_ptr() as _),
                    vld1q_u32((initial_state.as_ptr() as *const u8).add(16) as _),
                    vld1q_u32((initial_state.as_ptr() as *const u8).add(32) as _),
                    vld1q_u32((initial_state.as_ptr() as *const u8).add(48) as _),
                ];

                    
                let res = rounds(&initial_state_neon);
                initial_state_neon[3] = vaddq_u32(initial_state_neon[3], vld1q_u32([PARALLEL_BLOCKS as u32, 0, 0, 0].as_ptr()));

                for i in 0..PARALLEL_BLOCKS {
                    let block = &res[i];
                    let mut block00 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start) as _);
                    let mut block01 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 16) as _);
                    let mut block02 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 32) as _);
                    let mut block03 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 48) as _);

                    block00 = veorq_u32(block00, block[0]);
                    block01 = veorq_u32(block01, block[1]);
                    block02 = veorq_u32(block02, block[2]);
                    block03 = veorq_u32(block03, block[3]);

                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start) as _, block00);
                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 16) as _, block01);
                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 32) as _, block02);
                    vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 48) as _, block03);
                    start += Self::BLOCK_LEN;
                }
                // initial_state[12] += (start / Self::BLOCK_LEN) as u32;
            }
        } else {

            let mut keystream = [0u8; Self::BLOCK_LEN];
            let plaintext = unsafe { crate::utils::slice_to_array_at_mut(plaintext_or_ciphertext, start) };
            Self::block_op(&mut initial_state, &mut keystream);
            initial_state[12] = initial_state[12].wrapping_add(1);
            v512_i8_xor(plaintext, &keystream);
            start += Self::BLOCK_LEN;

            let mut keystream = [0u8; Self::BLOCK_LEN];
            let plaintext = unsafe { crate::utils::slice_to_array_at_mut(plaintext_or_ciphertext, start) };
            Self::block_op(&mut initial_state, &mut keystream);
            initial_state[12] = initial_state[12].wrapping_add(1);
            v512_i8_xor(plaintext, &keystream);
            start += Self::BLOCK_LEN;

            let mut keystream = [0u8; Self::BLOCK_LEN];
            let plaintext = unsafe { crate::utils::slice_to_array_at_mut(plaintext_or_ciphertext, start) };
            Self::block_op(&mut initial_state, &mut keystream);
            initial_state[12] = initial_state[12].wrapping_add(1);
            v512_i8_xor(plaintext, &keystream);
            start += Self::BLOCK_LEN;

            let mut keystream = [0u8; Self::BLOCK_LEN];
            let plaintext = unsafe { crate::utils::slice_to_array_at_mut(plaintext_or_ciphertext, start) };
            Self::block_op(&mut initial_state, &mut keystream);
            initial_state[12] = initial_state[12].wrapping_add(1);
            v512_i8_xor(plaintext, &keystream);
            start += Self::BLOCK_LEN;

        }
        }
    }

    #[inline(always)]
    fn op(&self, init_block_counter: u32, nonce: &[u8; $nonce_len], plaintext_or_ciphertext: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut initial_state = self.initial_state;
        // Counter (32-bits, little-endian)
        initial_state[12] = init_block_counter;
        // Nonce (96-bits, little-endian)
        initial_state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        initial_state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        initial_state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
        

        let mut start = 0;
        let mut len_remain = plaintext_or_ciphertext.len();

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if len_remain >= Self::BLOCK_LEN * PARALLEL_BLOCKS {
            unsafe {
                /*
                let mut initial_state_sse = [
                    _mm_loadu_si128(initial_state.as_ptr() as _),
                    _mm_loadu_si128((initial_state.as_ptr() as *const u8).add(16) as _),
                    _mm_loadu_si128((initial_state.as_ptr() as *const u8).add(32) as _),
                    _mm_loadu_si128((initial_state.as_ptr() as *const u8).add(48) as _),
                ];
                */

                let mut state = [
                    _mm_set1_epi32(initial_state[0] as _),
                    _mm_set1_epi32(initial_state[1] as _),
                    _mm_set1_epi32(initial_state[2] as _),
                    _mm_set1_epi32(initial_state[3] as _),
                    _mm_set1_epi32(initial_state[4] as _),
                    _mm_set1_epi32(initial_state[5] as _),
                    _mm_set1_epi32(initial_state[6] as _),
                    _mm_set1_epi32(initial_state[7] as _),
                    _mm_set1_epi32(initial_state[8] as _),
                    _mm_set1_epi32(initial_state[9] as _),
                    _mm_set1_epi32(initial_state[10] as _),
                    _mm_set1_epi32(initial_state[11] as _),
                    _mm_set1_epi32(initial_state[12] as _),
                    _mm_set1_epi32(initial_state[13] as _),
                    _mm_set1_epi32(initial_state[14] as _),
                    _mm_set1_epi32(initial_state[15] as _),
                ];
                state[12] = _mm_add_epi32(state[12], _mm_set_epi32(3, 2, 1, 0));
                while len_remain >= Self::BLOCK_LEN * PARALLEL_BLOCKS {
                    // _mm_prefetch(plaintext_or_ciphertext.as_ptr().add(start + Self::BLOCK_LEN * PARALLEL_BLOCKS) as _, _MM_HINT_T0);
                    /*
                    let res = rounds(&initial_state_sse);
                    initial_state_sse[3] = _mm_add_epi32(initial_state_sse[3], _mm_set_epi32(0, 0, 0, PARALLEL_BLOCKS as _));
                    */
                    let res = rounds_vertical(&state);
                    state[12] = _mm_add_epi32(state[12], _mm_set1_epi32(PARALLEL_BLOCKS as _));
                    
                    for block in 0..4 {
                        let block = &res[block];
                        let block00 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start) as _);
                        let block01 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start + 16) as _);
                        let block02 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start + 32) as _);
                        let block03 = _mm_loadu_si128(plaintext_or_ciphertext.as_ptr().add(start + 48) as _);

                        _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start) as _, _mm_xor_si128(block00, block[0]));
                        _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start + 16) as _, _mm_xor_si128(block01, block[1]));
                        _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start + 32) as _, _mm_xor_si128(block02, block[2]));
                        _mm_storeu_si128(plaintext_or_ciphertext.as_ptr().add(start + 48) as _, _mm_xor_si128(block03, block[3]));
                        start += Self::BLOCK_LEN;
                    }

                    len_remain -= Self::BLOCK_LEN * 4;
                }
                initial_state[12] += (start / Self::BLOCK_LEN) as u32;
            }
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        if len_remain >= Self::BLOCK_LEN * PARALLEL_BLOCKS {
            unsafe {
                let mut state = [
                    vdupq_n_u32(initial_state[0]),
                    vdupq_n_u32(initial_state[1]),
                    vdupq_n_u32(initial_state[2]),
                    vdupq_n_u32(initial_state[3]),
                    vdupq_n_u32(initial_state[4]),
                    vdupq_n_u32(initial_state[5]),
                    vdupq_n_u32(initial_state[6]),
                    vdupq_n_u32(initial_state[7]),
                    vdupq_n_u32(initial_state[8]),
                    vdupq_n_u32(initial_state[9]),
                    vdupq_n_u32(initial_state[10]),
                    vdupq_n_u32(initial_state[11]),
                    vdupq_n_u32(initial_state[12]),
                    vdupq_n_u32(initial_state[13]),
                    vdupq_n_u32(initial_state[14]),
                    vdupq_n_u32(initial_state[15]),
                ];
                state[12] = vaddq_u32(state[12], vld1q_u32([0, 1, 2, 3].as_ptr()));

                while len_remain >= Self::BLOCK_LEN * PARALLEL_BLOCKS {
                    let res = rounds_vertical(&state);
                    state[12] = vaddq_u32(state[12], vdupq_n_u32(PARALLEL_BLOCKS as u32));

                    for i in 0..PARALLEL_BLOCKS {
                        let block = &res[i];
                        let mut block00 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start) as _);
                        let mut block01 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 16) as _);
                        let mut block02 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 32) as _);
                        let mut block03 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 48) as _);

                        block00 = veorq_u32(block00, block[0]);
                        block01 = veorq_u32(block01, block[1]);
                        block02 = veorq_u32(block02, block[2]);
                        block03 = veorq_u32(block03, block[3]);

                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start) as _, block00);
                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 16) as _, block01);
                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 32) as _, block02);
                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 48) as _, block03);
                        start += Self::BLOCK_LEN;
                    }

                    len_remain -= Self::BLOCK_LEN * PARALLEL_BLOCKS;
                }
                initial_state[12] += (start / Self::BLOCK_LEN) as u32;
            }
        }

        #[cfg(all(target_arch = "arm", target_feature = "neon"))]
        if len_remain >= Self::BLOCK_LEN * PARALLEL_BLOCKS {
            unsafe {
                let mut initial_state_neon = [
                    vld1q_u32(initial_state.as_ptr() as _),
                    vld1q_u32((initial_state.as_ptr() as *const u8).add(16) as _),
                    vld1q_u32((initial_state.as_ptr() as *const u8).add(32) as _),
                    vld1q_u32((initial_state.as_ptr() as *const u8).add(48) as _),
                ];
                
                while len_remain >= Self::BLOCK_LEN * PARALLEL_BLOCKS {
                    
                    let res = rounds(&initial_state_neon);
                    initial_state_neon[3] = vaddq_u32(initial_state_neon[3], vld1q_u32([PARALLEL_BLOCKS as u32, 0, 0, 0].as_ptr()));

                    for i in 0..PARALLEL_BLOCKS {
                        let block = &res[i];
                        let mut block00 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start) as _);
                        let mut block01 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 16) as _);
                        let mut block02 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 32) as _);
                        let mut block03 = vld1q_u32(plaintext_or_ciphertext.as_ptr().add(start + 48) as _);

                        block00 = veorq_u32(block00, block[0]);
                        block01 = veorq_u32(block01, block[1]);
                        block02 = veorq_u32(block02, block[2]);
                        block03 = veorq_u32(block03, block[3]);

                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start) as _, block00);
                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 16) as _, block01);
                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 32) as _, block02);
                        vst1q_u32(plaintext_or_ciphertext.as_mut_ptr().add(start + 48) as _, block03);
                        start += Self::BLOCK_LEN;
                    }

                    len_remain -= Self::BLOCK_LEN * PARALLEL_BLOCKS;
                }
                initial_state[12] += (start / Self::BLOCK_LEN) as u32;
            }
        }

        while len_remain >= Self::BLOCK_LEN {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            let plaintext = unsafe { crate::utils::slice_to_array_at_mut(plaintext_or_ciphertext, start) };
            Self::block_op(&mut initial_state, &mut keystream);
            initial_state[12] = initial_state[12].wrapping_add(1);
            v512_i8_xor(plaintext, &keystream);
            start += Self::BLOCK_LEN;
            len_remain -= Self::BLOCK_LEN;
        }

        if len_remain > 0 {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            let rem = unsafe { plaintext_or_ciphertext.get_unchecked_mut(start..start + len_remain) };
            Self::block_op(&mut initial_state, &mut keystream);
            unsafe {
                crate::utils::assume(len_remain < Self::BLOCK_LEN);
            }
            for i in 0..len_remain {
                rem[i] ^= keystream[i];
            }
        }
    }

    /// Nonce (96-bits, little-endian)
    #[inline(always)]
    pub fn encrypt_slice(
        &self,
        init_block_counter: u32,
        nonce: &[u8; $nonce_len],
        plaintext_in_ciphertext_out: &mut [u8],
    ) {
        self.op(init_block_counter, nonce, plaintext_in_ciphertext_out)
    }

    /// Nonce (96-bits, little-endian)
    #[inline(always)]
    pub fn decrypt_slice(
        &self,
        init_block_counter: u32,
        nonce: &[u8; $nonce_len],
        ciphertext_in_plaintext_and: &mut [u8],
    ) {
        self.op(init_block_counter, nonce, ciphertext_in_plaintext_and)
    }
}
    }
}

impl_chacha20_for_target!(Chacha20Soft, 32, 64, 12, 4);

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        impl_chacha20_for_target!(Chacha20Sse, 32, 64, 12, 4, "sse2");
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon"))] {
        impl_chacha20_for_target!(Chacha20Neon, 32, 64, 12, 4, "neon");
    }
}

cfg_if::cfg_if!{
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2"))] {
        pub type Chacha20 = Chacha20Sse;
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "neon"))] {
        pub type Chacha20 = Chacha20Neon;
    } else {
        pub type Chacha20 = Chacha20Soft;
    }
}

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = state[d] ^ state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = state[b] ^ state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] = state[d] ^ state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = state[b] ^ state[c];
    state[b] = state[b].rotate_left(7);
}

#[inline(always)]
pub(crate) fn diagonal_rounds(state: &mut [u32; 16]) {
    #[inline(always)]
    fn two_rounds(state: &mut [u32; 16]) {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
    two_rounds(state);
}

#[inline(always)]
fn add_si512(a: &mut [u32; Chacha20::STATE_LEN], b: &[u32; Chacha20::STATE_LEN]) {
    for i in 0..Chacha20::STATE_LEN {
        a[i] = a[i].wrapping_add(b[i]);
    }
}

#[inline(always)]
pub(crate) fn v512_i8_xor(a: &mut [u8; Chacha20::BLOCK_LEN], b: &[u8; Chacha20::BLOCK_LEN]) {
    for i in 0..Chacha20::BLOCK_LEN {
        a[i] ^= b[i];
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::*;
        #[cfg(target_arch = "x86")]
        use std::arch::x86::*;

        macro_rules! rotate_left {
            ($v:expr, 8) => {
                #[cfg(target_feature = "ssse3")]
                {
                    $v = _mm_shuffle_epi8($v, _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3));
                }
                #[cfg(not(target_feature = "ssse3"))]
                {
                    $v = _mm_or_si128(_mm_slli_epi32($v, 8), _mm_srli_epi32($v, 32 - 8));
                }
            };
            ($v:expr, 16) => {
                #[cfg(target_feature = "ssse3")]
                {
                    $v = _mm_shuffle_epi8($v, _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2));
                }
                #[cfg(not(target_feature = "ssse3"))]
                {
                    $v = _mm_or_si128(_mm_slli_epi32($v, 16), _mm_srli_epi32($v, 32 - 16));
                }
            };
            ($v:expr, $r:literal) => {
                $v = _mm_or_si128(_mm_slli_epi32($v, $r), _mm_srli_epi32($v, 32 - $r));
            };
        }

        #[target_feature(enable = "sse2")]
        #[inline]
        unsafe fn quarter_round_sse(state_04: &mut __m128i, state_48: &mut __m128i, state_8c: &mut __m128i, state_c0: &mut __m128i) {
            *state_04 = _mm_add_epi32(*state_04, *state_48);
            *state_c0 = _mm_xor_si128(*state_c0, *state_04);
            rotate_left!(*state_c0, 16);

            *state_8c = _mm_add_epi32(*state_8c, *state_c0);
            *state_48 = _mm_xor_si128(*state_48, *state_8c);
            rotate_left!(*state_48, 12);

            *state_04 = _mm_add_epi32(*state_04, *state_48);
            *state_c0 = _mm_xor_si128(*state_c0, *state_04);
            rotate_left!(*state_c0, 8);

            *state_8c = _mm_add_epi32(*state_8c, *state_c0);
            *state_48 = _mm_xor_si128(*state_48, *state_8c);
            rotate_left!(*state_48, 7);
        }

        #[target_feature(enable = "sse2")]
        #[inline]
        unsafe fn double_quarter_round(v: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {
            add_xor_rot(v);
            rows_to_cols(v);
            add_xor_rot(v);
            cols_to_rows(v);
        }

        // #[target_feature(enable = "sse2")]
        #[inline(always)]
        unsafe fn rounds_vertical(v: &[__m128i; 16]) -> [[__m128i; 4]; PARALLEL_BLOCKS] {
            let mut res = *v;

            #[target_feature(enable = "sse2")]
            #[inline]
            unsafe fn quarter_round_sse_idx(state: &mut [__m128i; 16], a: usize, b: usize, c: usize, d: usize) {
                let mut sa = state[a];
                let mut sb = state[b];
                let mut sc = state[c];
                let mut sd = state[d];
                quarter_round_sse(&mut sa, &mut sb, &mut sc, &mut sd);
                state[a] = sa;
                state[b] = sb;
                state[c] = sc;
                state[d] = sd;
            }

            #[target_feature(enable = "sse2")]
            #[inline]
            unsafe fn double_quarter_round_sse(v: &mut [__m128i; 16]) {
                quarter_round_sse_idx(v, 0, 4, 8, 12);
                quarter_round_sse_idx(v, 1, 5, 9, 13);
                quarter_round_sse_idx(v, 2, 6, 10, 14);
                quarter_round_sse_idx(v, 3, 7, 11, 15);
                quarter_round_sse_idx(v, 0, 5, 10, 15);
                quarter_round_sse_idx(v, 1, 6, 11, 12);
                quarter_round_sse_idx(v, 2, 7, 8, 13);
                quarter_round_sse_idx(v, 3, 4, 9, 14);
            }

            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);
            double_quarter_round_sse(&mut res);

            for i in 0..16 {
                res[i] = _mm_add_epi32(res[i], v[i]);
            }
            interleave4x4(res)
        }

        #[target_feature(enable = "sse2")]
        #[inline]
        unsafe fn interleave4x4(v: [__m128i; 16]) -> [[__m128i; 4]; 4] {
            let mut res = [[v[0]; 4]; 4];
            for i in 0..4 {
                let a = v[i * 4 + 0];
                let b = v[i * 4 + 1];
                let c = v[i * 4 + 2];
                let d = v[i * 4 + 3];
                let tmp0 = _mm_unpacklo_epi32(a, b);
                let tmp1 = _mm_unpackhi_epi32(a, b);
                let tmp2 = _mm_unpacklo_epi32(c, d);
                let tmp3 = _mm_unpackhi_epi32(c, d);

                res[0][i] = _mm_unpacklo_epi64(tmp0, tmp2);
                res[1][i] = _mm_unpackhi_epi64(tmp0, tmp2);
                res[2][i] = _mm_unpacklo_epi64(tmp1, tmp3);
                res[3][i] = _mm_unpackhi_epi64(tmp1, tmp3);
            }
            res
        }

        #[target_feature(enable = "sse2")]
        #[inline]
        unsafe fn rounds(v: &[__m128i; 4]) -> [[__m128i; 4]; PARALLEL_BLOCKS] {
            let mut res = [*v; PARALLEL_BLOCKS];
            for i in 1..PARALLEL_BLOCKS {
                res[i][3] = _mm_add_epi32(res[i][3], _mm_set_epi32(0, 0, 0, i as i32));
            }

            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);


            for i in 0..PARALLEL_BLOCKS {
                for j in 0..4 {
                    res[i][j] = _mm_add_epi32(res[i][j], v[j]);
                }

                // add the counter since `v` is lacking updated counter values
                res[i][3] = _mm_add_epi32(res[i][3], _mm_set_epi32(0, 0, 0, i as i32));
            }

            res
        }

        #[target_feature(enable = "sse2")]
        #[inline]
        unsafe fn rows_to_cols(blocks: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {
            for i in 0..PARALLEL_BLOCKS {
                let [a, _, c, d] = &mut blocks[i];
                *c = _mm_shuffle_epi32(*c, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
                *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
                *a = _mm_shuffle_epi32(*a, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
            }
        }

        #[target_feature(enable = "sse2")]
        #[inline]
        unsafe fn cols_to_rows(blocks: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {

            for i in 0..PARALLEL_BLOCKS {
                let [a, _, c, d] = &mut blocks[i];
                *c = _mm_shuffle_epi32(*c, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
                *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
                *a = _mm_shuffle_epi32(*a, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
            }
        }

        #[target_feature(enable = "sse2")]
        #[inline]
        unsafe fn add_xor_rot(blocks: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {
            for i in 0..PARALLEL_BLOCKS {
                let [a, b, c, d] = &mut blocks[i];
                quarter_round_sse(a, b, c, d);
            }
        }
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "neon"))] {
        #[cfg(target_arch = "arm")]
        use core::arch::arm::*;
        #[cfg(target_arch = "aarch64")]
        use core::arch::aarch64::*;

        macro_rules! add64 {
            ($a:expr, $b:expr) => {
                vreinterpretq_u32_u64(vaddq_u64(
                    vreinterpretq_u64_u32($a),
                    vreinterpretq_u64_u32($b),
                ))
            };
        }

        macro_rules! rotate_left {
            ($v:expr, 8) => {
                #[cfg(target_arch = "aarch64")]
                {
                    let maskb = [3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
                    let mask = vld1q_u8(maskb.as_ptr());
            
                    $v = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32($v), mask))
                }
                #[cfg(target_arch = "arm")]
                {
                    $v = vsliq_n_u32(vshrq_n_u32($v, 24), $v, 8)
                }
            };
            ($v:expr, 16) => {
                $v = vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32($v)))
            };
            ($v:expr, $r:literal) => {
                $v = vsliq_n_u32(vshrq_n_u32($v, 32 - $r), $v, $r)
            };
        }

        #[target_feature(enable = "neon")]
        #[inline]
        unsafe fn quarter_round_neon(state_04: &mut uint32x4_t, state_48: &mut uint32x4_t, state_8c: &mut uint32x4_t, state_c0: &mut uint32x4_t) {
            *state_04 = vaddq_u32(*state_04, *state_48);
            *state_c0 = veorq_u32(*state_c0, *state_04);
            rotate_left!(*state_c0, 16);

            *state_8c = vaddq_u32(*state_8c, *state_c0);
            *state_48 = veorq_u32(*state_48, *state_8c);
            rotate_left!(*state_48, 12);

            *state_04 = vaddq_u32(*state_04, *state_48);
            *state_c0 = veorq_u32(*state_c0, *state_04);
            rotate_left!(*state_c0, 8);

            *state_8c = vaddq_u32(*state_8c, *state_c0);
            *state_48 = veorq_u32(*state_48, *state_8c);
            rotate_left!(*state_48, 7);
        }

        #[target_feature(enable = "neon")]
        #[inline]
        unsafe fn double_quarter_round(v: &mut [[uint32x4_t; 4]; PARALLEL_BLOCKS]) {
            add_xor_rot(v);
            rows_to_cols(v);
            add_xor_rot(v);
            cols_to_rows(v);
        }

        #[cfg(target_arch = "aarch64")]
        #[inline(always)]
        unsafe fn rounds_vertical(v: &[uint32x4_t; 16]) -> [[uint32x4_t; 4]; PARALLEL_BLOCKS] {
            let mut res = *v;

            #[target_feature(enable = "neon")]
            #[inline]
            unsafe fn quarter_round_neon_idx(state: &mut [uint32x4_t; 16], a: usize, b: usize, c: usize, d: usize) {
                let mut sa = state[a];
                let mut sb = state[b];
                let mut sc = state[c];
                let mut sd = state[d];
                quarter_round_neon(&mut sa, &mut sb, &mut sc, &mut sd);
                state[a] = sa;
                state[b] = sb;
                state[c] = sc;
                state[d] = sd;
            }
            #[target_feature(enable = "neon")]
            #[inline]
            unsafe fn double_quarter_round_neon(v: &mut [uint32x4_t; 16]) {
                quarter_round_neon_idx(v, 0, 4, 8, 12);
                quarter_round_neon_idx(v, 1, 5, 9, 13);
                quarter_round_neon_idx(v, 2, 6, 10, 14);
                quarter_round_neon_idx(v, 3, 7, 11, 15);
                quarter_round_neon_idx(v, 0, 5, 10, 15);
                quarter_round_neon_idx(v, 1, 6, 11, 12);
                quarter_round_neon_idx(v, 2, 7, 8, 13);
                quarter_round_neon_idx(v, 3, 4, 9, 14);
            }

            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);
            double_quarter_round_neon(&mut res);

            for i in 0..16 {
                res[i] = vaddq_u32(res[i], v[i]);
            }
            #[target_feature(enable = "neon")]
            #[inline]
            unsafe fn interleave4x4(v: [uint32x4_t; 4 * 4]) -> [[uint32x4_t; 4]; 4] {
                let mut res = [[v[0]; 4]; PARALLEL_BLOCKS];

                for i in 0..4 {
                    let a = v[i * 4 + 0];
                    let b = v[i * 4 + 1];
                    let c = v[i * 4 + 2];
                    let d = v[i * 4 + 3];
                    let tmp0 = vzip1q_u32(a, b);
                    let tmp1 = vzip2q_u32(a, b);
                    let tmp2 = vzip1q_u32(c, d);
                    let tmp3 = vzip2q_u32(c, d);

                    res[0][i] = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(tmp0), vreinterpretq_u64_u32(tmp2)));
                    res[1][i] = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(tmp0), vreinterpretq_u64_u32(tmp2)));
                    res[2][i] = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(tmp1), vreinterpretq_u64_u32(tmp3)));
                    res[3][i] = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(tmp1), vreinterpretq_u64_u32(tmp3)));
                }
                res
            }
            interleave4x4(res)
        }

        #[target_feature(enable = "neon")]
        #[inline]
        unsafe fn rounds(v: &[uint32x4_t; 4]) -> [[uint32x4_t; 4]; PARALLEL_BLOCKS] {
            let mut res = [*v; PARALLEL_BLOCKS];

            for i in 1..PARALLEL_BLOCKS {
                res[i][3] = add64!(res[i][3], vld1q_u32([i as u32, 0, 0, 0].as_ptr()));
            }

            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);
            double_quarter_round(&mut res);

            for i in 0..PARALLEL_BLOCKS {
                res[i][0] = vaddq_u32(res[i][0], v[0]);
                res[i][1] = vaddq_u32(res[i][1], v[1]);
                res[i][2] = vaddq_u32(res[i][2], v[2]);
                res[i][3] = vaddq_u32(res[i][3], v[3]);
                // add the counter since `v` is lacking updated counter values
                res[i][3] = add64!(res[i][3], vld1q_u32([i as u32, 0, 0, 0].as_ptr()));
            }

            res
        }
            

        #[target_feature(enable = "neon")]
        #[inline]
        unsafe fn rows_to_cols(blocks: &mut [[uint32x4_t; 4]; PARALLEL_BLOCKS]) {
            for i in 0..PARALLEL_BLOCKS {
                let [a, _, c, d] = &mut blocks[i];
                *c = vextq_u32(*c, *c, 1);
                *d = vextq_u32(*d, *d, 2);
                *a = vextq_u32(*a, *a, 3);
            }
        }

        #[target_feature(enable = "neon")]
        #[inline]
        unsafe fn cols_to_rows(blocks: &mut [[uint32x4_t; 4]; PARALLEL_BLOCKS]) {
            for i in 0..PARALLEL_BLOCKS {
                let [a, _, c, d] = &mut blocks[i];
                *c = vextq_u32(*c, *c, 3);
                *d = vextq_u32(*d, *d, 2);
                *a = vextq_u32(*a, *a, 1);
            }
        }

        #[target_feature(enable = "neon")]
        #[inline]
        unsafe fn add_xor_rot(blocks: &mut [[uint32x4_t; 4]; PARALLEL_BLOCKS]) {
            for i in 0..PARALLEL_BLOCKS {
                let [a, b, c, d] = &mut blocks[i];
                quarter_round_neon(a, b, c, d);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chacha20() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut chacha20 = Chacha20::new(key);
        let mut plaintext = [0u8; 64];
        let expected_ciphertext = [
            0x76, 0xB9, 0xE2, 0xAE, 0xA4, 0xF4, 0x3B, 0x97,
            0x48, 0x54, 0x60, 0xEE, 0x5F, 0x8B, 0xB3, 0x27,
            0xAD, 0xC3, 0x0B, 0xAB, 0xB4, 0x98, 0xFB, 0x0D,
            0xB0, 0x2F, 0xF5, 0xD7, 0x97, 0x6A, 0x13, 0xD8,
            0xFA, 0x60, 0x7B, 0x5F, 0x75, 0x72, 0x6E, 0xAA,
            0x5F, 0x0D, 0xCA, 0x14, 0x94, 0xF5, 0x64, 0x18,
            0x5A, 0x72, 0x8A, 0xC7, 0x21, 0x2D, 0x97, 0x2B,
            0xFB, 0xBE, 0x8C, 0x52, 0x8E, 0xD3, 0x5B, 0xB9,
        ];
        let mut decrypted = [0u8; 64];
        for i in 0..plaintext.len() {
            plaintext[i] = i as u8;
        }
        let mut ciphertext = plaintext;
        chacha20.encrypt_slice(0, &nonce, &mut ciphertext);
        assert_eq!(expected_ciphertext, ciphertext);
        chacha20.decrypt_slice(0, &nonce, &mut ciphertext);
        decrypted.copy_from_slice(&ciphertext);
        assert_eq!(plaintext, decrypted);

        // test long message
        let mut plaintext = [0u8; 1024];
        let mut decrypted = [0u8; 1024];
        
        for i in 0..plaintext.len() {
            plaintext[i] = i as u8;
        }
        let mut ciphertext = plaintext;
        chacha20.encrypt_slice(0, &nonce, &mut ciphertext);
        chacha20.decrypt_slice(0, &nonce, &mut ciphertext);
        decrypted.copy_from_slice(&ciphertext);
        assert_eq!(plaintext, decrypted);
    }
}