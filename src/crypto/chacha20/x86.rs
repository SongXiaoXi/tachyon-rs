use super::PARALLEL_BLOCKS;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use std::arch::x86::*;

macro_rules! impl_chacha20_for_target {
    ($name:tt, $key_len:literal, $block_len:literal, $nonce_len:literal, $counter_len:literal$(, $feature:literal)?) => {
#[derive(Clone, Copy)]
pub struct $name {
    pub(crate) initial_state: [u32; 16],
}

impl $name {
    pub const KEY_LEN: usize = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 12;
    pub const COUNTER_LEN: usize = 4;

    pub(crate) const STATE_LEN: usize = 16; // len in doubleword (32-bits)

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

        crate::const_loop!(i, 0, 16, {
            keystream[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
        });
    }

    #[inline(always)]
    pub(crate) fn op_1block(&self, init_block_counter: u32, nonce: &[u8; $nonce_len], plaintext_or_ciphertext: &mut [u8; 64]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut initial_state = self.initial_state;
        // Counter (32-bits, little-endian)
        initial_state[12] = init_block_counter;
        // Nonce (96-bits, little-endian)
        initial_state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        initial_state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        initial_state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

        Self::block_op(&mut initial_state, plaintext_or_ciphertext);
    }

    #[inline(always)]
    pub(crate) fn op_4blocks(&self, init_block_counter: u32, nonce: &[u8; $nonce_len], data: &mut [u8; 256]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut initial_state = self.initial_state;
        // Counter (32-bits, little-endian)
        initial_state[12] = init_block_counter;
        // Nonce (96-bits, little-endian)
        initial_state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        initial_state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        initial_state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

        let mut start = 0;

        unsafe {
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
            let res = rounds_vertical(&state);
            
            #[crate::loop_unroll(block, 0, 4)]
            fn loop_unroll() {
                let block = &res[block];
                let block00 = _mm_loadu_si128(data.as_ptr().add(start + 0) as _);
                let block01 = _mm_loadu_si128(data.as_ptr().add(start + 16) as _);
                let block02 = _mm_loadu_si128(data.as_ptr().add(start + 32) as _);
                let block03 = _mm_loadu_si128(data.as_ptr().add(start + 48) as _);

                _mm_storeu_si128(data.as_ptr().add(start + 0) as _, _mm_xor_si128(block00, block[0]));
                _mm_storeu_si128(data.as_ptr().add(start + 16) as _, _mm_xor_si128(block01, block[1]));
                _mm_storeu_si128(data.as_ptr().add(start + 32) as _, _mm_xor_si128(block02, block[2]));
                _mm_storeu_si128(data.as_ptr().add(start + 48) as _, _mm_xor_si128(block03, block[3]));
                start += Self::BLOCK_LEN;
            }
        }
        
        _ = start;
    }
}

$(#[unsafe_target_feature::unsafe_target_feature($feature)])?
impl $name {
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

        if len_remain >= Self::BLOCK_LEN * PARALLEL_BLOCKS {
            unsafe {
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
                    let res = rounds_vertical(&state);
                    state[12] = _mm_add_epi32(state[12], _mm_set1_epi32(PARALLEL_BLOCKS as _));
                   
                    #[crate::loop_unroll(block, 0, 4)]
                    fn loop_unroll() {
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
            // Safety: len_remain is less than BLOCK_LEN
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

impl_chacha20_for_target!(Chacha20SSE, 32, 64, 12, 4, "sse2,ssse3");
impl_chacha20_for_target!(Chacha20AVX, 32, 64, 12, 4, "avx");

type Chacha20Soft = super::soft::Chacha20Soft;

use super::soft::diagonal_rounds;
use super::soft::add_si512;
use super::soft::v512_i8_xor;

macro_rules! rotate_left {
    // ($v:expr, 8) => {
    //     // #[cfg(target_feature = "ssse3")]
    //     // {
    //         // $v = _mm_shuffle_epi8($v, _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3));
    //     // }
    //     // #[cfg(not(target_feature = "ssse3"))]
    //     // {
    //         $v = _mm_xor_si128(_mm_slli_epi32($v, 8), _mm_srli_epi32($v, 32 - 8));
    //     // }
    // };
    // ($v:expr, 16) => {
    //     // #[cfg(target_feature = "ssse3")]
    //     // {
    //         // $v = _mm_shuffle_epi8($v, _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2));
    //     // }
    //     // #[cfg(not(target_feature = "ssse3"))]
    //     // {
    //         $v = _mm_xor_si128(_mm_slli_epi32($v, 16), _mm_srli_epi32($v, 32 - 16));
    //     // }
    // };
    ($v:expr, $r:literal) => {
        $v = _mm_xor_si128(_mm_slli_epi32($v, $r), _mm_srli_epi32($v, 32 - $r));
    };
}

#[inline(always)]
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

#[inline(always)]
unsafe fn double_quarter_round(v: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {
    add_xor_rot(v);
    rows_to_cols(v);
    add_xor_rot(v);
    cols_to_rows(v);
}

#[inline(always)]
unsafe fn rounds_vertical(v: &[__m128i; 16]) -> [[__m128i; 4]; PARALLEL_BLOCKS] {
    let mut res = *v;

    #[inline(always)]
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

    #[inline(always)]
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

    #[crate::loop_unroll(_, 0, 10)]
    fn loop_unroll() {
        double_quarter_round_sse(&mut res);
    }

    #[crate::loop_unroll(i, 0, 16)]
    fn loop_unroll() {
        res[i] = _mm_add_epi32(res[i], v[i]);
    }
    interleave4x4(res)
}

#[inline(always)]
unsafe fn interleave4x4(v: [__m128i; 16]) -> [[__m128i; 4]; 4] {
    let mut res = [[v[0]; 4]; 4];
    #[crate::loop_unroll(i, 0, 4)]
    fn loop_unroll() {
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

#[inline(always)]
unsafe fn rounds(v: &[__m128i; 4]) -> [[__m128i; 4]; PARALLEL_BLOCKS] {
    let mut res = [*v; PARALLEL_BLOCKS];
    #[crate::loop_unroll(i, 0, 4)]
    fn loop_unroll() {
        res[i][3] = _mm_add_epi32(res[i][3], _mm_set_epi32(0, 0, 0, i as i32));
    }

    #[crate::loop_unroll(_, 0, 10)]
    fn loop_unroll() {
        double_quarter_round(&mut res);
    }

    #[crate::loop_unroll(i, 0, 4)]
    fn loop_unroll() {
        #[crate::loop_unroll(j, 0, 4)]
        fn loop_unroll() {
            res[i][j] = _mm_add_epi32(res[i][j], v[j]);
        }

        // add the counter since `v` is lacking updated counter values
        res[i][3] = _mm_add_epi32(res[i][3], _mm_set_epi32(0, 0, 0, i as i32));
    }

    res
}

#[inline(always)]
unsafe fn rows_to_cols(blocks: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {
    #[crate::loop_unroll(i, 0, 4)]
    fn loop_unroll() {
        let [a, _, c, d] = &mut blocks[i];
        *c = _mm_shuffle_epi32(*c, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
        *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        *a = _mm_shuffle_epi32(*a, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
    }
}

#[inline(always)]
unsafe fn cols_to_rows(blocks: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {
    #[crate::loop_unroll(i, 0, 4)]
    fn loop_unroll() {
        let [a, _, c, d] = &mut blocks[i];
        *c = _mm_shuffle_epi32(*c, 0b_10_01_00_11); // _MM_SHUFFLE(2, 1, 0, 3)
        *d = _mm_shuffle_epi32(*d, 0b_01_00_11_10); // _MM_SHUFFLE(1, 0, 3, 2)
        *a = _mm_shuffle_epi32(*a, 0b_00_11_10_01); // _MM_SHUFFLE(0, 3, 2, 1)
    }
}

#[inline(always)]
unsafe fn add_xor_rot(blocks: &mut [[__m128i; 4]; PARALLEL_BLOCKS]) {
    #[crate::loop_unroll(i, 0, 4)]
    fn loop_unroll() {
        let [a, b, c, d] = &mut blocks[i];
        quarter_round_sse(a, b, c, d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20() {
        if crate::is_hw_feature_detected!("sse2") {
            chacha20_test_case!(Chacha20SSE);
        }
        if crate::is_hw_feature_detected!("avx") {
            chacha20_test_case!(Chacha20AVX);
        }
    }
}