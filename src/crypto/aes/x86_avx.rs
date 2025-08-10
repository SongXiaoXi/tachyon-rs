#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::x86::*;

#[derive(Clone, Copy)]
pub struct AES128 {
    key_schedule: [__m128i; 20],
}

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;
}

#[unsafe_target_feature::unsafe_target_feature("avx,aes")]
impl AES128 {
    #[inline(always)]
    pub fn new(key: [u8; 16]) -> Self {
        let mut key_schedule = [unsafe { core::mem::zeroed() }; 20];
        unsafe {
            load_key_128!(&mut key_schedule, &key);
        }
        Self { key_schedule }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        Self::new(unsafe { *(key.as_ptr() as *const [u8; 16]) })
    }

    #[inline(always)]
    pub fn encrypt(&self, data: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_ENC_BLOCK!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(data.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn encrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_ENC_BLOCK!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn encrypt_simd(&self, mut block: __m128i) -> __m128i {
        DO_ENC_BLOCK!(block, self.key_schedule);
        block
    }

    #[inline(always)]
    pub fn decrypt(&self, data: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_DEC_BLOCK!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(data.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn decrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_DEC_BLOCK!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn decrypt_simd(&self, mut block: __m128i) -> __m128i {
        DO_DEC_BLOCK!(block, self.key_schedule);
        block
    }

    #[inline(always)]
    pub fn encrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        let mut block0 = unsafe { _mm_loadu_si128(data0.as_ptr() as *const __m128i) };
        let mut block1 = unsafe { _mm_loadu_si128(data1.as_ptr() as *const __m128i) };
        let mut block2 = unsafe { _mm_loadu_si128(data2.as_ptr() as *const __m128i) };
        let mut block3 = unsafe { _mm_loadu_si128(data3.as_ptr() as *const __m128i) };
        DO_ENC_4_BLOCKS!(block0, block1, block2, block3, self.key_schedule);
        unsafe {
            _mm_storeu_si128(data0.as_mut_ptr() as *mut __m128i, block0);
            _mm_storeu_si128(data1.as_mut_ptr() as *mut __m128i, block1);
            _mm_storeu_si128(data2.as_mut_ptr() as *mut __m128i, block2);
            _mm_storeu_si128(data3.as_mut_ptr() as *mut __m128i, block3);
        }
    }

    #[inline(always)]
    pub(crate) fn encrypt_4_blocks_xor(&self, data: [&[u8; 16]; 4], text: [&mut [u8; 16]; 4]) {
        DO_ENC_BLOCKS_XOR!(4, data, text, self.key_schedule);
    }

    #[inline(always)]
    pub(crate) fn encrypt_6_blocks_xor(&self, data: [&[u8; 16]; 6], text: [&mut [u8; 16]; 6]) {
        DO_ENC_BLOCKS_XOR!(6, data, text, self.key_schedule);
    }

    #[inline(always)]
    pub fn decrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        let mut block0 = unsafe { _mm_loadu_si128(data0.as_ptr() as *const __m128i) };
        let mut block1 = unsafe { _mm_loadu_si128(data1.as_ptr() as *const __m128i) };
        let mut block2 = unsafe { _mm_loadu_si128(data2.as_ptr() as *const __m128i) };
        let mut block3 = unsafe { _mm_loadu_si128(data3.as_ptr() as *const __m128i) };
        DO_DEC_4_BLOCKS!(block0, block1, block2, block3, self.key_schedule);
        unsafe {
            _mm_storeu_si128(data0.as_mut_ptr() as *mut __m128i, block0);
            _mm_storeu_si128(data1.as_mut_ptr() as *mut __m128i, block1);
            _mm_storeu_si128(data2.as_mut_ptr() as *mut __m128i, block2);
            _mm_storeu_si128(data3.as_mut_ptr() as *mut __m128i, block3);
        }
    }
    // data must be a slice of 16 bytes
    #[inline(always)]
    pub fn encrypt_slice(&self, data: &mut [u8]) {
        assert_eq!(data.len() % 16, 0);
        let mut chunks = data.chunks_exact_mut(16 * 4);
        for chunk in &mut chunks {
            let block0 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 0) };
            let block0 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block0) };
            let block1 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 16) };
            let block1 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block1) };
            let block2 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 32) };
            let block2 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block2) };
            let block3 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 48) };
            let block3 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block3) };

            self.encrypt_4_blocks(block0, block1, block2, block3);
        }

        for chunk in chunks.into_remainder().chunks_exact_mut(16) {
            let mut block = unsafe { crate::utils::slice_to_array_mut(chunk) };
            self.encrypt(&mut block);
        }
    }
    // data must be a slice of 16 bytes
    #[inline(always)]
    pub fn decrypt_slice(&self, data: &mut [u8]) {
        assert_eq!(data.len() % 16, 0);
        let mut chunks = data.chunks_exact_mut(16 * 4);
        for chunk in &mut chunks {
            let block0 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 0) };
            let block0 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block0) };
            let block1 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 16) };
            let block1 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block1) };
            let block2 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 32) };
            let block2 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block2) };
            let block3 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 48) };
            let block3 = unsafe { core::mem::transmute::<&mut [u8; 16], _>(block3) };

            self.decrypt_4_blocks(block0, block1, block2, block3);
        }

        for chunk in chunks.into_remainder().chunks_exact_mut(16) {
            let mut block = unsafe { crate::utils::slice_to_array_mut(chunk) };
            self.decrypt(&mut block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128() {
        if !is_x86_feature_detected!("avx") || !is_x86_feature_detected!("aes") {
            return;
        }
        aes128_test_case!();
    }
}