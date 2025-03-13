#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use unsafe_target_feature::unsafe_target_feature;

#[inline(always)]
fn key_expansion_128(mut key: __m128i, keygened: __m128i) -> __m128i {
    unsafe {
        let keygened = {
            const IMM8: i32 = crate::_MM_SHUFFLE(3, 3, 3, 3);
            _mm_shuffle_epi32::<IMM8>(keygened) 
        };
        key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));
        key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));
        key = _mm_xor_si128(key, _mm_slli_si128::<4>(key));
        _mm_xor_si128(key, keygened)
    }
}

#[unsafe_target_feature("aes")]
#[inline(always)]
fn key_exp_128<const RCON: i32>(key: __m128i) -> __m128i {
    unsafe {
        let keygened = _mm_aeskeygenassist_si128(key, RCON);
        key_expansion_128(key, keygened)
    }
}

#[unsafe_target_feature("aes")]
#[inline(always)]
fn load_key_128(key_schedule: &mut [__m128i; 20], key: &[u8; 16]) {
    unsafe {
        let key = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        key_schedule[0] = key;
        key_schedule[1] = key_exp_128::<0x01>(key_schedule[0]);
        key_schedule[2] = key_exp_128::<0x02>(key_schedule[1]);
        key_schedule[3] = key_exp_128::<0x04>(key_schedule[2]);
        key_schedule[4] = key_exp_128::<0x08>(key_schedule[3]);
        key_schedule[5] = key_exp_128::<0x10>(key_schedule[4]);
        key_schedule[6] = key_exp_128::<0x20>(key_schedule[5]);
        key_schedule[7] = key_exp_128::<0x40>(key_schedule[6]);
        key_schedule[8] = key_exp_128::<0x80>(key_schedule[7]);
        key_schedule[9] = key_exp_128::<0x1b>(key_schedule[8]);
        key_schedule[10] = key_exp_128::<0x36>(key_schedule[9]);

        crate::const_loop!(i, 1, 9, {
            key_schedule[10 + i] = _mm_aesimc_si128(key_schedule[10 - i]);
        });
    }
}

macro_rules! DO_ENC_BLOCK {
    ($block:expr, $key:expr) => {
        unsafe {
            $block = _mm_xor_si128($block, $key[0]);
            crate::const_loop!(i, 1, 9, {
                $block = _mm_aesenc_si128($block, $key[i]);
            });
            $block = _mm_aesenclast_si128($block, $key[10]);
        }
    };
}

macro_rules! DO_DEC_BLOCK {
    ($block:expr, $key:expr) => {
        unsafe {
            $block = _mm_xor_si128($block, $key[10]);
            crate::const_loop!(i, 1, 9, {
                $block = _mm_aesdec_si128($block, $key[10 + i]);
            });
            $block = _mm_aesdeclast_si128($block, $key[0]);
        }
    };
}

#[derive(Clone, Copy)]
pub struct AES128 {
    key_schedule: [__m128i; 20],
}

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    #[inline(always)]
    pub fn new(key: [u8; 16]) -> Self {
        let mut key_schedule = [unsafe { core::mem::zeroed() }; 20];
        load_key_128(&mut key_schedule, &key);
        Self { key_schedule }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        Self::new(unsafe { *(key.as_ptr() as *const [u8; 16]) })
    }
}

#[unsafe_target_feature("aes")]
impl AES128 {
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
        DO_ENC_BLOCK!(block0, self.key_schedule);
        DO_ENC_BLOCK!(block1, self.key_schedule);
        DO_ENC_BLOCK!(block2, self.key_schedule);
        DO_ENC_BLOCK!(block3, self.key_schedule);
        unsafe {
            _mm_storeu_si128(data0.as_mut_ptr() as *mut __m128i, block0);
            _mm_storeu_si128(data1.as_mut_ptr() as *mut __m128i, block1);
            _mm_storeu_si128(data2.as_mut_ptr() as *mut __m128i, block2);
            _mm_storeu_si128(data3.as_mut_ptr() as *mut __m128i, block3);
        }
    }

    #[inline(always)]
    pub fn decrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        let mut block0 = unsafe { _mm_loadu_si128(data0.as_ptr() as *const __m128i) };
        let mut block1 = unsafe { _mm_loadu_si128(data1.as_ptr() as *const __m128i) };
        let mut block2 = unsafe { _mm_loadu_si128(data2.as_ptr() as *const __m128i) };
        let mut block3 = unsafe { _mm_loadu_si128(data3.as_ptr() as *const __m128i) };
        DO_DEC_BLOCK!(block0, self.key_schedule);
        DO_DEC_BLOCK!(block1, self.key_schedule);
        DO_DEC_BLOCK!(block2, self.key_schedule);
        DO_DEC_BLOCK!(block3, self.key_schedule);
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
            let block0 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block0) };
            let block1 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 1) };
            let block1 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block1) };
            let block2 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 2) };
            let block2 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block2) };
            let block3 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 3) };
            let block3 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block3) };

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
            let block0 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block0) };
            let block1 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 1) };
            let block1 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block1) };
            let block2 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 2) };
            let block2 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block2) };
            let block3 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 3) };
            let block3 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block3) };

            self.decrypt_4_blocks(block0, block1, block2, block3);
        }

        for chunk in chunks.into_remainder().chunks_exact_mut(16) {
            let mut block = unsafe { crate::utils::slice_to_array_mut(chunk) };
            self.decrypt(&mut block);
        }
    }
}

struct AES128Vaes {
    key_schedule: [__m128i; 20],
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let cipher = AES128::new(key);

        let mut data = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        cipher.encrypt(&mut data);
        assert_eq!(data, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);

        let mut data = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        cipher.decrypt(&mut data);
        assert_eq!(data, [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]);
    }
}