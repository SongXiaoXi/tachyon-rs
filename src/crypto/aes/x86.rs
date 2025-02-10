#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

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

#[inline(always)]
fn key_exp_128<const RCON: i32>(key: __m128i) -> __m128i {
    unsafe {
        let keygened = _mm_aeskeygenassist_si128(key, RCON);
        key_expansion_128(key, keygened)
    }
}

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

        key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
        key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
        key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
        key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
        key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
        key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
        key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
        key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
        key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
    }
}

macro_rules! DO_ENC_BLOCK {
    ($block:expr, $key:expr) => {
        unsafe {
            $block = _mm_xor_si128($block, $key[0]);
            $block = _mm_aesenc_si128($block, $key[1]);
            $block = _mm_aesenc_si128($block, $key[2]);
            $block = _mm_aesenc_si128($block, $key[3]);
            $block = _mm_aesenc_si128($block, $key[4]);
            $block = _mm_aesenc_si128($block, $key[5]);
            $block = _mm_aesenc_si128($block, $key[6]);
            $block = _mm_aesenc_si128($block, $key[7]);
            $block = _mm_aesenc_si128($block, $key[8]);
            $block = _mm_aesenc_si128($block, $key[9]);
            $block = _mm_aesenclast_si128($block, $key[10]);
        }
    };
}

macro_rules! DO_DEC_BLOCK {
    ($block:expr, $key:expr) => {
        unsafe {
            $block = _mm_xor_si128($block, $key[10]);
            $block = _mm_aesdec_si128($block, $key[11]);
            $block = _mm_aesdec_si128($block, $key[12]);
            $block = _mm_aesdec_si128($block, $key[13]);
            $block = _mm_aesdec_si128($block, $key[14]);
            $block = _mm_aesdec_si128($block, $key[15]);
            $block = _mm_aesdec_si128($block, $key[16]);
            $block = _mm_aesdec_si128($block, $key[17]);
            $block = _mm_aesdec_si128($block, $key[18]);
            $block = _mm_aesdec_si128($block, $key[19]);
            $block = _mm_aesdeclast_si128($block, $key[0]);
        }
    };
}

#[derive(Clone)]
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