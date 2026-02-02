#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use unsafe_target_feature::unsafe_target_feature;

#[macro_use]
mod macros {

macro_rules! key_expansion_128 {
    ($key:expr, $keygened:ident) => {
        {
            let mut key = $key;
            let keygened = {
                const IMM8: i32 = crate::_MM_SHUFFLE(3, 3, 3, 3);
                _mm_shuffle_epi32::<IMM8>($keygened) 
            };
            key = _mm_xor_si128($key, _mm_slli_si128::<4>(key));
            key = _mm_xor_si128($key, _mm_slli_si128::<4>(key));
            key = _mm_xor_si128($key, _mm_slli_si128::<4>(key));
            _mm_xor_si128(key, keygened)
        }
    }
}

macro_rules! key_exp_128 {
    ($key:expr, $rcon:expr) => {
        {
            let keygened = _mm_aeskeygenassist_si128($key, $rcon);
            key_expansion_128!($key, keygened)
        }
    }
}

macro_rules! load_key_128 {
    ($key_schedule:expr, $key:expr) => {
        load_key_128_enc!($key_schedule, $key);
        crate::const_loop!(i, 1, 9, {
            $key_schedule[10 + i] = _mm_aesimc_si128($key_schedule[10 - i]);
        });
    }
}

macro_rules! load_key_128_enc {
    ($key_schedule:expr, $key:expr) => {
        let key = _mm_loadu_si128($key.as_ptr() as *const __m128i);
        $key_schedule[0] = key;
        $key_schedule[1] = key_exp_128!($key_schedule[0], 0x01);
        $key_schedule[2] = key_exp_128!($key_schedule[1], 0x02);
        $key_schedule[3] = key_exp_128!($key_schedule[2], 0x04);
        $key_schedule[4] = key_exp_128!($key_schedule[3], 0x08);
        $key_schedule[5] = key_exp_128!($key_schedule[4], 0x10);
        $key_schedule[6] = key_exp_128!($key_schedule[5], 0x20);
        $key_schedule[7] = key_exp_128!($key_schedule[6], 0x40);
        $key_schedule[8] = key_exp_128!($key_schedule[7], 0x80);
        $key_schedule[9] = key_exp_128!($key_schedule[8], 0x1b);
        $key_schedule[10] = key_exp_128!($key_schedule[9], 0x36);
    }
}

macro_rules! DO_ENC_BLOCK {
    ($block:expr, $key:expr) => {
        #[allow(unused_unsafe)]
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
        #[allow(unused_unsafe)]
        unsafe {
            $block = _mm_xor_si128($block, $key[10]);
            crate::const_loop!(i, 1, 9, {
                $block = _mm_aesdec_si128($block, $key[10 + i]);
            });
            $block = _mm_aesdeclast_si128($block, $key[0]);
        }
    };
}

macro_rules! DO_ENC_4_BLOCKS {
    ($block0:expr, $block1:expr, $block2:expr, $block3:expr, $key:expr) => {
        $block0 = _mm_xor_si128($block0, $key[0]);
        $block1 = _mm_xor_si128($block1, $key[0]);
        $block2 = _mm_xor_si128($block2, $key[0]);
        $block3 = _mm_xor_si128($block3, $key[0]);
        crate::const_loop!(i, 1, 9, {
            $block0 = _mm_aesenc_si128($block0, $key[i]);
            $block1 = _mm_aesenc_si128($block1, $key[i]);
            $block2 = _mm_aesenc_si128($block2, $key[i]);
            $block3 = _mm_aesenc_si128($block3, $key[i]);
        });
        $block0 = _mm_aesenclast_si128($block0, $key[10]);
        $block1 = _mm_aesenclast_si128($block1, $key[10]);
        $block2 = _mm_aesenclast_si128($block2, $key[10]);
        $block3 = _mm_aesenclast_si128($block3, $key[10]);
    };
}

macro_rules! DO_DEC_4_BLOCKS {
    ($block0:expr, $block1:expr, $block2:expr, $block3:expr, $key:expr) => {
        $block0 = _mm_xor_si128($block0, $key[10]);
        $block1 = _mm_xor_si128($block1, $key[10]);
        $block2 = _mm_xor_si128($block2, $key[10]);
        $block3 = _mm_xor_si128($block3, $key[10]);
        crate::const_loop!(i, 1, 9, {
            $block0 = _mm_aesdec_si128($block0, $key[10 + i]);
            $block1 = _mm_aesdec_si128($block1, $key[10 + i]);
            $block2 = _mm_aesdec_si128($block2, $key[10 + i]);
            $block3 = _mm_aesdec_si128($block3, $key[10 + i]);
        });
        $block0 = _mm_aesdeclast_si128($block0, $key[0]);
        $block1 = _mm_aesdeclast_si128($block1, $key[0]);
        $block2 = _mm_aesdeclast_si128($block2, $key[0]);
        $block3 = _mm_aesdeclast_si128($block3, $key[0]);
    };
}

macro_rules! DO_ENC_BLOCKS_XOR {
    (4,$blocks:expr,$texts:expr,$key:expr) => {{
        let mut block0 = unsafe { _mm_loadu_si128($blocks[0].as_ptr() as *const _) };
        let mut block1 = unsafe { _mm_loadu_si128($blocks[1].as_ptr() as *const _) };
        let mut block2 = unsafe { _mm_loadu_si128($blocks[2].as_ptr() as *const _) };
        let mut block3 = unsafe { _mm_loadu_si128($blocks[3].as_ptr() as *const _) };

        block0 = _mm_xor_si128(block0, $key[0]);
        block1 = _mm_xor_si128(block1, $key[0]);
        block2 = _mm_xor_si128(block2, $key[0]);
        block3 = _mm_xor_si128(block3, $key[0]);

        crate::const_loop!(i, 1, 9, {
            block0 = _mm_aesenc_si128(block0, $key[i]);
            block1 = _mm_aesenc_si128(block1, $key[i]);
            block2 = _mm_aesenc_si128(block2, $key[i]);
            block3 = _mm_aesenc_si128(block3, $key[i]);
        });

        block0 = _mm_aesenclast_si128(block0,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[0].as_ptr() as *const _)));
        block1 = _mm_aesenclast_si128(block1,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[1].as_ptr() as *const _)));
        block2 = _mm_aesenclast_si128(block2,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[2].as_ptr() as *const _)));
        block3 = _mm_aesenclast_si128(block3,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[3].as_ptr() as *const _)));

        unsafe {
            _mm_storeu_si128($texts[0].as_mut_ptr() as *mut _, block0);
            _mm_storeu_si128($texts[1].as_mut_ptr() as *mut _, block1);
            _mm_storeu_si128($texts[2].as_mut_ptr() as *mut _, block2);
            _mm_storeu_si128($texts[3].as_mut_ptr() as *mut _, block3);
        }
    }};
    (6,$blocks:expr,$texts:expr,$key:expr) => {{
        let mut block0 = unsafe { _mm_loadu_si128($blocks[0].as_ptr() as *const _) };
        let mut block1 = unsafe { _mm_loadu_si128($blocks[1].as_ptr() as *const _) };
        let mut block2 = unsafe { _mm_loadu_si128($blocks[2].as_ptr() as *const _) };
        let mut block3 = unsafe { _mm_loadu_si128($blocks[3].as_ptr() as *const _) };
        let mut block4 = unsafe { _mm_loadu_si128($blocks[4].as_ptr() as *const _) };
        let mut block5 = unsafe { _mm_loadu_si128($blocks[5].as_ptr() as *const _) };

        block0 = _mm_xor_si128(block0, $key[0]);
        block1 = _mm_xor_si128(block1, $key[0]);
        block2 = _mm_xor_si128(block2, $key[0]);
        block3 = _mm_xor_si128(block3, $key[0]);
        block4 = _mm_xor_si128(block4, $key[0]);
        block5 = _mm_xor_si128(block5, $key[0]);

        crate::const_loop!(i, 1, 9, {
            block0 = _mm_aesenc_si128(block0, $key[i]);
            block1 = _mm_aesenc_si128(block1, $key[i]);
            block2 = _mm_aesenc_si128(block2, $key[i]);
            block3 = _mm_aesenc_si128(block3, $key[i]);
            block4 = _mm_aesenc_si128(block4, $key[i]);
            block5 = _mm_aesenc_si128(block5, $key[i]);
        });

        block0 = _mm_aesenclast_si128(block0,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[0].as_ptr() as *const _)));
        block1 = _mm_aesenclast_si128(block1,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[1].as_ptr() as *const _)));
        block2 = _mm_aesenclast_si128(block2,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[2].as_ptr() as *const _)));
        block3 = _mm_aesenclast_si128(block3,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[3].as_ptr() as *const _)));
        block4 = _mm_aesenclast_si128(block4,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[4].as_ptr() as *const _)));
        block5 = _mm_aesenclast_si128(block5,  _mm_xor_si128($key[10], _mm_loadu_si128($texts[5].as_ptr() as *const _)));
        unsafe {
            _mm_storeu_si128($texts[0].as_mut_ptr() as *mut _, block0);
            _mm_storeu_si128($texts[1].as_mut_ptr() as *mut _, block1);
            _mm_storeu_si128($texts[2].as_mut_ptr() as *mut _, block2);
            _mm_storeu_si128($texts[3].as_mut_ptr() as *mut _, block3);
            _mm_storeu_si128($texts[4].as_mut_ptr() as *mut _, block4);
            _mm_storeu_si128($texts[5].as_mut_ptr() as *mut _, block5);
        }
    }};
}


macro_rules! key_expansion_256_1 {
    ($key:expr, $keygened:expr) => {{
        let mut key = $key;

        let tmp = _mm_shuffle_epi32($keygened, 0xff);

        let mut t = _mm_slli_si128(key, 4);
        key = _mm_xor_si128(key, t);
        t = _mm_slli_si128(t, 4);
        key = _mm_xor_si128(key, t);
        t = _mm_slli_si128(t, 4);
        key = _mm_xor_si128(key, t);

        _mm_xor_si128(key, tmp)
    }};
}

macro_rules! key_expansion_256_2 {
    ($key:expr, $keygened:expr) => {{
        let mut key = $key;

        let tmp = _mm_shuffle_epi32($keygened, 0xaa);

        let mut t = _mm_slli_si128(key, 4);
        key = _mm_xor_si128(key, t);
        t = _mm_slli_si128(t, 4);
        key = _mm_xor_si128(key, t);
        t = _mm_slli_si128(t, 4);
        key = _mm_xor_si128(key, t);

        _mm_xor_si128(key, tmp)
    }};
}

macro_rules! key_exp_256_1 {
    ($k1:expr, $k2:expr, $rcon:expr) => {{
        let keygened = _mm_aeskeygenassist_si128($k2, $rcon);
        key_expansion_256_1!($k1, keygened)
    }};
}

macro_rules! key_exp_256_2 {
    ($k2:expr, $k1_new:expr) => {{
        let keygened = _mm_aeskeygenassist_si128($k1_new, 0x00);
        key_expansion_256_2!($k2, keygened)
    }};
}

macro_rules! load_key_256 {
    ($key_schedule:expr, $key:expr) => {{
        let k0 = _mm_loadu_si128($key.as_ptr() as *const __m128i);
        let k1 = _mm_loadu_si128($key.as_ptr().add(16) as *const __m128i);

        $key_schedule[0] = k0;
        $key_schedule[1] = k1;

        $key_schedule[2] = key_exp_256_1!($key_schedule[0], $key_schedule[1], 0x01);
        $key_schedule[3] = key_exp_256_2!($key_schedule[1], $key_schedule[2]);

        $key_schedule[4] = key_exp_256_1!($key_schedule[2], $key_schedule[3], 0x02);
        $key_schedule[5] = key_exp_256_2!($key_schedule[3], $key_schedule[4]);

        $key_schedule[6] = key_exp_256_1!($key_schedule[4], $key_schedule[5], 0x04);
        $key_schedule[7] = key_exp_256_2!($key_schedule[5], $key_schedule[6]);

        $key_schedule[8] = key_exp_256_1!($key_schedule[6], $key_schedule[7], 0x08);
        $key_schedule[9] = key_exp_256_2!($key_schedule[7], $key_schedule[8]);

        $key_schedule[10] = key_exp_256_1!($key_schedule[8], $key_schedule[9], 0x10);
        $key_schedule[11] = key_exp_256_2!($key_schedule[9], $key_schedule[10]);

        $key_schedule[12] = key_exp_256_1!($key_schedule[10], $key_schedule[11], 0x20);
        $key_schedule[13] = key_exp_256_2!($key_schedule[11], $key_schedule[12]);

        $key_schedule[14] = key_exp_256_1!($key_schedule[12], $key_schedule[13], 0x40);

        // ---- decryption keys layout (15 keys) ----
        // dec[0]  = enc[14]
        // dec[i]  = aesimc(enc[14 - i]) for i=1..13
        // dec[14] = enc[0]
        $key_schedule[15] = $key_schedule[14];
        crate::const_loop!(i, 1, 13, {
            $key_schedule[15 + i] = _mm_aesimc_si128($key_schedule[14 - i]);
        });
        $key_schedule[29] = $key_schedule[0];
    }};
}

macro_rules! DO_ENC_BLOCK_256 {
    ($block:expr, $key:expr) => {
        #[allow(unused_unsafe)]
        unsafe {
            $block = _mm_xor_si128($block, $key[0]);
            crate::const_loop!(i, 1, 13, {
                $block = _mm_aesenc_si128($block, $key[i]);
            });
            $block = _mm_aesenclast_si128($block, $key[14]);
        }
    };
}

macro_rules! DO_DEC_BLOCK_256 {
    ($block:expr, $key:expr) => {
        #[allow(unused_unsafe)]
        unsafe {
            // match AES128 style: initial xor with last enc key
            $block = _mm_xor_si128($block, $key[14]);

            // 13 middle rounds use aesimc(enc[13..1]) stored at key[16..28]
            crate::const_loop!(i, 1, 13, {
                $block = _mm_aesdec_si128($block, $key[15 + i]);
            });

            $block = _mm_aesdeclast_si128($block, $key[0]);
        }
    };
}

}

pub(crate) use key_expansion_128;
pub(crate) use key_exp_128;
pub(crate) use load_key_128;
pub(crate) use load_key_128_enc;
pub(crate) use DO_ENC_BLOCK;
pub(crate) use DO_DEC_BLOCK;
pub(crate) use DO_ENC_4_BLOCKS;
pub(crate) use DO_DEC_4_BLOCKS;
pub(crate) use DO_ENC_BLOCKS_XOR;
pub(crate) use key_expansion_256_1;
pub(crate) use key_expansion_256_2;
pub(crate) use key_exp_256_1;
pub(crate) use key_exp_256_2;
pub(crate) use load_key_256;
pub(crate) use DO_ENC_BLOCK_256;
pub(crate) use DO_DEC_BLOCK_256;

#[derive(Clone, Copy)]
pub struct AES128 {
    key_schedule: [__m128i; 20],
}

#[derive(Clone, Copy)]
pub(crate) struct AES128Encryptor {
    key_schedule: [__m128i; 11],
}

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;
}

impl AES128Encryptor {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;
}

#[unsafe_target_feature("sse2,aes")]
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
    pub(crate) fn encrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
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
    pub(crate) fn decrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
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
    /// Encrypts a slice of data in place.   
    /// `data` must be a slice of 16 bytes.
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
    /// Encrypts a slice of 16 bytes.   
    /// `data` must be a slice of 16 bytes.
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

#[unsafe_target_feature("sse2,aes")]
impl AES128Encryptor {
    #[inline(always)]
    pub fn new(key: [u8; 16]) -> Self {
        let mut key_schedule = [unsafe { core::mem::zeroed() }; 11];
        unsafe {
            load_key_128_enc!(&mut key_schedule, &key);
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
    pub(crate) fn encrypt_4_blocks(
        &self,
        data0: &mut [u8; 16],
        data1: &mut [u8; 16],
        data2: &mut [u8; 16],
        data3: &mut [u8; 16],
    ) {
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
}

#[derive(Clone, Copy)]
pub struct AES256 {
    key_schedule: [__m128i; 30],
}

impl AES256 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 32;
    pub const IS_SOFT: bool = false;
}

#[unsafe_target_feature("sse2,aes")]
impl AES256 {
    #[inline(always)]
    pub fn new(key: [u8; 32]) -> Self {
        let mut key_schedule = [unsafe { core::mem::zeroed() }; 30];
        unsafe {
            load_key_256!(&mut key_schedule, &key);
        }
        Self { key_schedule }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        Self::new(unsafe { *(key.as_ptr() as *const [u8; 32]) })
    }
#[inline(always)]
    pub fn encrypt(&self, data: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_ENC_BLOCK_256!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(data.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn encrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_ENC_BLOCK_256!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn encrypt_simd(&self, mut block: __m128i) -> __m128i {
        DO_ENC_BLOCK_256!(block, self.key_schedule);
        block
    }

    #[inline(always)]
    pub fn decrypt(&self, data: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_DEC_BLOCK_256!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(data.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn decrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        let mut block = unsafe { _mm_loadu_si128(data.as_ptr() as *const __m128i) };
        DO_DEC_BLOCK_256!(block, self.key_schedule);
        unsafe { _mm_storeu_si128(output.as_mut_ptr() as *mut __m128i, block) };
    }

    #[inline(always)]
    pub fn decrypt_simd(&self, mut block: __m128i) -> __m128i {
        DO_DEC_BLOCK_256!(block, self.key_schedule);
        block
    }

    #[inline(always)]
    pub(crate) fn encrypt_4_blocks_xor(&self, data: [&[u8; 16]; 4], text: [&mut [u8; 16]; 4]) {
        unsafe {
            let mut block0 = _mm_loadu_si128(data[0].as_ptr() as *const __m128i);
            let mut block1 = _mm_loadu_si128(data[1].as_ptr() as *const __m128i);
            let mut block2 = _mm_loadu_si128(data[2].as_ptr() as *const __m128i);
            let mut block3 = _mm_loadu_si128(data[3].as_ptr() as *const __m128i);

            DO_ENC_BLOCK_256!(block0, self.key_schedule);
            DO_ENC_BLOCK_256!(block1, self.key_schedule);
            DO_ENC_BLOCK_256!(block2, self.key_schedule);
            DO_ENC_BLOCK_256!(block3, self.key_schedule);

            block0 = _mm_xor_si128(block0, _mm_loadu_si128(text[0].as_ptr() as *const __m128i));
            block1 = _mm_xor_si128(block1, _mm_loadu_si128(text[1].as_ptr() as *const __m128i));
            block2 = _mm_xor_si128(block2, _mm_loadu_si128(text[2].as_ptr() as *const __m128i));
            block3 = _mm_xor_si128(block3, _mm_loadu_si128(text[3].as_ptr() as *const __m128i));

            _mm_storeu_si128(text[0].as_mut_ptr() as *mut __m128i, block0);
            _mm_storeu_si128(text[1].as_mut_ptr() as *mut __m128i, block1);
            _mm_storeu_si128(text[2].as_mut_ptr() as *mut __m128i, block2);
            _mm_storeu_si128(text[3].as_mut_ptr() as *mut __m128i, block3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128() {
        if !crate::is_hw_feature_detected!("sse2", "aes") {
            return;
        }
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let cipher = AES128::new(key);

        let mut data = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        cipher.encrypt(&mut data);
        assert_eq!(data, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);

        let mut data = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        cipher.decrypt(&mut data);
        assert_eq!(data, [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]);
    }

    #[test]
    fn test_aes256() {
        if !crate::is_hw_feature_detected!("sse2", "aes") {
            return;
        }
        aes256_test_case!();
    }
}