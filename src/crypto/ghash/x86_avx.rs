#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct GHash {
    key: __m128i,
    buf: __m128i,
    key2: __m128i,
    key3: __m128i,
    key4: __m128i,
    key5: __m128i,
    key6: __m128i,
    fold_key: __m128i,
    fold_key2: __m128i,
    fold_key3: __m128i,
    fold_key4: __m128i,
    fold_key5: __m128i,
    fold_key6: __m128i,
}

use super::x86::gf_mul;
use super::x86::gf_mul_prepare_k;
use super::x86::gf_mul_without_modular;
use super::x86::gf_mul_modular;
use super::x86::fold_key;

#[inline(always)]
unsafe fn gf_mul2(a: __m128i, b: __m128i) -> __m128i {
    gf_mul_modular!(gf_mul_without_modular!(a, b, fold_key!(a)))
}

#[unsafe_target_feature("avx,pclmulqdq")]
impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;

    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
        let key = key.clone();

        let tag = _mm_setzero_si128();
        let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let key = _mm_shuffle_epi8(_mm_loadu_si128(key.as_ptr() as *const __m128i), vm);

        let key_orig = key;

        let key = gf_mul_prepare_k!(key);
        let key2 = gf_mul2(key, key_orig);
        let key3 = gf_mul2(key, key2);
        let key4 = gf_mul2(key, key3);
        let key5 = gf_mul2(key, key4);
        let key6 = gf_mul2(key, key5);

        let key2 = gf_mul_prepare_k!(key2);
        let key3 = gf_mul_prepare_k!(key3);
        let key4 = gf_mul_prepare_k!(key4);
        let key5 = gf_mul_prepare_k!(key5);
        let key6 = gf_mul_prepare_k!(key6);
        
        let fold_key = fold_key!(key);
        let fold_key2 = fold_key!(key2);
        let fold_key3 = fold_key!(key3);
        let fold_key4 = fold_key!(key4);
        let fold_key5 = fold_key!(key5);
        let fold_key6 = fold_key!(key6);

        Self {
            key,
            buf: tag,
            key2, key3, key4, key5, key6,
            fold_key, fold_key2, fold_key3, fold_key4, fold_key5, fold_key6
        }
    }

    #[inline]
    unsafe fn gf_mul_buf(&mut self, mut b: __m128i) {
        let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        b = _mm_shuffle_epi8(b, vm);
        b = _mm_xor_si128(b, self.buf);
        self.buf = gf_mul2(self.key, b);
    }

    #[inline]
    unsafe fn gf_mul(a: __m128i, b: __m128i) -> __m128i {
        gf_mul!(a, b)
    }

    #[inline]
    pub fn update(&mut self, m: &[u8]) {
        let mut mlen = m.len();

        let mut start = 0;
        while mlen >= Self::BLOCK_LEN {
            self.gf_mul_buf(_mm_loadu_si128(&m[start] as *const u8 as *const _));
            mlen -= Self::BLOCK_LEN;
            start += Self::BLOCK_LEN;
        }

        if mlen != 0 {
            let rem = &m[start..];
            let rlen = rem.len();

            let mut last_block = [0u8; Self::BLOCK_LEN];
            // Magic: black_box is used to prevent the compiler from using bzero
            std::hint::black_box(last_block.as_mut_ptr());
            unsafe {
                crate::utils::assume(rlen <= Self::BLOCK_LEN);

                crate::utils::copy_chunks_u8(
                    last_block.as_mut_ptr(),
                    rem.as_ptr(),
                    rlen,
                );
            }
            // last_block[..rlen].copy_from_slice(rem);
            self.gf_mul_buf(_mm_loadu_si128(last_block.as_ptr() as *const _));
        }
    }

    #[inline(always)]
    pub(crate) fn update_4block_for_aes(&mut self, m0: &[u8; 16], m1: &[u8; 16], m2: &[u8; 16], m3: &[u8; 16]) {
        unsafe {
            let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
            let m0 = _mm_loadu_si128(m0.as_ptr() as *const __m128i);
            let m1 = _mm_loadu_si128(m1.as_ptr() as *const __m128i);
            let m2 = _mm_loadu_si128(m2.as_ptr() as *const __m128i);
            let m3 = _mm_loadu_si128(m3.as_ptr() as *const __m128i);
            let m0 = _mm_xor_si128(_mm_shuffle_epi8(m0, vm), self.buf);
            let m1 = _mm_shuffle_epi8(m1, vm);
            let m2 = _mm_shuffle_epi8(m2, vm);
            let m3 = _mm_shuffle_epi8(m3, vm);

            let ret0 = gf_mul_without_modular!(self.key4, m0, self.fold_key4);
            let ret1 = gf_mul_without_modular!(self.key3, m1, self.fold_key3);
            let ret2 = gf_mul_without_modular!(self.key2, m2, self.fold_key2);
            let ret3 = gf_mul_without_modular!(self.key, m3, self.fold_key);

            let ret_0 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.0, ret1.0), ret2.0), ret3.0);
            let ret_1 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.1, ret1.1), ret2.1), ret3.1);
            let ret_2 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.2, ret1.2), ret2.2), ret3.2);

            self.buf = gf_mul_modular!((ret_0, ret_1, ret_2));
        }
    }

    #[inline]
    pub(crate) fn update_6block_for_aes(&mut self, m0: &[u8; 16], m1: &[u8; 16], m2: &[u8; 16], m3: &[u8; 16], m4: &[u8; 16], m5: &[u8; 16]) {
        unsafe {
            let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
            let m0 = _mm_loadu_si128(m0.as_ptr() as *const __m128i);
            let m1 = _mm_loadu_si128(m1.as_ptr() as *const __m128i);
            let m2 = _mm_loadu_si128(m2.as_ptr() as *const __m128i);
            let m3 = _mm_loadu_si128(m3.as_ptr() as *const __m128i);
            let m4 = _mm_loadu_si128(m4.as_ptr() as *const __m128i);
            let m5 = _mm_loadu_si128(m5.as_ptr() as *const __m128i);
            let m0 = _mm_xor_si128(_mm_shuffle_epi8(m0, vm), self.buf);
            let m1 = _mm_shuffle_epi8(m1, vm);
            let m2 = _mm_shuffle_epi8(m2, vm);
            let m3 = _mm_shuffle_epi8(m3, vm);
            let m4 = _mm_shuffle_epi8(m4, vm);
            let m5 = _mm_shuffle_epi8(m5, vm);

            let ret0 = gf_mul_without_modular!(self.key6, m0, self.fold_key6);
            let ret1 = gf_mul_without_modular!(self.key5, m1, self.fold_key5);
            let ret2 = gf_mul_without_modular!(self.key4, m2, self.fold_key4);
            let ret3 = gf_mul_without_modular!(self.key3, m3, self.fold_key3);
            let ret4 = gf_mul_without_modular!(self.key2, m4, self.fold_key2);
            let ret5 = gf_mul_without_modular!(self.key, m5, self.fold_key);

            let ret_0 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.0, ret1.0), ret2.0), ret3.0), ret4.0), ret5.0);
            let ret_1 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.1, ret1.1), ret2.1), ret3.1), ret4.1), ret5.1);
            let ret_2 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.2, ret1.2), ret2.2), ret3.2), ret4.2), ret5.2);

            self.buf = gf_mul_modular!((ret_0, ret_1, ret_2));
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; 16] {
        let mut out = [0u8; Self::TAG_LEN];

        let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        _mm_storeu_si128(
            out.as_mut_ptr() as *mut __m128i,
            _mm_shuffle_epi8(self.buf, vm),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ghash() {
        if !(std::is_x86_feature_detected!("pclmulqdq") && std::is_x86_feature_detected!("avx")) {
            return;
        }
        ghash_test_case!();
    }
}