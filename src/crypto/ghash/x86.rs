#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[macro_use]
mod macros {

/// Macro to perform Galois Field multiplication using PCLMULQDQ instruction
/// This macro takes two `__m128i` values and returns their product in Galois Field (GF(2^128)).
/// Safety: This macro assumes that target_feature `pclmulqdq` and `sse2` are enabled.
#[allow(unused_macros)]
macro_rules! gf_mul {
    ($a:expr, $b:expr) => {
        {
            let mut tmp2: __m128i;
            let mut tmp3: __m128i;
            let mut tmp4: __m128i;
            let mut tmp5: __m128i;
            let mut tmp6: __m128i;
            let mut tmp7: __m128i;
            let mut tmp8: __m128i;
            let mut tmp9: __m128i;

            tmp3 = _mm_clmulepi64_si128($a, $b, 0x00);
            tmp4 = _mm_clmulepi64_si128($a, $b, 0x10);
            tmp5 = _mm_clmulepi64_si128($a, $b, 0x01);
            tmp6 = _mm_clmulepi64_si128($a, $b, 0x11);
            tmp4 = _mm_xor_si128(tmp4, tmp5);
            tmp5 = _mm_slli_si128(tmp4, 8);
            tmp4 = _mm_srli_si128(tmp4, 8);
            tmp3 = _mm_xor_si128(tmp3, tmp5);
            tmp6 = _mm_xor_si128(tmp6, tmp4);
            tmp7 = _mm_srli_epi32(tmp3, 31);
            tmp8 = _mm_srli_epi32(tmp6, 31);
            tmp3 = _mm_slli_epi32(tmp3, 1);
            tmp6 = _mm_slli_epi32(tmp6, 1);
            tmp9 = _mm_srli_si128(tmp7, 12);
            tmp8 = _mm_slli_si128(tmp8, 4);
            tmp7 = _mm_slli_si128(tmp7, 4);
            tmp3 = _mm_or_si128(tmp3, tmp7);
            tmp6 = _mm_or_si128(tmp6, tmp8);
            tmp6 = _mm_or_si128(tmp6, tmp9);
            tmp7 = _mm_slli_epi32(tmp3, 31);
            tmp8 = _mm_slli_epi32(tmp3, 30);
            tmp9 = _mm_slli_epi32(tmp3, 25);
            tmp7 = _mm_xor_si128(tmp7, tmp8);
            tmp7 = _mm_xor_si128(tmp7, tmp9);
            tmp8 = _mm_srli_si128(tmp7, 4);
            tmp7 = _mm_slli_si128(tmp7, 12);
            tmp3 = _mm_xor_si128(tmp3, tmp7);
            tmp2 = _mm_srli_epi32(tmp3, 1);
            tmp4 = _mm_srli_epi32(tmp3, 2);
            tmp5 = _mm_srli_epi32(tmp3, 7);
            tmp2 = _mm_xor_si128(tmp2, tmp4);
            tmp2 = _mm_xor_si128(tmp2, tmp5);
            tmp2 = _mm_xor_si128(tmp2, tmp8);
            tmp3 = _mm_xor_si128(tmp3, tmp2);
            tmp6 = _mm_xor_si128(tmp6, tmp3);
            tmp6
        }
    }
}

macro_rules! gf_mul_prepare_k {
    ($key:expr) => {
        {
            let key = $key;
            let t0 = _mm_set1_epi8(0xe1u8 as i8);
            let t0_hi = _mm_slli_epi64(t0, 57);
            let t0_lo = _mm_srli_epi64(t0, 63);
            let t0 = _mm_unpacklo_epi64(t0_lo, t0_hi);

            let t1 = _mm_shuffle_epi8(key, _mm_set1_epi8(15));
            let t2 = _mm_srli_epi64(key, 63);
            let t1 = _mm_cmplt_epi8(t1, _mm_setzero_si128());
            // let r = _mm_slli_epi64(key, 1);
            let r = _mm_add_epi64(key, key);
            let t0 = _mm_and_si128(t0, t1);
            let r = _mm_xor_si128(r, _mm_slli_si128(t2, 8));
            let r = _mm_xor_si128(r, t0);
            r
        }
    }
}

macro_rules! fold_key {
    ($key:expr) => {
        {
            let key = $key;
            _mm_xor_si128(_mm_shuffle_epi32(key, crate::_MM_SHUFFLE(1, 0, 3, 2)), key)
            // _mm_xor_si128(_mm_srli_si128(key, 8), key)
        }
    }
}

macro_rules! gf_mul_no_reduce {
    ($a:expr,$b:expr,$fold_a:expr) => {
        {
            let a = $a;
            let b = $b;
            let a_k = $fold_a;
            let t0 = _mm_clmulepi64_si128(a, b, 0x00);
            let t2 = _mm_clmulepi64_si128(a, b, 0x11);

            let fold_b = fold_key!(b);
            let t1 = _mm_clmulepi64_si128(a_k, fold_b, 0x00);
            (t0, t1, t2)
        }
    };
}

macro_rules! gf_mul_reduce {
    ($a:expr) => {
        {
            let a = $a;
            let (mut r0, mut r1, mut r2) = a;

            r1 = _mm_xor_si128(r0, r1);
            r1 = _mm_xor_si128(r1, r2);

            r0 = _mm_xor_si128(r0, _mm_slli_si128(r1, 8));

            let mut tmp = _mm_slli_epi64(r0, 57);
            tmp = _mm_xor_si128(tmp, _mm_slli_epi64(r0, 62));
            tmp = _mm_xor_si128(tmp, _mm_slli_epi64(r0, 63));
            r0 = _mm_xor_si128(r0, _mm_slli_si128(tmp, 8));

            r2 = _mm_xor_si128(r2, _mm_srli_si128(_mm_xor_si128(r1, tmp), 8));

            tmp = _mm_srli_epi64(r0, 1);
            r2 = _mm_xor_si128(r2, r0);
            r0 = _mm_xor_si128(r0, tmp);
            tmp = _mm_srli_epi64(tmp, 6);
            r0 = _mm_srli_epi64(r0, 1);
            r0 = _mm_xor_si128(r0, r2);
            r0 = _mm_xor_si128(r0, tmp);
            r0
        }
    };
}

macro_rules! x86_ghash_128_impl {
    ($($feature:literal)?) => {
#[derive(Clone, Copy)]
pub struct GHash {
    buf: __m128i,
    key: __m128i,
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

$(#[unsafe_target_feature::unsafe_target_feature($feature)])?
impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;

    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
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
    pub fn update(&mut self, m: &[u8]) {
        let mut mlen = m.len();

        let mut start = 0;
        while mlen >= Self::BLOCK_LEN {
            self.gf_mul_buf(_mm_loadu_si128(m.as_ptr().add(start) as _));
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
    pub(crate) fn update_4block_for_aes(&mut self, m: [&[u8; 16]; 4]) {
        unsafe {
            let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
            let m0 = _mm_loadu_si128(m[0].as_ptr() as *const __m128i);
            let m1 = _mm_loadu_si128(m[1].as_ptr() as *const __m128i);
            let m2 = _mm_loadu_si128(m[2].as_ptr() as *const __m128i);
            let m3 = _mm_loadu_si128(m[3].as_ptr() as *const __m128i);
            let m0 = _mm_xor_si128(_mm_shuffle_epi8(m0, vm), self.buf);
            let m1 = _mm_shuffle_epi8(m1, vm);
            let m2 = _mm_shuffle_epi8(m2, vm);
            let m3 = _mm_shuffle_epi8(m3, vm);

            let ret0 = gf_mul_no_reduce!(self.key4, m0, self.fold_key4);
            let ret1 = gf_mul_no_reduce!(self.key3, m1, self.fold_key3);
            let ret2 = gf_mul_no_reduce!(self.key2, m2, self.fold_key2);
            let ret3 = gf_mul_no_reduce!(self.key, m3, self.fold_key);

            let ret_0 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.0, ret1.0), ret2.0), ret3.0);
            let ret_1 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.1, ret1.1), ret2.1), ret3.1);
            let ret_2 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.2, ret1.2), ret2.2), ret3.2);

            self.buf = gf_mul_reduce!((ret_0, ret_1, ret_2));
        }
    }

    #[inline]
    pub(crate) fn update_6block_for_aes(&mut self, m: [&[u8; 16]; 6]) {
        unsafe {
            let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
            let m0 = _mm_loadu_si128(m[0].as_ptr() as *const _);
            let m1 = _mm_loadu_si128(m[1].as_ptr() as *const _);
            let m2 = _mm_loadu_si128(m[2].as_ptr() as *const _);
            let m3 = _mm_loadu_si128(m[3].as_ptr() as *const _);
            let m4 = _mm_loadu_si128(m[4].as_ptr() as *const _);
            let m5 = _mm_loadu_si128(m[5].as_ptr() as *const _);
            let m0 = _mm_xor_si128(_mm_shuffle_epi8(m0, vm), self.buf);
            let m1 = _mm_shuffle_epi8(m1, vm);
            let m2 = _mm_shuffle_epi8(m2, vm);
            let m3 = _mm_shuffle_epi8(m3, vm);
            let m4 = _mm_shuffle_epi8(m4, vm);
            let m5 = _mm_shuffle_epi8(m5, vm);

            let ret0 = gf_mul_no_reduce!(self.key6, m0, self.fold_key6);
            let ret1 = gf_mul_no_reduce!(self.key5, m1, self.fold_key5);
            let ret2 = gf_mul_no_reduce!(self.key4, m2, self.fold_key4);
            let ret3 = gf_mul_no_reduce!(self.key3, m3, self.fold_key3);
            let ret4 = gf_mul_no_reduce!(self.key2, m4, self.fold_key2);
            let ret5 = gf_mul_no_reduce!(self.key, m5, self.fold_key);

            let ret_0 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.0, ret1.0), ret2.0), ret3.0), ret4.0), ret5.0);
            let ret_1 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.1, ret1.1), ret2.1), ret3.1), ret4.1), ret5.1);
            let ret_2 = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ret0.2, ret1.2), ret2.2), ret3.2), ret4.2), ret5.2);

            self.buf = gf_mul_reduce!((ret_0, ret_1, ret_2));
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
    }
}

}

pub(crate) use gf_mul_prepare_k;
pub(crate) use gf_mul_no_reduce;
pub(crate) use gf_mul_reduce;
pub(crate) use fold_key;
pub(crate) use x86_ghash_128_impl;
#[allow(unused_imports)]
pub(crate) use gf_mul;

#[inline(always)]
pub(crate) unsafe fn gf_mul2(a: __m128i, b: __m128i) -> __m128i {
    gf_mul_reduce!(gf_mul_no_reduce!(a, b, fold_key!(a)))
}

x86_ghash_128_impl!("sse2,ssse3,pclmulqdq");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ghash() {
        if !crate::is_hw_feature_detected!("pclmulqdq", "sse2", "ssse3") {
            return;
        }
        ghash_test_case!();
    }

    #[test]
    fn test_clmul() {
        if !crate::is_hw_feature_detected!("pclmulqdq", "sse2") {
            return;
        }
        let a = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6];
        let b = [0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        unsafe {
            let a = _mm_loadu_si128(a.as_ptr() as *const _);
            let b = _mm_loadu_si128(b.as_ptr() as *const _);
            let res = gf_mul2(gf_mul_prepare_k!(a), b);
            let expected = gf_mul!(a, b);
            let mut res_arr = [0u8; 16];
            _mm_storeu_si128(res_arr.as_mut_ptr() as *mut _, res);
            let mut expected_arr = [0u8; 16];
            _mm_storeu_si128(expected_arr.as_mut_ptr() as *mut _, expected);
            assert_eq!(res_arr, expected_arr);
        }
    }
}