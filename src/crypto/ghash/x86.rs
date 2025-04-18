use crate::_MM_SHUFFLE;
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
    fold_key: __m128i,
    fold_key2: __m128i,
    fold_key3: __m128i,
    fold_key4: __m128i,
}

#[macro_use]
mod macros {
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

/// Multiply four elements and reduce them modulo the irreducible polynomial
/// 
/// # Safety
/// requires target_feature="sse2,ssse3,pclmulqdq"
macro_rules! gf_mul_reduce_4 {
    (
        $x1:expr, $x2:expr, $x3:expr, $x4:expr,
        $h1:expr, $h2:expr, $h3:expr, $h4:expr,
        $fold_key:expr, $fold_key2:expr, $fold_key3:expr, $fold_key4:expr$(,)?
    ) => {
        {
            let (h1_x1_lo, h1_x1_hi);
        let (h2_x2_lo, h2_x2_hi);
        let (h3_x3_lo, h3_x3_hi);
        let (h4_x4_lo, h4_x4_hi);
        let (mut lo, mut hi);
        let (mut tmp0, mut tmp1, mut tmp2, mut tmp3, mut tmp4, mut tmp5, mut tmp6, mut tmp7, mut tmp8, mut tmp9);

        h1_x1_lo = _mm_clmulepi64_si128($h1, $x1, 0x00);
        h2_x2_lo = _mm_clmulepi64_si128($h2, $x2, 0x00);
        h3_x3_lo = _mm_clmulepi64_si128($h3, $x3, 0x00);
        h4_x4_lo = _mm_clmulepi64_si128($h4, $x4, 0x00);

        lo = _mm_xor_si128(h1_x1_lo, h2_x2_lo);
        lo = _mm_xor_si128(lo, h3_x3_lo);
        lo = _mm_xor_si128(lo, h4_x4_lo);

        h1_x1_hi = _mm_clmulepi64_si128($h1, $x1, 0x11);
        h2_x2_hi = _mm_clmulepi64_si128($h2, $x2, 0x11);
        h3_x3_hi = _mm_clmulepi64_si128($h3, $x3, 0x11);
        h4_x4_hi = _mm_clmulepi64_si128($h4, $x4, 0x11);

        hi = _mm_xor_si128(h1_x1_hi, h2_x2_hi);
        hi = _mm_xor_si128(hi, h3_x3_hi);
        hi = _mm_xor_si128(hi, h4_x4_hi);

        tmp0 = $fold_key;
        tmp4 = _mm_xor_si128(_mm_shuffle_epi32($x1, crate::_MM_SHUFFLE(1, 0, 3, 2)), $x1);
        tmp1 = $fold_key2;
        tmp5 = _mm_xor_si128(_mm_shuffle_epi32($x2, crate::_MM_SHUFFLE(1, 0, 3, 2)), $x2);
        tmp2 = $fold_key3;
        tmp6 = _mm_xor_si128(_mm_shuffle_epi32($x3, crate::_MM_SHUFFLE(1, 0, 3, 2)), $x3);
        tmp3 = $fold_key4;
        tmp7 = _mm_xor_si128(_mm_shuffle_epi32($x4, crate::_MM_SHUFFLE(1, 0, 3, 2)), $x4);

        tmp0 = _mm_clmulepi64_si128(tmp0, tmp4, 0x00);
        tmp1 = _mm_clmulepi64_si128(tmp1, tmp5, 0x00);
        tmp2 = _mm_clmulepi64_si128(tmp2, tmp6, 0x00);
        tmp3 = _mm_clmulepi64_si128(tmp3, tmp7, 0x00);

        tmp0 = _mm_xor_si128(tmp0, tmp1);
        tmp0 = _mm_xor_si128(tmp0, tmp2);
        tmp0 = _mm_xor_si128(tmp0, tmp3);
        tmp0 = _mm_xor_si128(tmp0, _mm_xor_si128(lo, hi));

        tmp4 = _mm_slli_si128(tmp0, 8);
        tmp0 = _mm_srli_si128(tmp0, 8);

        lo = _mm_xor_si128(tmp4, lo);
        hi = _mm_xor_si128(tmp0, hi);

        tmp3 = lo;
        tmp6 = hi;

        tmp7 = _mm_srli_epi32(tmp3, 31);
        tmp8 = _mm_srli_epi32(tmp6, 31);
        tmp3 = _mm_slli_epi32(tmp3, 1);
        tmp6 = _mm_slli_epi32(tmp6, 1);

        tmp9 = _mm_alignr_epi8(tmp8, tmp7, 12);
        tmp7 = _mm_slli_si128(tmp7, 4);
        tmp3 = _mm_or_si128(tmp3, tmp7);
        tmp6 = _mm_or_si128(tmp6, tmp9);

        tmp7 = _mm_slli_epi32(tmp3, 31);
        tmp8 = _mm_slli_epi32(tmp3, 30);
        tmp9 = _mm_slli_epi32(tmp3, 25);

        tmp7 = _mm_xor_si128(tmp7, _mm_xor_si128(tmp8, tmp9));
        tmp8 = tmp7;
        tmp9 = tmp3;
        tmp7 = _mm_slli_si128(tmp7, 12);
        tmp3 = _mm_xor_si128(tmp3, tmp7);

        tmp2 = _mm_srli_epi32(tmp3, 1);
        tmp4 = _mm_srli_epi32(tmp3, 2);
        tmp5 = _mm_srli_epi32(tmp3, 7);
        tmp3 = _mm_xor_si128(tmp9, _mm_alignr_epi8(tmp8, tmp8, 4));
        tmp2 = _mm_xor_si128(tmp2, _mm_xor_si128(tmp4, tmp5));
        _mm_xor_si128(tmp2, _mm_xor_si128(tmp3, tmp6))
        }
    }
}
}

pub(crate) use gf_mul;
pub(crate) use gf_mul_reduce_4;

#[unsafe_target_feature("sse2,ssse3,pclmulqdq")]
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

        let key2 = Self::gf_mul(key, key);
        let key3 = Self::gf_mul(key2, key);
        let key4 = Self::gf_mul(key2, key2);

        let fold_key = _mm_xor_si128(_mm_shuffle_epi32(key, _MM_SHUFFLE(1, 0, 3, 2)), key);
        let fold_key2 = _mm_xor_si128(_mm_shuffle_epi32(key2, _MM_SHUFFLE(1, 0, 3, 2)), key2);
        let fold_key3 = _mm_xor_si128(_mm_shuffle_epi32(key3, _MM_SHUFFLE(1, 0, 3, 2)), key3);
        let fold_key4 = _mm_xor_si128(_mm_shuffle_epi32(key4, _MM_SHUFFLE(1, 0, 3, 2)), key4);
        

        Self { key, buf: tag, key2, key3, key4, fold_key, fold_key2, fold_key3, fold_key4 }
    }

    #[inline]
    unsafe fn gf_mul_buf(&mut self, mut b: __m128i) {
        let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        b = _mm_shuffle_epi8(b, vm);
        b = _mm_xor_si128(b, self.buf);
        self.buf = Self::gf_mul(self.key, b);
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
            last_block[..rlen].copy_from_slice(rem);
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
            let m0 = _mm_shuffle_epi8(m0, vm);
            let m1 = _mm_shuffle_epi8(m1, vm);
            let m2 = _mm_shuffle_epi8(m2, vm);
            let m3 = _mm_shuffle_epi8(m3, vm);
            self.buf = gf_mul_reduce_4!(
                _mm_xor_si128(m0, self.buf), m1, m2, m3,
                self.key4, self.key3, self.key2, self.key,
                self.fold_key4, self.fold_key3, self.fold_key2, self.fold_key
            );
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
        if !(std::is_x86_feature_detected!("pclmulqdq") && std::is_x86_feature_detected!("sse2") && std::is_x86_feature_detected!("ssse3")) {
            return;
        }
        ghash_test_case!();
    }
}