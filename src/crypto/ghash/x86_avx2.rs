#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::x86::*;

macro_rules! gf_mul_reduce {
    ($a:expr) => {{
        let (mut r0, mut r1, r2) = $a;
        r1 = _mm_xor_si128(r0, _mm_xor_si128(r1, r2));

        let poly = _mm_set1_epi64x(0xc200000000000000u64 as i64);
        let tmp0 = _mm_xor_si128(_mm_clmulepi64_si128(r0, poly, 0x00), r1);

        r0 = _mm_xor_si128(_mm_shuffle_epi32(r0, crate::_MM_SHUFFLE(1, 0, 3, 2)), tmp0);
        let tmp1 = _mm_clmulepi64_si128(r0, poly, 0x10);
        
        _mm_xor_si128(
            _mm_xor_si128(
                _mm_shuffle_epi32(r0, crate::_MM_SHUFFLE(1, 0, 3, 2)),
                r2,
            ),
            tmp1,
        )
    }};
}

x86_ghash_128_impl!("avx2,pclmulqdq,bmi1,bmi2,movbe");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ghash() {
        if !crate::is_hw_feature_detected!("avx2", "bmi2", "movbe", "pclmulqdq") {
            return;
        }
        ghash_test_case!();
    }
}