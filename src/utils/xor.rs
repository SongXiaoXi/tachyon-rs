use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2"))] {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        #[inline(always)]
        pub fn xor_si128_inplace_sse2(a: &mut [u8; 16], b: &[u8; 16]) {
            unsafe {
                let mut c = _mm_loadu_si128(a.as_ptr() as *const __m128i);
                let d = _mm_loadu_si128(b.as_ptr() as *const __m128i);
                c = _mm_xor_si128(c, d);
                _mm_storeu_si128(a.as_mut_ptr() as *mut __m128i, c);
            }
        }

        #[cfg(target_feature = "sse2")]
        #[inline]
        pub fn xor_si128_inplace(a: &mut [u8; 16], b: &[u8; 16]) {
            xor_si128_inplace_sse2(a, b)
        }
        /*
        #[cfg(not(target_feature = "sse2"))]
        #[inline]
        pub fn xor_si128_inplace(a: &mut [u8; 16], b: &[u8; 16]) {
            if crate::is_hw_feature_available!(
                "x86" => ("sse2"),
                "x86_64" => ("sse2")
            ) {
                xor_si128_inplace_sse2(a, b)
            } else {
                xor_si128_inplace_generic(a, b)
            }
        }
        */
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "neon"))] {
        #[cfg(target_arch = "aarch64")]
        use core::arch::aarch64::*;
        #[cfg(target_arch = "arm")]
        use core::arch::arm::*;
        #[inline(always)]
        pub fn xor_si128_inplace(a: &mut [u8; 16], b: &[u8; 16]) {
            unsafe {
                let mut c = vld1q_u8(a.as_ptr());
                let d = vld1q_u8(b.as_ptr());
                c = veorq_u8(c, d);
                vst1q_u8(a.as_mut_ptr(), c);
            }
        }
    } else {
        #[inline(always)]
        pub fn xor_si128_inplace(a: &mut [u8; 16], b: &[u8; 16]) {
            xor_si128_inplace_generic(a, b)
        }
    }

}

#[allow(dead_code)]
#[inline(always)]
fn xor_si128_inplace_generic(a: &mut [u8; 16], b: &[u8; 16]) {
    crate::const_loop!(i, 0, 16, {
        a[i] ^= b[i]
    });
}