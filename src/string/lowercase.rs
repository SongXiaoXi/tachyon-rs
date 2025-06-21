#[cfg(all(target_arch = "arm", target_feature = "v7"))]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn lowercase_bytes(mut ptr: *mut i8, mut len: usize) {
    while len > 0 {
        *ptr = (*ptr as u8 as char).to_ascii_lowercase() as i8;
        ptr = ptr.add(1);
        len -= 1;
    }
}

#[inline(always)]
fn lowercase_general(mut s: String) -> String {
    unsafe {
        let ptr = s.as_mut_ptr() as *mut i8;
        let len = s.len();
        lowercase_bytes(ptr, len);
    }
    s
}

#[inline(always)]
unsafe fn lowercase_ptr(mut out: *mut i8, mut in_ptr: *const i8, mut len: usize) {
    while len > 0 {
        *out = (*in_ptr as u8 as char).to_ascii_lowercase() as i8;
        out = out.add(1);
        in_ptr = in_ptr.add(1);
        len -= 1;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
#[inline]
unsafe fn lowercase_ptr_sse2(mut out: *mut i8, mut in_ptr: *const i8, mut len: usize) {
    let ascii_a = _mm_set1_epi8(b'A' as i8 - 1);
    let ascii_z = _mm_set1_epi8(b'Z' as i8 + 1);
    let add = _mm_set1_epi8(b'a' as i8 - b'A' as i8);

    while len >= 16 {
        let inp = _mm_loadu_si128(in_ptr as _);
        let ge_a = _mm_cmpgt_epi8(inp, ascii_a);
        let le_z = _mm_cmplt_epi8(inp, ascii_z);
        let mask = _mm_and_si128(ge_a, le_z);
        let to_add = _mm_and_si128(mask, add);
        let added = _mm_add_epi8(inp, to_add);
        _mm_storeu_si128(out as _, added);
        out = out.add(16);
        in_ptr = in_ptr.add(16);
        len -= 16;
    }
    lowercase_ptr(out, in_ptr, len);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn lowercase_ptr_avx2(mut out: *mut i8, mut in_ptr: *const i8, mut len: usize) {
    let ascii_a = _mm256_set1_epi8(b'A' as i8 - 1);
    let ascii_z = _mm256_set1_epi8(b'Z' as i8 + 1);

    let add = _mm256_set1_epi8(b'a' as i8 - b'A' as i8);

    while len >= 32 {
        let c = _mm256_loadu_si256(in_ptr as _);
        let ge_a = _mm256_cmpgt_epi8(c, ascii_a);
        let le_z = _mm256_cmpgt_epi8(ascii_z, c);
        let mask = _mm256_and_si256(ge_a, le_z);
        let to_add = _mm256_and_si256(mask, add);
        let added = _mm256_add_epi8(c, to_add);
        _mm256_storeu_si256(out as _, added);
        in_ptr = in_ptr.add(32);
        out = out.add(32);
        len -= 32;
    }
    lowercase_ptr(out, in_ptr, len);
}

#[cfg(all(target_feature = "avx512f", target_feature = "avx512bw"))]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn lowercase_avx512(mut s: String) -> String {
    let mut ptr = s.as_mut_ptr() as *mut i8;
    let mut len = s.len();

    let ascii_a = _mm512_set1_epi8(b'A' as i8);
    let ascii_z = _mm512_set1_epi8(b'Z' as i8);
    let add = _mm512_set1_epi8(b'a' as i8 - b'A' as i8);

    while len >= 64 {
        let c = _mm512_loadu_si512(ptr as _);
        let ge_a = _mm512_cmpge_epi8_mask(c, ascii_a);
        let le_z = _mm512_cmple_epi8_mask(c, ascii_z);
        let is_upper = _kand_mask64(ge_a, le_z);
        let result = _mm512_mask_add_epi8(c, is_upper, c, add);
        _mm512_storeu_si512(ptr, result);
        ptr = ptr.add(64);
        len -= 64;
    }
    {
        let c = _mm512_maskz_loadu_epi8(_mm512_setzero_si512(), (1 << len) - 1, ptr);
        let ge_a = _mm512_cmpge_epi8_mask(c, ascii_a);
        let le_z = _mm512_cmple_epi8_mask(c, ascii_z);
        let is_upper = _kand_mask64(ge_a, le_z);
        let result = _mm512_mask_add_epi8(c, is_upper, c, add);
        _mm512_mask_storeu_epi8(ptr, (1 << len) - 1, result);
    }
    s
}


#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn lowercase_ptr_neon(mut out: *mut i8, mut in_ptr: *const i8, mut len: usize) {
    let ascii_a = vdupq_n_u8(b'A');
    let ascii_z = vdupq_n_u8(b'Z');
    let add = vdupq_n_u8(b'a' - b'A');

    while len >= 16 {
        let inp = vld1q_u8(in_ptr as _);
        let greater_than_a = vcgeq_u8(inp,  ascii_a);
        let less_equal_z = vcleq_u8(inp, ascii_z);
        let mask = vandq_u8(greater_than_a, less_equal_z);
        let to_add = vandq_u8(mask, add);
        let added = vaddq_u8(inp, to_add);
        vst1q_u8(out as _, added);
        in_ptr = in_ptr.add(16);
        out = out.add(16);
        len -= 16;
    }
    lowercase_ptr(out, in_ptr, len);
}


// x86: 0 - soft, 1 - sse2, 2 - avx2
// arm: 0 - soft, 1 - neon
// aarch64: 0 - neon
#[cfg(not(target_arch = "aarch64"))]
static mut CASE_IDX: u32 = u32::MAX;
#[cfg(target_arch = "aarch64")]
const CASE_IDX: u32 = 0;

#[inline]
pub(crate) fn case_idx() -> u32 {
    #[allow(unused_unsafe)]
    unsafe {
        #[cfg(not(target_arch = "aarch64"))]
        if CASE_IDX == u32::MAX {
            if crate::is_hw_feature_detected!(
                "x86" => ("avx2"),
                "x86_64" => ("avx2"),
            ) {
                CASE_IDX = 2;
            } else if crate::is_hw_feature_detected!(
                "x86" => ("sse2"),
                "x86_64" => ("sse2"),
                "arm" => ("neon"),
            ) {
                CASE_IDX = 1;
            } else {
                CASE_IDX = 0;
            }
        }
        CASE_IDX
    }
}

#[inline]
pub unsafe fn lowercase_inplace(s: &mut [u8]) {
    match case_idx() {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        2 => unsafe { lowercase_ptr_avx2(s.as_mut_ptr() as _, s.as_ptr() as _, s.len()) },
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        1 => unsafe { lowercase_ptr_sse2(s.as_mut_ptr() as _, s.as_ptr() as _, s.len()) },
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        1 => unsafe { lowercase_ptr_neon(s.as_mut_ptr() as _, s.as_ptr() as _, s.len()) },
        0 => unsafe { lowercase_bytes(s.as_mut_ptr() as _, s.len()) },
        _ => unreachable!(),
    }
}

#[inline]
pub unsafe fn lowercase_into(out: &mut [u8], input: &[u8]) {
    assert!(out.len() >= input.len(), "Output buffer must be at least as long as input buffer");
    match case_idx() {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        2 => unsafe { lowercase_ptr_avx2(out.as_mut_ptr() as _, input.as_ptr() as _, input.len()) },
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        1 => unsafe { lowercase_ptr_sse2(out.as_mut_ptr() as _, input.as_ptr() as _, input.len()) },
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        1 => unsafe { lowercase_ptr_neon(out.as_mut_ptr() as _, input.as_ptr() as _, input.len()) },
        0 => unsafe { lowercase_bytes(out.as_mut_ptr() as _, input.len()) },
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn lowercase(mut s: String) -> String {
        unsafe { lowercase_inplace(s.as_bytes_mut()); }
        s
    }

    #[test]
    fn test_lowercase() {
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".to_string();
        let s = s.repeat(1000);
        let g = lowercase_general(s.clone());
        let l = lowercase(s.clone());
        assert_eq!(g, l);

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::arch::is_x86_feature_detected!("sse2") {
                let g = lowercase_general(s.clone());
                let l = lowercase(s.clone());
                assert_eq!(g, l);
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::arch::is_x86_feature_detected!("avx2") {
                let g = lowercase_general(s.clone());
                let l = lowercase(s.clone());
                assert_eq!(g, l);
        }
        /*
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::arch::is_x86_feature_detected!("avx512f") && std::arch::is_x86_feature_detected!("avx512bw") {
            unsafe {
                let g = lowercase_general(s.clone());
                let l = lowercase_avx512(s.clone());
                assert_eq!(g, l);
            }
        }
        */

        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        if crate::is_hw_feature_detected!("neon") {
            let g = lowercase_general(s.clone());
            let l = lowercase(s.clone());
            assert_eq!(g, l);
        }
    }
}