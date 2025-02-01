#[cfg(all(target_arch = "arm", target_feature = "neon"))]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
unsafe fn uppercase_bytes(mut ptr: *mut i8, mut len: usize) {
    while len > 0 {
        *ptr = (*ptr as u8 as char).to_ascii_uppercase() as i8;
        ptr = ptr.add(1);
        len -= 1;
    }
}

#[inline]
fn uppercase_general(mut s: String) -> String {
    unsafe {
        let ptr = s.as_mut_ptr() as *mut i8;
        let len = s.len();
        uppercase_bytes(ptr, len);
    }
    s
}

#[cfg(target_feature = "sse2")]
#[inline]
unsafe fn uppercase_sse2(mut s: String) -> String {
    let mut ptr = s.as_mut_ptr() as *mut i8;
    let mut len = s.len();

    let ascii_a = _mm_set1_epi8(b'a' as i8 - 1);
    let ascii_z = _mm_set1_epi8(b'z' as i8 + 1);
    let add = _mm_set1_epi8(b'a' as i8 - b'A' as i8);

    const BLOCK_SIZE: usize = std::mem::size_of::<__m128i>();

    while len >= BLOCK_SIZE {
        let inp = _mm_loadu_si128(ptr as _);
        let ge_a = _mm_cmpgt_epi8(inp,  ascii_a);
        let le_z = _mm_cmplt_epi8(inp, ascii_z);
        let mask = _mm_and_si128(ge_a, le_z);
        let to_add = _mm_and_si128(mask, add);
        let added = _mm_sub_epi8(inp, to_add);
        _mm_storeu_si128(ptr as _, added);
        ptr = ptr.add(BLOCK_SIZE);
        len -= BLOCK_SIZE;
    }
    uppercase_bytes(ptr, len);
    s
}

#[cfg(target_feature = "avx2")]
#[inline]
unsafe fn uppercase_avx2(mut s: String) -> String {
    let mut ptr = s.as_mut_ptr() as *mut i8;
    let mut len = s.len();

    let ascii_a = _mm256_set1_epi8(b'a' as i8 - 1);
    let ascii_z = _mm256_set1_epi8(b'z' as i8 + 1);
    let add = _mm256_set1_epi8(b'a' as i8 - b'A' as i8);

    const BLOCK_SIZE: usize = std::mem::size_of::<__m256i>();

    while len >= BLOCK_SIZE {
        let c = _mm256_loadu_si256(ptr as _);
        let ge_a = _mm256_cmpgt_epi8(c, ascii_a);
        let le_z = _mm256_cmpgt_epi8(ascii_z, c);
        let mask = _mm256_and_si256(ge_a, le_z);
        let to_add = _mm256_and_si256(mask, add);
        let added = _mm256_sub_epi8(c, to_add);
        _mm256_storeu_si256(ptr as _, added);
        ptr = ptr.add(BLOCK_SIZE);
        len -= BLOCK_SIZE;
    }
    uppercase_bytes(ptr, len);
    s
}

#[cfg(target_feature = "avx512f")]
#[inline]
unsafe fn uppercase_avx512(mut s: String) -> String {
    let mut ptr = s.as_mut_ptr() as *mut i8;
    let mut len = s.len();

    let ascii_a = _mm512_set1_epi8(b'a' as i8);
    let ascii_z = _mm512_set1_epi8(b'z' as i8);
    let add = _mm512_set1_epi8(b'a' as i8 - b'A' as i8);

    const BLOCK_SIZE: usize = std::mem::size_of::<__m512i>();

    while len >= BLOCK_SIZE {
        let c = _mm512_loadu_epi8(ptr as _);
        let ge_a = _mm512_cmpge_epi8_mask(c, ascii_a);
        let le_z = _mm512_cmple_epi8_mask(c, ascii_z);
        let is_upper = _kand_mask64(ge_a, le_z);
        let result = _mm512_mask_sub_epi8(c, is_upper, c, add);
        _mm512_storeu_epi8(ptr, result);
        ptr = ptr.add(BLOCK_SIZE);
        len -= BLOCK_SIZE;
    }
    uppercase_bytes(ptr, len);
    s
}

#[cfg(target_feature = "neon")]
#[inline]
unsafe fn uppercase_neon(mut s: String) -> String {
    let mut ptr = s.as_mut_ptr();
    let mut len = s.len();

    let ascii_a = vdupq_n_u8(b'a');
    let ascii_z = vdupq_n_u8(b'z');
    let add = vdupq_n_u8(b'a' - b'A');

    const BLOCK_SIZE: usize = std::mem::size_of::<uint8x16_t>();

    while len >= BLOCK_SIZE {
        let inp = vld1q_u8(ptr);
        let greater_than_a = vcgeq_u8(inp,  ascii_a);
        let less_equal_z = vcleq_u8(inp, ascii_z);
        let mask = vandq_u8(greater_than_a, less_equal_z);
        let to_add = vandq_u8(mask, add);
        let added = vsubq_u8(inp, to_add);
        vst1q_u8(ptr as _, added);
        ptr = ptr.add(BLOCK_SIZE);
        len -= BLOCK_SIZE;
    }
    uppercase_bytes(ptr as _, len);
    s
}

#[allow(unreachable_code)]
pub fn uppercase(s: String) -> String {
    #[cfg(target_feature = "avx2")]
    unsafe {
        return uppercase_avx2(s);
    }
    #[cfg(target_feature = "sse2")]
    unsafe {
        return uppercase_sse2(s);
    }
    #[cfg(target_feature = "neon")]
    unsafe {
        return uppercase_neon(s);
    }
    uppercase_general(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uppercase() {
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".to_string();
        let gen = uppercase_general(s.clone());
        let l = uppercase(s);
        assert_eq!(gen, l);
    }
}