#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[allow(unused_imports)]
use super::x86::gf_mul;

#[derive(Clone, Copy)]
pub struct GHash {
    buf: __m128i,
    key: [__m128i; 16], // 16 - 1
    fold_key: [__m128i; 16], // 16 - 1
}

use super::x86::gf_mul_prepare_k;
use super::x86::gf_mul_no_reduce;
use super::x86::fold_key;

/// Horizontal XOR for 4x128-bit vectors
#[inline(always)]
pub(crate) unsafe fn _mm512_hxori128x4_epi128(a: __m512i) -> __m128i {
    
    // let tmp = _mm512_extracti64x4_epi64(a, 1);
    // let a = _mm256_xor_si256(_mm512_castsi512_si256(a), tmp);
    // let tmp = _mm256_extracti32x4_epi32(a, 1);
    // _mm_xor_si128(_mm256_castsi256_si128(a), tmp)
    
    let a0 = _mm512_castsi512_si128(a);
    let a1 = _mm512_extracti32x4_epi32(a, 1);
    let a2 = _mm512_extracti32x4_epi32(a, 2);
    let a3 = _mm512_extracti32x4_epi32(a, 3);

    _mm_xor3_si128(
        _mm_xor_si128(a0, a1),
        a2,
        a3,
    )
}

#[inline(always)]
pub(crate) unsafe fn _mm512_xor3_si512(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
    _mm512_ternarylogic_epi64(a, b, c, 0x96) // 3-way xor
}

#[inline(always)]
pub(crate) unsafe fn _mm_xor3_si128(a: __m128i, b: __m128i, c: __m128i) -> __m128i {
    _mm_ternarylogic_epi64(a, b, c, 0x96) // 3-way xor
}

#[inline(always)]
pub(crate) unsafe fn _mm512_or3_si512(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
    _mm512_ternarylogic_epi64(a, b, c, 0xfe) // 3-way or
}

#[macro_use]
mod macros {
#[allow(unused_macros)]
macro_rules! gf_mul_x4 {
    ($a:expr, $b:expr) => {{
        let a = $a;
        let b = $b;

        let mut tmp2: __m512i;
        let mut tmp3: __m512i;
        let mut tmp4: __m512i;
        let mut tmp5: __m512i;
        let mut tmp6: __m512i;
        let mut tmp7: __m512i;
        let mut tmp8: __m512i;
        let mut tmp9: __m512i;

        tmp3 = _mm512_clmulepi64_epi128(a, b, 0x00);
        tmp4 = _mm512_clmulepi64_epi128(a, b, 0x10);
        tmp5 = _mm512_clmulepi64_epi128(a, b, 0x01);
        tmp6 = _mm512_clmulepi64_epi128(a, b, 0x11);
        tmp4 = _mm512_xor_si512(tmp4, tmp5);
        tmp5 = _mm512_bslli_epi128(tmp4, 8);
        tmp4 = _mm512_bsrli_epi128(tmp4, 8);
        tmp3 = _mm512_xor_si512(tmp3, tmp5); // low
        tmp6 = _mm512_xor_si512(tmp6, tmp4); // high
        tmp7 = _mm512_srli_epi32(tmp3, 31);
        tmp8 = _mm512_srli_epi32(tmp6, 31);
        tmp3 = _mm512_slli_epi32(tmp3, 1);
        tmp6 = _mm512_slli_epi32(tmp6, 1);
        tmp9 = _mm512_bsrli_epi128(tmp7, 12);
        tmp8 = _mm512_bslli_epi128(tmp8, 4);
        tmp7 = _mm512_bslli_epi128(tmp7, 4);
        tmp3 = _mm512_or_si512(tmp3, tmp7);
        tmp6 = _mm512_or3_si512(tmp6, tmp8, tmp9);
        tmp7 = _mm512_slli_epi32(tmp3, 31);
        tmp8 = _mm512_slli_epi32(tmp3, 30);
        tmp9 = _mm512_slli_epi32(tmp3, 25);
        tmp7 = _mm512_xor3_si512(tmp7, tmp8, tmp9);
        tmp8 = _mm512_bsrli_epi128(tmp7, 4);
        tmp7 = _mm512_bslli_epi128(tmp7, 12);
        tmp3 = _mm512_xor_si512(tmp3, tmp7);
        tmp2 = _mm512_srli_epi32(tmp3, 1);
        tmp4 = _mm512_srli_epi32(tmp3, 2);
        tmp5 = _mm512_srli_epi32(tmp3, 7);
        tmp2 = _mm512_xor_si512(tmp2, tmp4);
        tmp2 = _mm512_xor3_si512(tmp2, tmp5, tmp8);
        tmp6 = _mm512_xor3_si512(tmp6, tmp3, tmp2);
        tmp6
    }}
}

macro_rules! fold_key_x4 {
    ($key:expr) => {
        {
            let key = $key;
            _mm512_xor_si512(_mm512_shuffle_epi32(key, crate::_MM_SHUFFLE(1, 0, 3, 2)), key)
            // _mm_xor_si128(_mm_srli_si128(key, 8), key)
        }
    }
}

macro_rules! gf_mul_reduce {
    ($a:expr) => {{
        let (mut r0, mut r1, r2) = $a;

        r1 = _mm_xor3_si128(r0, r1, r2);

        r0 = _mm_xor_si128(r0, _mm_slli_si128(r1, 8));

        let tmp = _mm_xor3_si128(_mm_slli_epi64(r0, 57), _mm_slli_epi64(r0, 62), _mm_slli_epi64(r0, 63));

        r0 = _mm_xor_si128(r0, _mm_slli_si128(tmp, 8));

        _mm_xor3_si128(
            _mm_xor3_si128(
                r0,
                _mm_srli_epi64(r0, 1),
                _mm_srli_epi64(r0, 2),
            ),
            _mm_xor3_si128(_mm_srli_si128(r1, 8), r2, _mm_srli_si128(tmp, 8)),
            _mm_srli_epi64(r0, 7),
        )
    }};
}

macro_rules! gf_mul_no_reduce_x4 {
    ($a:expr,$b:expr,$fold_a:expr) => {
        {
            let a = $a;
            let b = $b;
            let a_k = $fold_a;
            let t0 = _mm512_clmulepi64_epi128(a, b, 0x00);
            let t2 = _mm512_clmulepi64_epi128(a, b, 0x11);

            let fold_b = fold_key_x4!(b);
            let t1 = _mm512_clmulepi64_epi128(a_k, fold_b, 0x00);
            (t0, t1, t2)
        }
    };
}

// #[allow(unused_macros)]
// macro_rules! gf_mul_reduce_x4 {
//     ($a:expr) => {{
//         let (mut r0, mut r1, r2) = $a;

//         r1 = _mm512_xor3_si512(r0, r1, r2);

//         r0 = _mm512_xor_si512(r0, _mm512_bslli_epi128(r1, 8));

//         let tmp = _mm512_xor3_si512(_mm512_slli_epi64(r0, 57), _mm512_slli_epi64(r0, 62), _mm512_slli_epi64(r0, 63));

//         r0 = _mm512_xor_si512(r0, _mm512_bslli_epi128(tmp, 8));

//         _mm512_xor3_si512(
//             _mm512_xor3_si512(
//                 r2,
//                 _mm512_bsrli_epi128(r1, 8),
//                 _mm512_bsrli_epi128(tmp, 8)
//             ),
//             _mm512_xor3_si512(
//                 r0,
//                 _mm512_srli_epi64(r0, 1),
//                 _mm512_srli_epi64(r0, 2),
//             ),
//             _mm512_srli_epi64(r0, 7),
//         )
//     }};
// }

#[allow(unused_macros)]
macro_rules! gf_mul_reduce_x4 {
    ($a:expr) => {{
        /*
        // begin of a work basic version
        let (mut r0, mut r1, mut r2) = $a;
        r1 = _mm512_xor3_si512(r0, r1, r2);

        r2 = _mm512_xor_si512(r2, _mm512_bsrli_epi128(r1, 8));

        let mask = _mm512_broadcast_i32x4(_mm_set_epi32(0xffffffffu32 as i32, 0xffffffffu32 as i32, 0, 0));

        let poly = _mm512_set1_epi64(0xc200000000000000u64 as i64);
        let tmp0 = _mm512_clmulepi64_epi128(r0, poly, 0x00); // (a0 >> 1 ^ a0 >> 2 ^ a0 >> 7, a0 << 57, a0 << 62, a0 << 63)

        r0 = _mm512_xor_si512(r0, _mm512_bslli_epi128(r1, 8));
        let tmp1 = _mm512_clmulepi64_epi128(r0, poly, 0x11); // (a1 >> 1 ^ a1 >> 2 ^ a1 >> 7, a1 << 57, a1 << 62, a1 << 63)
        
        _mm512_xor_si512(
            _mm512_xor_si512(
                _mm512_xor3_si512(
                    r0,
                    r2,
                    tmp1,
                ),
                _mm512_shuffle_epi32(tmp0, crate::_MM_SHUFFLE(1, 0, 3, 2)),
            ),
            _mm512_and_si512(
                mask,
                _mm512_clmulepi64_epi128(tmp0, poly, 0x00),
            )
        )
        // end of a work basic version
        */

        let (mut r0, mut r1, r2) = $a;
        r1 = _mm512_xor3_si512(r0, r1, r2);

        let poly = _mm512_set1_epi64(0xc200000000000000u64 as i64);
        let tmp0 = _mm512_xor_si512(_mm512_clmulepi64_epi128(r0, poly, 0x00), r1);

        r0 = _mm512_xor_si512(r0, _mm512_shuffle_epi32(tmp0, crate::_MM_SHUFFLE(1, 0, 3, 2)));
        let tmp1 = _mm512_clmulepi64_epi128(r0, poly, 0x11);
        
        _mm512_xor3_si512(
            r0,
            r2,
            tmp1,
        )
    }};
}

}

#[inline(always)]
unsafe fn gf_mul2(a: __m128i, b: __m128i) -> __m128i {
    gf_mul_reduce!(gf_mul_no_reduce!(a, b, fold_key!(a)))
}

#[unsafe_target_feature::unsafe_target_feature("avx512f,avx512bw,avx512vl,vpclmulqdq")]
impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;

    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
        let tag = _mm_setzero_si128();
        let vm = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        let key = _mm_shuffle_epi8(_mm_loadu_si128(key.as_ptr() as _), vm);

        let key_orig = key;

        let key = gf_mul_prepare_k!(key);
        let key2 = gf_mul2(key, key_orig);
        let key3 = gf_mul2(key, key2);
        let key4 = gf_mul2(key, key3);
        let key5 = gf_mul2(key, key4);
        let key6 = gf_mul2(key, key5);
        let key7 = gf_mul2(key, key6);
        let key8 = gf_mul2(key, key7);
        let key9 = gf_mul2(key, key8);
        let key10 = gf_mul2(key, key9);
        let key11 = gf_mul2(key, key10);
        let key12 = gf_mul2(key, key11);
        let key13 = gf_mul2(key, key12);
        let key14 = gf_mul2(key, key13);
        let key15 = gf_mul2(key, key14);
        let key16 = gf_mul2(key, key15);

        let key2 = gf_mul_prepare_k!(key2);
        let key3 = gf_mul_prepare_k!(key3);
        let key4 = gf_mul_prepare_k!(key4);
        let key5 = gf_mul_prepare_k!(key5);
        let key6 = gf_mul_prepare_k!(key6);
        let key7 = gf_mul_prepare_k!(key7);
        let key8 = gf_mul_prepare_k!(key8);
        let key9 = gf_mul_prepare_k!(key9);
        let key10 = gf_mul_prepare_k!(key10);
        let key11 = gf_mul_prepare_k!(key11);
        let key12 = gf_mul_prepare_k!(key12);
        let key13 = gf_mul_prepare_k!(key13);
        let key14 = gf_mul_prepare_k!(key14);
        let key15 = gf_mul_prepare_k!(key15);
        let key16 = gf_mul_prepare_k!(key16);
        
        let fold_key = fold_key!(key);
        let fold_key2 = fold_key!(key2);
        let fold_key3 = fold_key!(key3);
        let fold_key4 = fold_key!(key4);
        let fold_key5 = fold_key!(key5);
        let fold_key6 = fold_key!(key6);
        let fold_key7 = fold_key!(key7);
        let fold_key8 = fold_key!(key8);
        let fold_key9 = fold_key!(key9);
        let fold_key10 = fold_key!(key10);
        let fold_key11 = fold_key!(key11);
        let fold_key12 = fold_key!(key12);
        let fold_key13 = fold_key!(key13);
        let fold_key14 = fold_key!(key14);
        let fold_key15 = fold_key!(key15);
        let fold_key16 = fold_key!(key16);

        Self {
            buf: tag,
            key: [
                key16, key15, key14, key13,
                key12, key11, key10, key9,
                key8, key7, key6, key5,
                key4, key3, key2, key,
            ],
            fold_key: [
                fold_key16, fold_key15, fold_key14, fold_key13,
                fold_key12, fold_key11, fold_key10, fold_key9,
                fold_key8, fold_key7, fold_key6, fold_key5,
                fold_key4, fold_key3, fold_key2, fold_key,
            ],
        }
    }

    #[inline]
    unsafe fn gf_mul_buf(&mut self, mut b: __m128i) {
        let vm = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        b = _mm_shuffle_epi8(b, vm);
        b = _mm_xor_si128(b, self.buf);
        self.buf = gf_mul2(self.key[self.key.len() - 1], b);
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

            let ret0 = gf_mul_no_reduce!(self.key[self.key.len() - 4], m0, self.fold_key[self.fold_key.len() - 4]);
            let ret1 = gf_mul_no_reduce!(self.key[self.key.len() - 3], m1, self.fold_key[self.fold_key.len() - 3]);
            let ret2 = gf_mul_no_reduce!(self.key[self.key.len() - 2], m2, self.fold_key[self.fold_key.len() - 2]);
            let ret3 = gf_mul_no_reduce!(self.key[self.key.len() - 1], m3, self.fold_key[self.fold_key.len() - 1]);

            let ret_0 = _mm_xor_si128(_mm_xor3_si128(ret0.0, ret1.0, ret2.0), ret3.0);
            let ret_1 = _mm_xor_si128(_mm_xor3_si128(ret0.1, ret1.1, ret2.1), ret3.1);
            let ret_2 = _mm_xor_si128(_mm_xor3_si128(ret0.2, ret1.2, ret2.2), ret3.2);

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

            let ret0 = gf_mul_no_reduce!(self.key[self.key.len() - 6], m0, self.fold_key[self.fold_key.len() - 6]);
            let ret1 = gf_mul_no_reduce!(self.key[self.key.len() - 5], m1, self.fold_key[self.fold_key.len() - 5]);
            let ret2 = gf_mul_no_reduce!(self.key[self.key.len() - 4], m2, self.fold_key[self.fold_key.len() - 4]);
            let ret3 = gf_mul_no_reduce!(self.key[self.key.len() - 3], m3, self.fold_key[self.fold_key.len() - 3]);
            let ret4 = gf_mul_no_reduce!(self.key[self.key.len() - 2], m4, self.fold_key[self.fold_key.len() - 2]);
            let ret5 = gf_mul_no_reduce!(self.key[self.key.len() - 1], m5, self.fold_key[self.fold_key.len() - 1]);

            let ret_0 = _mm_xor_si128(_mm_xor3_si128(ret0.0, ret1.0, ret2.0), _mm_xor3_si128(ret3.0, ret4.0, ret5.0));
            let ret_1 = _mm_xor_si128(_mm_xor3_si128(ret0.1, ret1.1, ret2.1), _mm_xor3_si128(ret3.1, ret4.1, ret5.1));
            let ret_2 = _mm_xor_si128(_mm_xor3_si128(ret0.2, ret1.2, ret2.2), _mm_xor3_si128(ret3.2, ret4.2, ret5.2));

            self.buf = gf_mul_reduce!((ret_0, ret_1, ret_2));
        }
    }

    #[inline]
    pub(crate) fn update_blocks_4x4(&mut self, m: &[[u8; 64]; 4]) {
        unsafe {
            let shuf_lane_x4 = _mm512_broadcast_i32x4(_mm_set_epi8(
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, 11, 12, 13, 14, 15,
            ));
            let m0 = _mm512_loadu_si512(m[0].as_ptr() as _);
            let m1 = _mm512_loadu_si512(m[1].as_ptr() as _);
            let m2 = _mm512_loadu_si512(m[2].as_ptr() as _);
            let m3 = _mm512_loadu_si512(m[3].as_ptr() as _);
            let m0 = _mm512_xor_si512(_mm512_shuffle_epi8(m0, shuf_lane_x4), _mm512_zextsi128_si512(self.buf));
            let m1 = _mm512_shuffle_epi8(m1, shuf_lane_x4);
            let m2 = _mm512_shuffle_epi8(m2, shuf_lane_x4);
            let m3 = _mm512_shuffle_epi8(m3, shuf_lane_x4);

            let ret0 = gf_mul_no_reduce_x4!(_mm512_loadu_si512(self.key.as_ptr().add(0) as _), m0, _mm512_loadu_si512(self.fold_key.as_ptr().add(0) as _));
            let ret1 = gf_mul_no_reduce_x4!(_mm512_loadu_si512(self.key.as_ptr().add(4) as _), m1, _mm512_loadu_si512(self.fold_key.as_ptr().add(4) as _));
            let ret2 = gf_mul_no_reduce_x4!(_mm512_loadu_si512(self.key.as_ptr().add(8) as _), m2, _mm512_loadu_si512(self.fold_key.as_ptr().add(8) as _));
            let ret3 = gf_mul_no_reduce_x4!(_mm512_loadu_si512(self.key.as_ptr().add(12) as _), m3, _mm512_loadu_si512(self.fold_key.as_ptr().add(12) as _));

            let ret_0 = _mm512_xor3_si512(_mm512_xor_si512(ret0.0, ret1.0), ret2.0, ret3.0);
            let ret_1 = _mm512_xor3_si512(_mm512_xor_si512(ret0.1, ret1.1), ret2.1, ret3.1);
            let ret_2 = _mm512_xor3_si512(_mm512_xor_si512(ret0.2, ret1.2), ret2.2, ret3.2);

            self.buf = _mm512_hxori128x4_epi128(gf_mul_reduce_x4!((ret_0, ret_1, ret_2)));
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
        if !crate::is_hw_feature_detected!("avx512f", "avx512bw", "avx512vl", "vpclmulqdq") {
            return;
        }
        ghash_test_case!();
    }

    #[test]
    fn test_clmul_x4() {
        if !crate::is_hw_feature_detected!("avx512f", "vpclmulqdq") {
            return;
        }
        use rand::Rng;
        let mut rng = rand::rng();
        let mut a_arr = [0u8; 64];
        let mut b_arr = [0u8; 64];
        rng.fill(&mut a_arr[..]);
        rng.fill(&mut b_arr[..]);
        unsafe {
            let a0 = _mm_loadu_si128(a_arr.as_ptr().add(0) as _);
            let b0 = _mm_loadu_si128(b_arr.as_ptr().add(0) as _);
            let a1 = _mm_loadu_si128(a_arr.as_ptr().add(16) as _);
            let b1 = _mm_loadu_si128(b_arr.as_ptr().add(16) as _);
            let a2 = _mm_loadu_si128(a_arr.as_ptr().add(32) as _);
            let b2 = _mm_loadu_si128(b_arr.as_ptr().add(32) as _);
            let a3 = _mm_loadu_si128(a_arr.as_ptr().add(48) as _);
            let b3 = _mm_loadu_si128(b_arr.as_ptr().add(48) as _);

            let c0 = gf_mul!(a0, b0);
            let c1 = gf_mul!(a1, b1);
            let c2 = gf_mul!(a2, b2);
            let c3 = gf_mul!(a3, b3);

            let mut expected_arr = [0u8; 64];
            _mm_storeu_si128(expected_arr.as_mut_ptr().add(0) as _, c0);
            _mm_storeu_si128(expected_arr.as_mut_ptr().add(16) as _, c1);
            _mm_storeu_si128(expected_arr.as_mut_ptr().add(32) as _, c2);
            _mm_storeu_si128(expected_arr.as_mut_ptr().add(48) as _, c3);

            let a = _mm512_loadu_si512(a_arr.as_ptr() as _);
            let b = _mm512_loadu_si512(b_arr.as_ptr() as _);

            let c = gf_mul_x4!(a, b);
            let mut c_arr = [0u8; 64];
            _mm512_storeu_si512(c_arr.as_mut_ptr() as _, c);

            assert_eq!(c_arr, expected_arr, "AVX512 4-way GF multiplication failed");
        }
    }
}