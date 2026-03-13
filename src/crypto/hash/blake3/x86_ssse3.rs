// BLAKE3 – x86/x86_64 128-bit SIMD (SSSE3 / AVX shared implementation).

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use unsafe_target_feature::unsafe_target_feature;

macro_rules! blake3_x86_128_impl {
($feature:literal) => {

// ROR byte-shuffle tables (_mm_shuffle_epi8).
const ROT16: [u8; 16] = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13];
const ROT8: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

// Diag/undiag shuffle immediates for _mm_shuffle_epi32.
const DIAG_R1: i32 = 0x39;
const DIAG_R2: i32 = 0x4E;
const DIAG_R3: i32 = 0x93;
const UNDIAG_R1: i32 = 0x93;
const UNDIAG_R2: i32 = 0x4E;
const UNDIAG_R3: i32 = 0x39;

// ---------------------------------------------------------------------------
// Block-level: single-block compression
// ---------------------------------------------------------------------------
#[unsafe_target_feature($feature)]
impl Blake3 {
    #[inline(always)]
    fn transform_impl(
        chaining_value: &[u32; 8],
        block: &[u32; 16],
        block_len: usize,
        counter: u64,
        flags: u32,
    ) -> [u32; 16] {
        unsafe {
            let rot16_tbl = _mm_loadu_si128(ROT16.as_ptr() as *const __m128i);
            let rot8_tbl = _mm_loadu_si128(ROT8.as_ptr() as *const __m128i);

            let cv0 = _mm_loadu_si128(chaining_value.as_ptr() as *const __m128i);
            let cv1 = _mm_loadu_si128(chaining_value.as_ptr().add(4) as *const __m128i);

            let mut r0 = cv0;
            let mut r1 = cv1;
            let mut r2 = _mm_loadu_si128(super::IV.as_ptr() as *const __m128i);
            let mut r3 = _mm_set_epi32(
                flags as i32,
                block_len as i32,
                (counter >> 32) as i32,
                counter as i32,
            );

            macro_rules! ror {
                ($v:expr, 7) => {
                    _mm_or_si128(_mm_srli_epi32($v, 7), _mm_slli_epi32($v, 25))
                };
                ($v:expr, 8) => {
                    _mm_shuffle_epi8($v, rot8_tbl)
                };
                ($v:expr, 12) => {
                    _mm_or_si128(_mm_srli_epi32($v, 12), _mm_slli_epi32($v, 20))
                };
                ($v:expr, 16) => {
                    _mm_shuffle_epi8($v, rot16_tbl)
                };
            }

            // Hard-coded message schedule: load directly from the original
            // block using pre-computed indices, eliminating the scalar
            // permute! step between rounds (saves ~192 memory ops).
            macro_rules! round_s {
                ($b:expr,
                 $s0:expr,$s1:expr,$s2:expr,$s3:expr,
                 $s4:expr,$s5:expr,$s6:expr,$s7:expr,
                 $s8:expr,$s9:expr,$s10:expr,$s11:expr,
                 $s12:expr,$s13:expr,$s14:expr,$s15:expr) => {{
                    let mx_col = _mm_set_epi32(
                        $b[$s6] as i32, $b[$s4] as i32,
                        $b[$s2] as i32, $b[$s0] as i32,
                    );
                    let my_col = _mm_set_epi32(
                        $b[$s7] as i32, $b[$s5] as i32,
                        $b[$s3] as i32, $b[$s1] as i32,
                    );
                    r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), mx_col);
                    r3 = ror!(_mm_xor_si128(r3, r0), 16);
                    r2 = _mm_add_epi32(r2, r3);
                    r1 = ror!(_mm_xor_si128(r1, r2), 12);
                    r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), my_col);
                    r3 = ror!(_mm_xor_si128(r3, r0), 8);
                    r2 = _mm_add_epi32(r2, r3);
                    r1 = ror!(_mm_xor_si128(r1, r2), 7);

                    r1 = _mm_shuffle_epi32(r1, DIAG_R1);
                    r2 = _mm_shuffle_epi32(r2, DIAG_R2);
                    r3 = _mm_shuffle_epi32(r3, DIAG_R3);

                    let mx_diag = _mm_set_epi32(
                        $b[$s14] as i32, $b[$s12] as i32,
                        $b[$s10] as i32, $b[$s8] as i32,
                    );
                    let my_diag = _mm_set_epi32(
                        $b[$s15] as i32, $b[$s13] as i32,
                        $b[$s11] as i32, $b[$s9] as i32,
                    );
                    r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), mx_diag);
                    r3 = ror!(_mm_xor_si128(r3, r0), 16);
                    r2 = _mm_add_epi32(r2, r3);
                    r1 = ror!(_mm_xor_si128(r1, r2), 12);
                    r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), my_diag);
                    r3 = ror!(_mm_xor_si128(r3, r0), 8);
                    r2 = _mm_add_epi32(r2, r3);
                    r1 = ror!(_mm_xor_si128(r1, r2), 7);

                    r1 = _mm_shuffle_epi32(r1, UNDIAG_R1);
                    r2 = _mm_shuffle_epi32(r2, UNDIAG_R2);
                    r3 = _mm_shuffle_epi32(r3, UNDIAG_R3);
                }};
            }

            // BLAKE3 message schedule: each round permutes the
            // 16 message word indices.
            let b = block;
            round_s!(b, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
            round_s!(b, 2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8);
            round_s!(b, 3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1);
            round_s!(b, 10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6);
            round_s!(b, 12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4);
            round_s!(b, 9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7);
            round_s!(b, 11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13);

            r0 = _mm_xor_si128(r0, r2);
            r1 = _mm_xor_si128(r1, r3);
            r2 = _mm_xor_si128(r2, cv0);
            r3 = _mm_xor_si128(r3, cv1);

            let mut out = [0u32; 16];
            _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r0);
            _mm_storeu_si128(out.as_mut_ptr().add(4) as *mut __m128i, r1);
            _mm_storeu_si128(out.as_mut_ptr().add(8) as *mut __m128i, r2);
            _mm_storeu_si128(out.as_mut_ptr().add(12) as *mut __m128i, r3);
            out
        }
    }

    // -----------------------------------------------------------------------
    // 4-way parallel chunk hashing.
    // Each __m128i lane holds the same word index from 4 different chunks.
    // -----------------------------------------------------------------------
    #[inline(always)]
    fn hash_4_chunks_impl(
        input: &[u8; 4096],
        key: &[u32; 8],
        counter: u64,
        flags: u32,
    ) -> [[u32; 8]; 4] {
        unsafe {
            let rot16_tbl = _mm_loadu_si128(ROT16.as_ptr() as *const __m128i);
            let rot8_tbl = _mm_loadu_si128(ROT8.as_ptr() as *const __m128i);

            let p0 = input.as_ptr() as *const __m128i;
            let p1 = input.as_ptr().add(1024) as *const __m128i;
            let p2 = input.as_ptr().add(2048) as *const __m128i;
            let p3 = input.as_ptr().add(3072) as *const __m128i;

            let ctr_lo = _mm_set_epi32(
                (counter + 3) as i32,
                (counter + 2) as i32,
                (counter + 1) as i32,
                counter as i32,
            );
            let ctr_hi = _mm_set_epi32(
                ((counter + 3) >> 32) as i32,
                ((counter + 2) >> 32) as i32,
                ((counter + 1) >> 32) as i32,
                (counter >> 32) as i32,
            );

            let iv0 = _mm_set1_epi32(super::IV[0] as i32);
            let iv1 = _mm_set1_epi32(super::IV[1] as i32);
            let iv2 = _mm_set1_epi32(super::IV[2] as i32);
            let iv3 = _mm_set1_epi32(super::IV[3] as i32);
            let blen = _mm_set1_epi32(64);

            let mut h0 = _mm_set1_epi32(key[0] as i32);
            let mut h1 = _mm_set1_epi32(key[1] as i32);
            let mut h2 = _mm_set1_epi32(key[2] as i32);
            let mut h3 = _mm_set1_epi32(key[3] as i32);
            let mut h4 = _mm_set1_epi32(key[4] as i32);
            let mut h5 = _mm_set1_epi32(key[5] as i32);
            let mut h6 = _mm_set1_epi32(key[6] as i32);
            let mut h7 = _mm_set1_epi32(key[7] as i32);

            for blk in 0u32..16 {
                let bf = match blk {
                    0 => flags | super::CHUNK_START,
                    15 => flags | super::CHUNK_END,
                    _ => flags,
                };

                let (mut s0, mut s1, mut s2, mut s3) = (h0, h1, h2, h3);
                let (mut s4, mut s5, mut s6, mut s7) = (h4, h5, h6, h7);
                let (mut s8, mut s9, mut s10, mut s11) = (iv0, iv1, iv2, iv3);
                let (mut s12, mut s13, mut s14, mut s15) =
                    (ctr_lo, ctr_hi, blen, _mm_set1_epi32(bf as i32));

                // __m128i offset: each block is 16 u32 = 4 __m128i.
                let bo = blk as usize * 4;

                // Load + 4×4 transpose via unpacklo/unpackhi.
                macro_rules! t4x4 {
                    ($off:expr) => {{
                        let a = _mm_loadu_si128(p0.add(bo + $off));
                        let b = _mm_loadu_si128(p1.add(bo + $off));
                        let c = _mm_loadu_si128(p2.add(bo + $off));
                        let d = _mm_loadu_si128(p3.add(bo + $off));
                        let t0 = _mm_unpacklo_epi32(a, b);
                        let t1 = _mm_unpackhi_epi32(a, b);
                        let t2 = _mm_unpacklo_epi32(c, d);
                        let t3 = _mm_unpackhi_epi32(c, d);
                        (
                            _mm_unpacklo_epi64(t0, t2),
                            _mm_unpackhi_epi64(t0, t2),
                            _mm_unpacklo_epi64(t1, t3),
                            _mm_unpackhi_epi64(t1, t3),
                        )
                    }};
                }

                let (mut m0, mut m1, mut m2, mut m3) = t4x4!(0);
                let (mut m4, mut m5, mut m6, mut m7) = t4x4!(1);
                let (mut m8, mut m9, mut m10, mut m11) = t4x4!(2);
                let (mut m12, mut m13, mut m14, mut m15) = t4x4!(3);

                macro_rules! g4 {
                    ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {{
                        $a = _mm_add_epi32(_mm_add_epi32($a, $b), $mx);
                        $d = _mm_shuffle_epi8(_mm_xor_si128($d, $a), rot16_tbl);
                        $c = _mm_add_epi32($c, $d);
                        let xb = _mm_xor_si128($b, $c);
                        $b = _mm_or_si128(_mm_srli_epi32(xb, 12), _mm_slli_epi32(xb, 20));
                        $a = _mm_add_epi32(_mm_add_epi32($a, $b), $my);
                        $d = _mm_shuffle_epi8(_mm_xor_si128($d, $a), rot8_tbl);
                        $c = _mm_add_epi32($c, $d);
                        let xb = _mm_xor_si128($b, $c);
                        $b = _mm_or_si128(_mm_srli_epi32(xb, 7), _mm_slli_epi32(xb, 25));
                    }};
                }

                macro_rules! round4 {
                    () => {{
                        g4!(s0, s4, s8,  s12, m0,  m1);
                        g4!(s1, s5, s9,  s13, m2,  m3);
                        g4!(s2, s6, s10, s14, m4,  m5);
                        g4!(s3, s7, s11, s15, m6,  m7);
                        g4!(s0, s5, s10, s15, m8,  m9);
                        g4!(s1, s6, s11, s12, m10, m11);
                        g4!(s2, s7, s8,  s13, m12, m13);
                        g4!(s3, s4, s9,  s14, m14, m15);
                    }};
                }

                macro_rules! perm4 {
                    () => {{
                        let (t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15)
                            = (m2,m6,m3,m10,m7,m0,m4,m13,m1,m11,m12,m5,m9,m14,m15,m8);
                        m0=t0; m1=t1; m2=t2; m3=t3; m4=t4; m5=t5; m6=t6; m7=t7;
                        m8=t8; m9=t9; m10=t10; m11=t11; m12=t12; m13=t13; m14=t14; m15=t15;
                    }};
                }

                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!();

                h0 = _mm_xor_si128(s0, s8);
                h1 = _mm_xor_si128(s1, s9);
                h2 = _mm_xor_si128(s2, s10);
                h3 = _mm_xor_si128(s3, s11);
                h4 = _mm_xor_si128(s4, s12);
                h5 = _mm_xor_si128(s5, s13);
                h6 = _mm_xor_si128(s6, s14);
                h7 = _mm_xor_si128(s7, s15);
            }

            // Transpose back and extract per-chunk CVs.
            let mut t = [[0u32; 4]; 8];
            _mm_storeu_si128(t[0].as_mut_ptr() as *mut __m128i, h0);
            _mm_storeu_si128(t[1].as_mut_ptr() as *mut __m128i, h1);
            _mm_storeu_si128(t[2].as_mut_ptr() as *mut __m128i, h2);
            _mm_storeu_si128(t[3].as_mut_ptr() as *mut __m128i, h3);
            _mm_storeu_si128(t[4].as_mut_ptr() as *mut __m128i, h4);
            _mm_storeu_si128(t[5].as_mut_ptr() as *mut __m128i, h5);
            _mm_storeu_si128(t[6].as_mut_ptr() as *mut __m128i, h6);
            _mm_storeu_si128(t[7].as_mut_ptr() as *mut __m128i, h7);
            let mut out = [[0u32; 8]; 4];
            for j in 0..4 {
                out[j] = [
                    t[0][j], t[1][j], t[2][j], t[3][j],
                    t[4][j], t[5][j], t[6][j], t[7][j],
                ];
            }
            out
        }
    }
}

// Safe wrappers.
#[inline(always)]
pub(super) fn transform(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    Blake3::transform_impl(chaining_value, block, block_len, counter, flags)
}

#[inline(always)]
pub(super) unsafe fn transform_inline(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    let rot16_tbl = _mm_loadu_si128(ROT16.as_ptr() as *const __m128i);
    let rot8_tbl = _mm_loadu_si128(ROT8.as_ptr() as *const __m128i);

    let cv0 = _mm_loadu_si128(chaining_value.as_ptr() as *const __m128i);
    let cv1 = _mm_loadu_si128(chaining_value.as_ptr().add(4) as *const __m128i);

    let mut r0 = cv0;
    let mut r1 = cv1;
    let mut r2 = _mm_loadu_si128(super::IV.as_ptr() as *const __m128i);
    let mut r3 = _mm_set_epi32(
        flags as i32,
        block_len as i32,
        (counter >> 32) as i32,
        counter as i32,
    );

    macro_rules! ror {
        ($v:expr, 7) => {
            _mm_or_si128(_mm_srli_epi32($v, 7), _mm_slli_epi32($v, 25))
        };
        ($v:expr, 8) => {
            _mm_shuffle_epi8($v, rot8_tbl)
        };
        ($v:expr, 12) => {
            _mm_or_si128(_mm_srli_epi32($v, 12), _mm_slli_epi32($v, 20))
        };
        ($v:expr, 16) => {
            _mm_shuffle_epi8($v, rot16_tbl)
        };
    }

    macro_rules! round_s {
        ($b:expr,
         $s0:expr,$s1:expr,$s2:expr,$s3:expr,
         $s4:expr,$s5:expr,$s6:expr,$s7:expr,
         $s8:expr,$s9:expr,$s10:expr,$s11:expr,
         $s12:expr,$s13:expr,$s14:expr,$s15:expr) => {{
            let mx_col = _mm_set_epi32(
                $b[$s6] as i32, $b[$s4] as i32,
                $b[$s2] as i32, $b[$s0] as i32,
            );
            let my_col = _mm_set_epi32(
                $b[$s7] as i32, $b[$s5] as i32,
                $b[$s3] as i32, $b[$s1] as i32,
            );
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), mx_col);
            r3 = ror!(_mm_xor_si128(r3, r0), 16);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 12);
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), my_col);
            r3 = ror!(_mm_xor_si128(r3, r0), 8);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 7);

            r1 = _mm_shuffle_epi32(r1, DIAG_R1);
            r2 = _mm_shuffle_epi32(r2, DIAG_R2);
            r3 = _mm_shuffle_epi32(r3, DIAG_R3);

            let mx_diag = _mm_set_epi32(
                $b[$s14] as i32, $b[$s12] as i32,
                $b[$s10] as i32, $b[$s8] as i32,
            );
            let my_diag = _mm_set_epi32(
                $b[$s15] as i32, $b[$s13] as i32,
                $b[$s11] as i32, $b[$s9] as i32,
            );
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), mx_diag);
            r3 = ror!(_mm_xor_si128(r3, r0), 16);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 12);
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), my_diag);
            r3 = ror!(_mm_xor_si128(r3, r0), 8);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 7);

            r1 = _mm_shuffle_epi32(r1, UNDIAG_R1);
            r2 = _mm_shuffle_epi32(r2, UNDIAG_R2);
            r3 = _mm_shuffle_epi32(r3, UNDIAG_R3);
        }};
    }

    let b = block;
    round_s!(b, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    round_s!(b, 2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8);
    round_s!(b, 3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1);
    round_s!(b, 10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6);
    round_s!(b, 12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4);
    round_s!(b, 9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7);
    round_s!(b, 11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13);

    r0 = _mm_xor_si128(r0, r2);
    r1 = _mm_xor_si128(r1, r3);
    r2 = _mm_xor_si128(r2, cv0);
    r3 = _mm_xor_si128(r3, cv1);

    let mut out = [0u32; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r0);
    _mm_storeu_si128(out.as_mut_ptr().add(4) as *mut __m128i, r1);
    _mm_storeu_si128(out.as_mut_ptr().add(8) as *mut __m128i, r2);
    _mm_storeu_si128(out.as_mut_ptr().add(12) as *mut __m128i, r3);
    out
}

#[inline(always)]
pub(super) unsafe fn hash_4_chunks_inline(
    input: &[u8; 4096],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 4] {

    let rot16_tbl = _mm_loadu_si128(ROT16.as_ptr() as *const __m128i);
    let rot8_tbl = _mm_loadu_si128(ROT8.as_ptr() as *const __m128i);

    let p0 = input.as_ptr() as *const __m128i;
    let p1 = input.as_ptr().add(1024) as *const __m128i;
    let p2 = input.as_ptr().add(2048) as *const __m128i;
    let p3 = input.as_ptr().add(3072) as *const __m128i;

    let ctr_lo = _mm_set_epi32(
        (counter + 3) as i32, (counter + 2) as i32,
        (counter + 1) as i32, counter as i32,
    );
    let ctr_hi = _mm_set_epi32(
        ((counter + 3) >> 32) as i32, ((counter + 2) >> 32) as i32,
        ((counter + 1) >> 32) as i32, (counter >> 32) as i32,
    );

    let iv0 = _mm_set1_epi32(super::IV[0] as i32);
    let iv1 = _mm_set1_epi32(super::IV[1] as i32);
    let iv2 = _mm_set1_epi32(super::IV[2] as i32);
    let iv3 = _mm_set1_epi32(super::IV[3] as i32);
    let blen = _mm_set1_epi32(64);

    let mut h0 = _mm_set1_epi32(key[0] as i32);
    let mut h1 = _mm_set1_epi32(key[1] as i32);
    let mut h2 = _mm_set1_epi32(key[2] as i32);
    let mut h3 = _mm_set1_epi32(key[3] as i32);
    let mut h4 = _mm_set1_epi32(key[4] as i32);
    let mut h5 = _mm_set1_epi32(key[5] as i32);
    let mut h6 = _mm_set1_epi32(key[6] as i32);
    let mut h7 = _mm_set1_epi32(key[7] as i32);

    for blk in 0u32..16 {
        let bf = match blk {
            0 => flags | super::CHUNK_START,
            15 => flags | super::CHUNK_END,
            _ => flags,
        };

        let (mut s0, mut s1, mut s2, mut s3) = (h0, h1, h2, h3);
        let (mut s4, mut s5, mut s6, mut s7) = (h4, h5, h6, h7);
        let (mut s8, mut s9, mut s10, mut s11) = (iv0, iv1, iv2, iv3);
        let (mut s12, mut s13, mut s14, mut s15) =
            (ctr_lo, ctr_hi, blen, _mm_set1_epi32(bf as i32));

        let bo = blk as usize * 4;

        macro_rules! t4x4 {
            ($off:expr) => {{
                let a = _mm_loadu_si128(p0.add(bo + $off));
                let b = _mm_loadu_si128(p1.add(bo + $off));
                let c = _mm_loadu_si128(p2.add(bo + $off));
                let d = _mm_loadu_si128(p3.add(bo + $off));
                let t0 = _mm_unpacklo_epi32(a, b);
                let t1 = _mm_unpackhi_epi32(a, b);
                let t2 = _mm_unpacklo_epi32(c, d);
                let t3 = _mm_unpackhi_epi32(c, d);
                (
                    _mm_unpacklo_epi64(t0, t2),
                    _mm_unpackhi_epi64(t0, t2),
                    _mm_unpacklo_epi64(t1, t3),
                    _mm_unpackhi_epi64(t1, t3),
                )
            }};
        }

        let (mut m0, mut m1, mut m2, mut m3) = t4x4!(0);
        let (mut m4, mut m5, mut m6, mut m7) = t4x4!(1);
        let (mut m8, mut m9, mut m10, mut m11) = t4x4!(2);
        let (mut m12, mut m13, mut m14, mut m15) = t4x4!(3);

        macro_rules! g4 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {{
                $a = _mm_add_epi32(_mm_add_epi32($a, $b), $mx);
                $d = _mm_shuffle_epi8(_mm_xor_si128($d, $a), rot16_tbl);
                $c = _mm_add_epi32($c, $d);
                let xb = _mm_xor_si128($b, $c);
                $b = _mm_or_si128(_mm_srli_epi32(xb, 12), _mm_slli_epi32(xb, 20));
                $a = _mm_add_epi32(_mm_add_epi32($a, $b), $my);
                $d = _mm_shuffle_epi8(_mm_xor_si128($d, $a), rot8_tbl);
                $c = _mm_add_epi32($c, $d);
                let xb = _mm_xor_si128($b, $c);
                $b = _mm_or_si128(_mm_srli_epi32(xb, 7), _mm_slli_epi32(xb, 25));
            }};
        }

        macro_rules! round4 {
            () => {{
                g4!(s0, s4, s8,  s12, m0,  m1);
                g4!(s1, s5, s9,  s13, m2,  m3);
                g4!(s2, s6, s10, s14, m4,  m5);
                g4!(s3, s7, s11, s15, m6,  m7);
                g4!(s0, s5, s10, s15, m8,  m9);
                g4!(s1, s6, s11, s12, m10, m11);
                g4!(s2, s7, s8,  s13, m12, m13);
                g4!(s3, s4, s9,  s14, m14, m15);
            }};
        }

        macro_rules! perm4 {
            () => {{
                let (t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15)
                    = (m2,m6,m3,m10,m7,m0,m4,m13,m1,m11,m12,m5,m9,m14,m15,m8);
                m0=t0; m1=t1; m2=t2; m3=t3; m4=t4; m5=t5; m6=t6; m7=t7;
                m8=t8; m9=t9; m10=t10; m11=t11; m12=t12; m13=t13; m14=t14; m15=t15;
            }};
        }

        round4!(); perm4!();
        round4!(); perm4!();
        round4!(); perm4!();
        round4!(); perm4!();
        round4!(); perm4!();
        round4!(); perm4!();
        round4!();

        h0 = _mm_xor_si128(s0, s8);
        h1 = _mm_xor_si128(s1, s9);
        h2 = _mm_xor_si128(s2, s10);
        h3 = _mm_xor_si128(s3, s11);
        h4 = _mm_xor_si128(s4, s12);
        h5 = _mm_xor_si128(s5, s13);
        h6 = _mm_xor_si128(s6, s14);
        h7 = _mm_xor_si128(s7, s15);
    }

    // Transpose back and extract per-chunk CVs.
    let mut t = [[0u32; 4]; 8];
    _mm_storeu_si128(t[0].as_mut_ptr() as *mut __m128i, h0);
    _mm_storeu_si128(t[1].as_mut_ptr() as *mut __m128i, h1);
    _mm_storeu_si128(t[2].as_mut_ptr() as *mut __m128i, h2);
    _mm_storeu_si128(t[3].as_mut_ptr() as *mut __m128i, h3);
    _mm_storeu_si128(t[4].as_mut_ptr() as *mut __m128i, h4);
    _mm_storeu_si128(t[5].as_mut_ptr() as *mut __m128i, h5);
    _mm_storeu_si128(t[6].as_mut_ptr() as *mut __m128i, h6);
    _mm_storeu_si128(t[7].as_mut_ptr() as *mut __m128i, h7);
    let mut out = [[0u32; 8]; 4];
    for j in 0..4 {
        out[j] = [
            t[0][j], t[1][j], t[2][j], t[3][j],
            t[4][j], t[5][j], t[6][j], t[7][j],
        ];
    }
    out
}

/// Inline 4-way parallel parent compression (1 block per lane).
/// Processes 4 parent nodes = 8 consecutive CVs → 4 output CVs.
#[inline(always)]
pub(super) unsafe fn compress_parents_4_inline(
    cvs: *const [u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [[u32; 8]; 4] {
    let rot16_tbl = _mm_loadu_si128(ROT16.as_ptr() as *const __m128i);
    let rot8_tbl = _mm_loadu_si128(ROT8.as_ptr() as *const __m128i);

    // 4 parent blocks, each 64 bytes (left_cv || right_cv).
    let p0 = cvs as *const __m128i;
    let p1 = (cvs as *const u8).add(64) as *const __m128i;
    let p2 = (cvs as *const u8).add(128) as *const __m128i;
    let p3 = (cvs as *const u8).add(192) as *const __m128i;

    // State: h = key, counter = 0, block_len = 64.
    let mut s0 = _mm_set1_epi32(key[0] as i32);
    let mut s1 = _mm_set1_epi32(key[1] as i32);
    let mut s2 = _mm_set1_epi32(key[2] as i32);
    let mut s3 = _mm_set1_epi32(key[3] as i32);
    let mut s4 = _mm_set1_epi32(key[4] as i32);
    let mut s5 = _mm_set1_epi32(key[5] as i32);
    let mut s6 = _mm_set1_epi32(key[6] as i32);
    let mut s7 = _mm_set1_epi32(key[7] as i32);
    let mut s8 = _mm_set1_epi32(super::IV[0] as i32);
    let mut s9 = _mm_set1_epi32(super::IV[1] as i32);
    let mut s10 = _mm_set1_epi32(super::IV[2] as i32);
    let mut s11 = _mm_set1_epi32(super::IV[3] as i32);
    let mut s12 = _mm_setzero_si128();
    let mut s13 = _mm_setzero_si128();
    let mut s14 = _mm_set1_epi32(64);
    let mut s15 = _mm_set1_epi32(flags as i32);

    // Load and transpose 4 parent blocks.
    macro_rules! t4x4 {
        ($off:expr) => {{
            let a = _mm_loadu_si128(p0.add($off));
            let b = _mm_loadu_si128(p1.add($off));
            let c = _mm_loadu_si128(p2.add($off));
            let d = _mm_loadu_si128(p3.add($off));
            let t0 = _mm_unpacklo_epi32(a, b);
            let t1 = _mm_unpackhi_epi32(a, b);
            let t2 = _mm_unpacklo_epi32(c, d);
            let t3 = _mm_unpackhi_epi32(c, d);
            (
                _mm_unpacklo_epi64(t0, t2),
                _mm_unpackhi_epi64(t0, t2),
                _mm_unpacklo_epi64(t1, t3),
                _mm_unpackhi_epi64(t1, t3),
            )
        }};
    }

    let (mut m0, mut m1, mut m2, mut m3) = t4x4!(0);
    let (mut m4, mut m5, mut m6, mut m7) = t4x4!(1);
    let (mut m8, mut m9, mut m10, mut m11) = t4x4!(2);
    let (mut m12, mut m13, mut m14, mut m15) = t4x4!(3);

    macro_rules! g4 {
        ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {{
            $a = _mm_add_epi32(_mm_add_epi32($a, $b), $mx);
            $d = _mm_shuffle_epi8(_mm_xor_si128($d, $a), rot16_tbl);
            $c = _mm_add_epi32($c, $d);
            let xb = _mm_xor_si128($b, $c);
            $b = _mm_or_si128(_mm_srli_epi32(xb, 12), _mm_slli_epi32(xb, 20));
            $a = _mm_add_epi32(_mm_add_epi32($a, $b), $my);
            $d = _mm_shuffle_epi8(_mm_xor_si128($d, $a), rot8_tbl);
            $c = _mm_add_epi32($c, $d);
            let xb = _mm_xor_si128($b, $c);
            $b = _mm_or_si128(_mm_srli_epi32(xb, 7), _mm_slli_epi32(xb, 25));
        }};
    }

    macro_rules! round4 {
        () => {{
            g4!(s0, s4, s8,  s12, m0,  m1);
            g4!(s1, s5, s9,  s13, m2,  m3);
            g4!(s2, s6, s10, s14, m4,  m5);
            g4!(s3, s7, s11, s15, m6,  m7);
            g4!(s0, s5, s10, s15, m8,  m9);
            g4!(s1, s6, s11, s12, m10, m11);
            g4!(s2, s7, s8,  s13, m12, m13);
            g4!(s3, s4, s9,  s14, m14, m15);
        }};
    }

    macro_rules! perm4 {
        () => {{
            let (t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15)
                = (m2,m6,m3,m10,m7,m0,m4,m13,m1,m11,m12,m5,m9,m14,m15,m8);
            m0=t0; m1=t1; m2=t2; m3=t3; m4=t4; m5=t5; m6=t6; m7=t7;
            m8=t8; m9=t9; m10=t10; m11=t11; m12=t12; m13=t13; m14=t14; m15=t15;
        }};
    }

    round4!(); perm4!();
    round4!(); perm4!();
    round4!(); perm4!();
    round4!(); perm4!();
    round4!(); perm4!();
    round4!(); perm4!();
    round4!();

    let h0 = _mm_xor_si128(s0, s8);
    let h1 = _mm_xor_si128(s1, s9);
    let h2 = _mm_xor_si128(s2, s10);
    let h3 = _mm_xor_si128(s3, s11);
    let h4 = _mm_xor_si128(s4, s12);
    let h5 = _mm_xor_si128(s5, s13);
    let h6 = _mm_xor_si128(s6, s14);
    let h7 = _mm_xor_si128(s7, s15);

    let mut t = [[0u32; 4]; 8];
    _mm_storeu_si128(t[0].as_mut_ptr() as *mut __m128i, h0);
    _mm_storeu_si128(t[1].as_mut_ptr() as *mut __m128i, h1);
    _mm_storeu_si128(t[2].as_mut_ptr() as *mut __m128i, h2);
    _mm_storeu_si128(t[3].as_mut_ptr() as *mut __m128i, h3);
    _mm_storeu_si128(t[4].as_mut_ptr() as *mut __m128i, h4);
    _mm_storeu_si128(t[5].as_mut_ptr() as *mut __m128i, h5);
    _mm_storeu_si128(t[6].as_mut_ptr() as *mut __m128i, h6);
    _mm_storeu_si128(t[7].as_mut_ptr() as *mut __m128i, h7);
    let mut out = [[0u32; 8]; 4];
    for j in 0..4 {
        out[j] = [
            t[0][j], t[1][j], t[2][j], t[3][j],
            t[4][j], t[5][j], t[6][j], t[7][j],
        ];
    }
    out
}

#[inline(always)]
pub(super) fn hash_4_chunks(
    input: &[u8; 4096],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 4] {
    Blake3::hash_4_chunks_impl(input, key, counter, flags)
}

}; // ($feature:literal) => { ... };
} // macro_rules! blake3_x86_128_impl

blake3_x86_128_impl!("ssse3");

#[inline(always)]
pub(super) unsafe fn hash_4_chunks_v6_core(
    input: &[u8; 4096],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 4] {

    macro_rules! rot16 {
        () => {{
            let mut ptr = ROT16.as_ptr() as *const __m128i;
            core::arch::asm!(
                "/* {ptr} */",
                ptr = inout(reg) ptr,
                options(nostack, preserves_flags, nomem),
            );
            _mm_loadu_si128(ptr)
        }};
    }
    macro_rules! rot8 {
        () => {{
            let mut ptr = ROT8.as_ptr() as *const __m128i;
            core::arch::asm!(
                "/* {ptr} */",
                ptr = inout(reg) ptr,
                options(nostack, preserves_flags, nomem),
            );
            _mm_loadu_si128(ptr)
        }};
    }

    let p0 = input.as_ptr();
    let p1 = input.as_ptr().add(1024);
    let p2 = input.as_ptr().add(2048);
    let p3 = input.as_ptr().add(3072);

    let ctr_lo = _mm_set_epi32(
        (counter + 3) as i32, (counter + 2) as i32,
        (counter + 1) as i32, counter as i32,
    );
    let ctr_hi = _mm_set_epi32(
        ((counter + 3) >> 32) as i32, ((counter + 2) >> 32) as i32,
        ((counter + 1) >> 32) as i32, (counter >> 32) as i32,
    );
    let iv0 = _mm_set1_epi32(super::IV[0] as i32);
    let iv1 = _mm_set1_epi32(super::IV[1] as i32);
    let iv2 = _mm_set1_epi32(super::IV[2] as i32);
    let iv3 = _mm_set1_epi32(super::IV[3] as i32);
    let blen = _mm_set1_epi32(64);

    let mut h0 = _mm_set1_epi32(key[0] as i32);
    let mut h1 = _mm_set1_epi32(key[1] as i32);
    let mut h2 = _mm_set1_epi32(key[2] as i32);
    let mut h3 = _mm_set1_epi32(key[3] as i32);
    let mut h4 = _mm_set1_epi32(key[4] as i32);
    let mut h5 = _mm_set1_epi32(key[5] as i32);
    let mut h6 = _mm_set1_epi32(key[6] as i32);
    let mut h7 = _mm_set1_epi32(key[7] as i32);

    for blk in 0u32..16 {
        let bf = match blk {
            0 => flags | super::CHUNK_START,
            15 => flags | super::CHUNK_END,
            _ => flags,
        };

        let (mut s0, mut s1, mut s2, mut s3) = (h0, h1, h2, h3);
        let (mut s4, mut s5, mut s6, mut s7) = (h4, h5, h6, h7);
        let (mut s8, mut s9, mut s10, mut s11) = (iv0, iv1, iv2, iv3);
        let (mut s12, mut s13, mut s14, mut s15) =
            (ctr_lo, ctr_hi, blen, _mm_set1_epi32(bf as i32));

        let bo = blk as usize * 64;

        macro_rules! t4x4 {
            ($off:expr) => {{
                let a = _mm_loadu_si128(p0.add(bo + $off) as *const __m128i);
                let b = _mm_loadu_si128(p1.add(bo + $off) as *const __m128i);
                let c = _mm_loadu_si128(p2.add(bo + $off) as *const __m128i);
                let d = _mm_loadu_si128(p3.add(bo + $off) as *const __m128i);
                let t0 = _mm_unpacklo_epi32(a, b);
                let t1 = _mm_unpackhi_epi32(a, b);
                let t2 = _mm_unpacklo_epi32(c, d);
                let t3 = _mm_unpackhi_epi32(c, d);
                (
                    _mm_unpacklo_epi64(t0, t2),
                    _mm_unpackhi_epi64(t0, t2),
                    _mm_unpacklo_epi64(t1, t3),
                    _mm_unpackhi_epi64(t1, t3),
                )
            }};
        }

        let (m0,  m1,  m2,  m3)  = t4x4!(0);
        let (m4,  m5,  m6,  m7)  = t4x4!(16);
        let (m8,  m9,  m10, m11) = t4x4!(32);
        let (m12, m13, m14, m15) = t4x4!(48);
        let msg = [m0, m1, m2, m3, m4, m5, m6, m7,
                   m8, m9, m10, m11, m12, m13, m14, m15];
        let mut mp = msg.as_ptr();

        macro_rules! black_box_ptr {
            ($ptr:expr) => {{
                $ptr
            }};
        }

        macro_rules! round6 {
            ([$i0:literal,$i1:literal,$i2:literal,$i3:literal,
              $i4:literal,$i5:literal,$i6:literal,$i7:literal,
              $i8:literal,$i9:literal,$i10:literal,$i11:literal,
              $i12:literal,$i13:literal,$i14:literal,$i15:literal]) => {{
                        core::arch::asm!(
            "/* {mp} */",
            mp = inout(reg) mp,
            options(nostack, preserves_flags, nomem),
        );
                // ═══ Column: G(0,4,8,12) G(1,5,9,13) G(2,6,10,14) G(3,7,11,15) ═══
                // a += b
                s0 = _mm_add_epi32(s0, s4);
                s1 = _mm_add_epi32(s1, s5);
                s2 = _mm_add_epi32(s2, s6);
                s3 = _mm_add_epi32(s3, s7);
                // a += m  (split + black_box ptr → forced mem reload → fold)
                s0 = _mm_add_epi32(s0, *black_box_ptr!(mp).add($i0));
                s1 = _mm_add_epi32(s1, *black_box_ptr!(mp).add($i2));
                s2 = _mm_add_epi32(s2, *black_box_ptr!(mp).add($i4));
                s3 = _mm_add_epi32(s3, *black_box_ptr!(mp).add($i6));
                // d = rot16(d ^ a)
                s12 = _mm_xor_si128(s12, s0);
                s12 = _mm_shuffle_epi8(s12, rot16!());
                s13 = _mm_xor_si128(s13, s1);
                s13 = _mm_shuffle_epi8(s13, rot16!());
                s14 = _mm_xor_si128(s14, s2);
                s14 = _mm_shuffle_epi8(s14, rot16!());
                s15 = _mm_xor_si128(s15, s3);
                s15 = _mm_shuffle_epi8(s15, rot16!());
                // c += d
                s8  = _mm_add_epi32(s8,  s12);
                s9  = _mm_add_epi32(s9,  s13);
                s10 = _mm_add_epi32(s10, s14);
                s11 = _mm_add_epi32(s11, s15);
                // b = ror12(b ^ c)  — destructive xor, serialized
                s4 = _mm_xor_si128(s4, s8);
                { let t = _mm_srli_epi32(s4, 12); s4 = _mm_slli_epi32(s4, 20); s4 = _mm_or_si128(s4, t); }
                s5 = _mm_xor_si128(s5, s9);
                { let t = _mm_srli_epi32(s5, 12); s5 = _mm_slli_epi32(s5, 20); s5 = _mm_or_si128(s5, t); }
                s6 = _mm_xor_si128(s6, s10);
                { let t = _mm_srli_epi32(s6, 12); s6 = _mm_slli_epi32(s6, 20); s6 = _mm_or_si128(s6, t); }
                s7 = _mm_xor_si128(s7, s11);
                { let t = _mm_srli_epi32(s7, 12); s7 = _mm_slli_epi32(s7, 20); s7 = _mm_or_si128(s7, t); }
                // a += b
                s0 = _mm_add_epi32(s0, s4);
                s1 = _mm_add_epi32(s1, s5);
                s2 = _mm_add_epi32(s2, s6);
                s3 = _mm_add_epi32(s3, s7);
                // a += m  (split)
                s0 = _mm_add_epi32(s0, *black_box_ptr!(mp).add($i1));
                s1 = _mm_add_epi32(s1, *black_box_ptr!(mp).add($i3));
                s2 = _mm_add_epi32(s2, *black_box_ptr!(mp).add($i5));
                s3 = _mm_add_epi32(s3, *black_box_ptr!(mp).add($i7));
                // d = rot8(d ^ a)
                s12 = _mm_xor_si128(s12, s0);
                s12 = _mm_shuffle_epi8(s12, rot8!());
                s13 = _mm_xor_si128(s13, s1);
                s13 = _mm_shuffle_epi8(s13, rot8!());
                s14 = _mm_xor_si128(s14, s2);
                s14 = _mm_shuffle_epi8(s14, rot8!());
                s15 = _mm_xor_si128(s15, s3);
                s15 = _mm_shuffle_epi8(s15, rot8!());
                // c += d
                s8  = _mm_add_epi32(s8,  s12);
                s9  = _mm_add_epi32(s9,  s13);
                s10 = _mm_add_epi32(s10, s14);
                s11 = _mm_add_epi32(s11, s15);
                // b = ror7(b ^ c)  — destructive xor, serialized
                s4 = _mm_xor_si128(s4, s8);
                { let t = _mm_srli_epi32(s4, 7); s4 = _mm_slli_epi32(s4, 25); s4 = _mm_or_si128(s4, t); }
                s5 = _mm_xor_si128(s5, s9);
                { let t = _mm_srli_epi32(s5, 7); s5 = _mm_slli_epi32(s5, 25); s5 = _mm_or_si128(s5, t); }
                s6 = _mm_xor_si128(s6, s10);
                { let t = _mm_srli_epi32(s6, 7); s6 = _mm_slli_epi32(s6, 25); s6 = _mm_or_si128(s6, t); }
                s7 = _mm_xor_si128(s7, s11);
                { let t = _mm_srli_epi32(s7, 7); s7 = _mm_slli_epi32(s7, 25); s7 = _mm_or_si128(s7, t); }

                // ═══ Diagonal: G(0,5,10,15) G(1,6,11,12) G(2,7,8,13) G(3,4,9,14) ═══
                // a += b
                s0 = _mm_add_epi32(s0, s5);
                s1 = _mm_add_epi32(s1, s6);
                s2 = _mm_add_epi32(s2, s7);
                s3 = _mm_add_epi32(s3, s4);
                // a += m  (split)
                s0 = _mm_add_epi32(s0, *black_box_ptr!(mp).add($i8));
                s1 = _mm_add_epi32(s1, *black_box_ptr!(mp).add($i10));
                s2 = _mm_add_epi32(s2, *black_box_ptr!(mp).add($i12));
                s3 = _mm_add_epi32(s3, *black_box_ptr!(mp).add($i14));
                // d = rot16(d ^ a) — diagonal
                s15 = _mm_xor_si128(s15, s0);
                s15 = _mm_shuffle_epi8(s15, rot16!());
                s12 = _mm_xor_si128(s12, s1);
                s12 = _mm_shuffle_epi8(s12, rot16!());
                s13 = _mm_xor_si128(s13, s2);
                s13 = _mm_shuffle_epi8(s13, rot16!());
                s14 = _mm_xor_si128(s14, s3);
                s14 = _mm_shuffle_epi8(s14, rot16!());
                // c += d — diagonal
                s10 = _mm_add_epi32(s10, s15);
                s11 = _mm_add_epi32(s11, s12);
                s8  = _mm_add_epi32(s8,  s13);
                s9  = _mm_add_epi32(s9,  s14);
                // b = ror12(b ^ c) — diagonal, serialized
                s5 = _mm_xor_si128(s5, s10);
                { let t = _mm_srli_epi32(s5, 12); s5 = _mm_slli_epi32(s5, 20); s5 = _mm_or_si128(s5, t); }
                s6 = _mm_xor_si128(s6, s11);
                { let t = _mm_srli_epi32(s6, 12); s6 = _mm_slli_epi32(s6, 20); s6 = _mm_or_si128(s6, t); }
                s7 = _mm_xor_si128(s7, s8);
                { let t = _mm_srli_epi32(s7, 12); s7 = _mm_slli_epi32(s7, 20); s7 = _mm_or_si128(s7, t); }
                s4 = _mm_xor_si128(s4, s9);
                { let t = _mm_srli_epi32(s4, 12); s4 = _mm_slli_epi32(s4, 20); s4 = _mm_or_si128(s4, t); }
                // a += b — diagonal
                s0 = _mm_add_epi32(s0, s5);
                s1 = _mm_add_epi32(s1, s6);
                s2 = _mm_add_epi32(s2, s7);
                s3 = _mm_add_epi32(s3, s4);
                // a += m  (split) — diagonal
                s0 = _mm_add_epi32(s0, *black_box_ptr!(mp).add($i9));
                s1 = _mm_add_epi32(s1, *black_box_ptr!(mp).add($i11));
                s2 = _mm_add_epi32(s2, *black_box_ptr!(mp).add($i13));
                s3 = _mm_add_epi32(s3, *black_box_ptr!(mp).add($i15));
                // d = rot8(d ^ a) — diagonal
                s15 = _mm_xor_si128(s15, s0);
                s15 = _mm_shuffle_epi8(s15, rot8!());
                s12 = _mm_xor_si128(s12, s1);
                s12 = _mm_shuffle_epi8(s12, rot8!());
                s13 = _mm_xor_si128(s13, s2);
                s13 = _mm_shuffle_epi8(s13, rot8!());
                s14 = _mm_xor_si128(s14, s3);
                s14 = _mm_shuffle_epi8(s14, rot8!());
                // c += d — diagonal
                s10 = _mm_add_epi32(s10, s15);
                s11 = _mm_add_epi32(s11, s12);
                s8  = _mm_add_epi32(s8,  s13);
                s9  = _mm_add_epi32(s9,  s14);
                // b = ror7(b ^ c) — diagonal, serialized
                s5 = _mm_xor_si128(s5, s10);
                { let t = _mm_srli_epi32(s5, 7); s5 = _mm_slli_epi32(s5, 25); s5 = _mm_or_si128(s5, t); }
                s6 = _mm_xor_si128(s6, s11);
                { let t = _mm_srli_epi32(s6, 7); s6 = _mm_slli_epi32(s6, 25); s6 = _mm_or_si128(s6, t); }
                s7 = _mm_xor_si128(s7, s8);
                { let t = _mm_srli_epi32(s7, 7); s7 = _mm_slli_epi32(s7, 25); s7 = _mm_or_si128(s7, t); }
                s4 = _mm_xor_si128(s4, s9);
                { let t = _mm_srli_epi32(s4, 7); s4 = _mm_slli_epi32(s4, 25); s4 = _mm_or_si128(s4, t); }
            }};
        }

        round6!([ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15]);
        round6!([ 2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8]);
        round6!([ 3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1]);
        round6!([10, 7,12, 9,14, 3,13,15, 4, 0,11, 2, 5, 8, 1, 6]);
        round6!([12,13, 9,11,15,10,14, 8, 7, 2, 5, 3, 0, 1, 6, 4]);
        round6!([ 9,14,11, 5, 8,12,15, 1,13, 3, 0,10, 2, 6, 4, 7]);
        round6!([11,15, 5, 0, 1, 9, 8, 6,14,10, 2,12, 3, 4, 7,13]);

        h0 = _mm_xor_si128(s0, s8);
        h1 = _mm_xor_si128(s1, s9);
        h2 = _mm_xor_si128(s2, s10);
        h3 = _mm_xor_si128(s3, s11);
        h4 = _mm_xor_si128(s4, s12);
        h5 = _mm_xor_si128(s5, s13);
        h6 = _mm_xor_si128(s6, s14);
        h7 = _mm_xor_si128(s7, s15);
    }

    let mut t = [[0u32; 4]; 8];
    _mm_storeu_si128(t[0].as_mut_ptr() as *mut __m128i, h0);
    _mm_storeu_si128(t[1].as_mut_ptr() as *mut __m128i, h1);
    _mm_storeu_si128(t[2].as_mut_ptr() as *mut __m128i, h2);
    _mm_storeu_si128(t[3].as_mut_ptr() as *mut __m128i, h3);
    _mm_storeu_si128(t[4].as_mut_ptr() as *mut __m128i, h4);
    _mm_storeu_si128(t[5].as_mut_ptr() as *mut __m128i, h5);
    _mm_storeu_si128(t[6].as_mut_ptr() as *mut __m128i, h6);
    _mm_storeu_si128(t[7].as_mut_ptr() as *mut __m128i, h7);
    let mut out = [[0u32; 8]; 4];
    for j in 0..4 {
        out[j] = [
            t[0][j], t[1][j], t[2][j], t[3][j],
            t[4][j], t[5][j], t[6][j], t[7][j],
        ];
    }
    out
}

// ---------------------------------------------------------------------------
// Slice-level
// ---------------------------------------------------------------------------
blake3_impl!(transform, transform_inline, hash_4_chunks, 4;
    hash_inline: hash_4_chunks_inline;
    oneshot_feature: "ssse3");

#[cfg(test)]
mod tests {
    use super::Blake3;

    blake3_test_case!(require_hw: "x86" => ("ssse3"), "x86_64" => ("ssse3"));
}
