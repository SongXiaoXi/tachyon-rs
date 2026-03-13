// BLAKE3 – x86/x86_64 AVX2 implementation.

#![allow(unused_unsafe)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use unsafe_target_feature::unsafe_target_feature;

// ---------------------------------------------------------------------------
// Single-block: delegate to AVX (VEX-encoded) transform.
// ---------------------------------------------------------------------------
#[inline(always)]
fn transform(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    super::x86_avx::transform(chaining_value, block, block_len, counter, flags)
}

// ---------------------------------------------------------------------------
// 256-bit ROR byte-shuffle tables for vpshufb.  Each 128-bit lane is
// identical.
// ---------------------------------------------------------------------------
static ROT16_256: [u8; 32] = [
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
];
static ROT8_256: [u8; 32] = [
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
];

macro_rules! xor_rot {
    ($a:expr, $b:expr, 16) => {{
        let x = _mm256_xor_si256($a, $b);
        let mut p = ROT16_256.as_ptr() as *const __m256i;
        core::arch::asm!(
            "/* {ptr} */",
            ptr = inout(reg) p,
            options(nostack, preserves_flags, nomem),
        );
        _mm256_shuffle_epi8(x, _mm256_loadu_si256(p))
    }};
    ($a:expr, $b:expr, 8) => {{
        let x = _mm256_xor_si256($a, $b);
        let mut p = ROT8_256.as_ptr() as *const __m256i;
        core::arch::asm!(
            "/* {ptr} */",
            ptr = inout(reg) p,
            options(nostack, preserves_flags, nomem),
        );
        _mm256_shuffle_epi8(x, _mm256_loadu_si256(p))
    }};
    ($a:expr, $b:expr, $r:literal) => {{
        let x = _mm256_xor_si256($a, $b);
        _mm256_or_si256(
            _mm256_srli_epi32(x, $r),
            _mm256_slli_epi32(x, 32 - $r),
        )
    }};
}

macro_rules! xor_rot_direct {
    ($a:expr, $b:expr, $r:literal) => {{
        let x = _mm256_xor_si256($a, $b);
        _mm256_or_si256(
            _mm256_srli_epi32(x, $r),
            _mm256_slli_epi32(x, 32 - $r),
        )
    }};
}

macro_rules! round_avx2 {
    ($s:ident, $m:expr,
     [$i0:literal,$i1:literal,$i2:literal,$i3:literal,
      $i4:literal,$i5:literal,$i6:literal,$i7:literal,
      $i8:literal,$i9:literal,$i10:literal,$i11:literal,
      $i12:literal,$i13:literal,$i14:literal,$i15:literal]) => { unsafe {
        // ── Column step: G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15) ──
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[4]),  $m[$i0]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[5]),  $m[$i2]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[6]),  $m[$i4]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[7]),  $m[$i6]);
        $s[12] = xor_rot!($s[12], $s[0], 16);
        $s[13] = xor_rot!($s[13], $s[1], 16);
        $s[14] = xor_rot!($s[14], $s[2], 16);
        $s[15] = xor_rot!($s[15], $s[3], 16);
        $s[8]  = _mm256_add_epi32($s[8],  $s[12]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[13]);
        $s[10] = _mm256_add_epi32($s[10], $s[14]);
        $s[11] = _mm256_add_epi32($s[11], $s[15]);
        $s[4] = xor_rot!($s[4], $s[8],  12);
        $s[5] = xor_rot!($s[5], $s[9],  12);
        $s[6] = xor_rot!($s[6], $s[10], 12);
        $s[7] = xor_rot!($s[7], $s[11], 12);
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[4]),  $m[$i1]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[5]),  $m[$i3]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[6]),  $m[$i5]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[7]),  $m[$i7]);
        $s[12] = xor_rot!($s[12], $s[0], 8);
        $s[13] = xor_rot!($s[13], $s[1], 8);
        $s[14] = xor_rot!($s[14], $s[2], 8);
        $s[15] = xor_rot!($s[15], $s[3], 8);
        $s[8]  = _mm256_add_epi32($s[8],  $s[12]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[13]);
        $s[10] = _mm256_add_epi32($s[10], $s[14]);
        $s[11] = _mm256_add_epi32($s[11], $s[15]);
        $s[4] = xor_rot!($s[4], $s[8],  7);
        $s[5] = xor_rot!($s[5], $s[9],  7);
        $s[6] = xor_rot!($s[6], $s[10], 7);
        $s[7] = xor_rot!($s[7], $s[11], 7);
        // ── Diagonal step: G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14) ──
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[5]),  $m[$i8]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[6]),  $m[$i10]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[7]),  $m[$i12]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[4]),  $m[$i14]);
        $s[15] = xor_rot!($s[15], $s[0], 16);
        $s[12] = xor_rot!($s[12], $s[1], 16);
        $s[13] = xor_rot!($s[13], $s[2], 16);
        $s[14] = xor_rot!($s[14], $s[3], 16);
        $s[10] = _mm256_add_epi32($s[10], $s[15]);
        $s[11] = _mm256_add_epi32($s[11], $s[12]);
        $s[8]  = _mm256_add_epi32($s[8],  $s[13]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[14]);
        $s[5] = xor_rot!($s[5], $s[10], 12);
        $s[6] = xor_rot!($s[6], $s[11], 12);
        $s[7] = xor_rot!($s[7], $s[8],  12);
        $s[4] = xor_rot!($s[4], $s[9],  12);
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[5]),  $m[$i9]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[6]),  $m[$i11]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[7]),  $m[$i13]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[4]),  $m[$i15]);
        $s[15] = xor_rot!($s[15], $s[0], 8);
        $s[12] = xor_rot!($s[12], $s[1], 8);
        $s[13] = xor_rot!($s[13], $s[2], 8);
        $s[14] = xor_rot!($s[14], $s[3], 8);
        $s[10] = _mm256_add_epi32($s[10], $s[15]);
        $s[11] = _mm256_add_epi32($s[11], $s[12]);
        $s[8]  = _mm256_add_epi32($s[8],  $s[13]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[14]);
        $s[5] = xor_rot!($s[5], $s[10], 7);
        $s[6] = xor_rot!($s[6], $s[11], 7);
        $s[7] = xor_rot!($s[7], $s[8],  7);
        $s[4] = xor_rot!($s[4], $s[9],  7);
    }};
}

macro_rules! round_avx2_direct {
    ($s:ident, $m:expr,
     [$i0:literal,$i1:literal,$i2:literal,$i3:literal,
      $i4:literal,$i5:literal,$i6:literal,$i7:literal,
      $i8:literal,$i9:literal,$i10:literal,$i11:literal,
      $i12:literal,$i13:literal,$i14:literal,$i15:literal]) => { unsafe {
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[4]),  $m[$i0]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[5]),  $m[$i2]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[6]),  $m[$i4]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[7]),  $m[$i6]);
        $s[12] = xor_rot_direct!($s[12], $s[0], 16);
        $s[13] = xor_rot_direct!($s[13], $s[1], 16);
        $s[14] = xor_rot_direct!($s[14], $s[2], 16);
        $s[15] = xor_rot_direct!($s[15], $s[3], 16);
        $s[8]  = _mm256_add_epi32($s[8],  $s[12]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[13]);
        $s[10] = _mm256_add_epi32($s[10], $s[14]);
        $s[11] = _mm256_add_epi32($s[11], $s[15]);
        $s[4] = xor_rot_direct!($s[4], $s[8],  12);
        $s[5] = xor_rot_direct!($s[5], $s[9],  12);
        $s[6] = xor_rot_direct!($s[6], $s[10], 12);
        $s[7] = xor_rot_direct!($s[7], $s[11], 12);
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[4]),  $m[$i1]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[5]),  $m[$i3]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[6]),  $m[$i5]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[7]),  $m[$i7]);
        $s[12] = xor_rot_direct!($s[12], $s[0], 8);
        $s[13] = xor_rot_direct!($s[13], $s[1], 8);
        $s[14] = xor_rot_direct!($s[14], $s[2], 8);
        $s[15] = xor_rot_direct!($s[15], $s[3], 8);
        $s[8]  = _mm256_add_epi32($s[8],  $s[12]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[13]);
        $s[10] = _mm256_add_epi32($s[10], $s[14]);
        $s[11] = _mm256_add_epi32($s[11], $s[15]);
        $s[4] = xor_rot_direct!($s[4], $s[8],  7);
        $s[5] = xor_rot_direct!($s[5], $s[9],  7);
        $s[6] = xor_rot_direct!($s[6], $s[10], 7);
        $s[7] = xor_rot_direct!($s[7], $s[11], 7);
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[5]),  $m[$i8]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[6]),  $m[$i10]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[7]),  $m[$i12]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[4]),  $m[$i14]);
        $s[15] = xor_rot_direct!($s[15], $s[0], 16);
        $s[12] = xor_rot_direct!($s[12], $s[1], 16);
        $s[13] = xor_rot_direct!($s[13], $s[2], 16);
        $s[14] = xor_rot_direct!($s[14], $s[3], 16);
        $s[10] = _mm256_add_epi32($s[10], $s[15]);
        $s[11] = _mm256_add_epi32($s[11], $s[12]);
        $s[8]  = _mm256_add_epi32($s[8],  $s[13]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[14]);
        $s[5] = xor_rot_direct!($s[5], $s[10], 12);
        $s[6] = xor_rot_direct!($s[6], $s[11], 12);
        $s[7] = xor_rot_direct!($s[7], $s[8],  12);
        $s[4] = xor_rot_direct!($s[4], $s[9],  12);
        $s[0] = _mm256_add_epi32(_mm256_add_epi32($s[0], $s[5]),  $m[$i9]);
        $s[1] = _mm256_add_epi32(_mm256_add_epi32($s[1], $s[6]),  $m[$i11]);
        $s[2] = _mm256_add_epi32(_mm256_add_epi32($s[2], $s[7]),  $m[$i13]);
        $s[3] = _mm256_add_epi32(_mm256_add_epi32($s[3], $s[4]),  $m[$i15]);
        $s[15] = xor_rot_direct!($s[15], $s[0], 8);
        $s[12] = xor_rot_direct!($s[12], $s[1], 8);
        $s[13] = xor_rot_direct!($s[13], $s[2], 8);
        $s[14] = xor_rot_direct!($s[14], $s[3], 8);
        $s[10] = _mm256_add_epi32($s[10], $s[15]);
        $s[11] = _mm256_add_epi32($s[11], $s[12]);
        $s[8]  = _mm256_add_epi32($s[8],  $s[13]);
        $s[9]  = _mm256_add_epi32($s[9],  $s[14]);
        $s[5] = xor_rot_direct!($s[5], $s[10], 7);
        $s[6] = xor_rot_direct!($s[6], $s[11], 7);
        $s[7] = xor_rot_direct!($s[7], $s[8],  7);
        $s[4] = xor_rot_direct!($s[4], $s[9],  7);
    }};
}

macro_rules! transpose_msg_128 {
    ($p0:expr, $p1:expr, $p2:expr, $p3:expr,
     $p4:expr, $p5:expr, $p6:expr, $p7:expr, $off:expr) => { unsafe {
        // Load first 16 bytes from each chunk, combine low/high halves.
        let r0 = _mm256_insertf128_si256::<1>(
            _mm256_castsi128_si256(_mm_loadu_si128($p0.add($off) as *const __m128i)),
            _mm_loadu_si128($p4.add($off) as *const __m128i));
        let r1 = _mm256_insertf128_si256::<1>(
            _mm256_castsi128_si256(_mm_loadu_si128($p1.add($off) as *const __m128i)),
            _mm_loadu_si128($p5.add($off) as *const __m128i));
        let r2 = _mm256_insertf128_si256::<1>(
            _mm256_castsi128_si256(_mm_loadu_si128($p2.add($off) as *const __m128i)),
            _mm_loadu_si128($p6.add($off) as *const __m128i));
        let r3 = _mm256_insertf128_si256::<1>(
            _mm256_castsi128_si256(_mm_loadu_si128($p3.add($off) as *const __m128i)),
            _mm_loadu_si128($p7.add($off) as *const __m128i));

        let t0 = _mm256_unpacklo_epi64(r0, r1);  // (c0w0,c0w1,c1w0,c1w1 | c4w0,c4w1,c5w0,c5w1)
        let t1 = _mm256_unpackhi_epi64(r0, r1);
        let t2 = _mm256_unpacklo_epi64(r2, r3);
        let t3 = _mm256_unpackhi_epi64(r2, r3);

        let m0 = _mm256_castps_si256(_mm256_shuffle_ps(
            _mm256_castsi256_ps(t0), _mm256_castsi256_ps(t2), 0x88));
        let m1 = _mm256_castps_si256(_mm256_shuffle_ps(
            _mm256_castsi256_ps(t0), _mm256_castsi256_ps(t2), 0xDD));
        let m2 = _mm256_castps_si256(_mm256_shuffle_ps(
            _mm256_castsi256_ps(t1), _mm256_castsi256_ps(t3), 0x88));
        let m3 = _mm256_castps_si256(_mm256_shuffle_ps(
            _mm256_castsi256_ps(t1), _mm256_castsi256_ps(t3), 0xDD));
        (m0, m1, m2, m3)
    }};
}

// ---------------------------------------------------------------------------
// 8-way parallel chunk hashing + 8-way parent batch (AVX2).
// ---------------------------------------------------------------------------
#[unsafe_target_feature("avx2")]
impl Blake3 {

    #[inline(always)]
    fn hash_8_chunks_avx2(
        input: &[u8; 8192],
        key: &[u32; 8],
        counter: u64,
        flags: u32,
    ) -> [[u32; 8]; 8] {

        let p0 = input.as_ptr();
        let p1 = unsafe { p0.add(1024) };
        let p2 = unsafe { p0.add(2048) };
        let p3 = unsafe { p0.add(3072) };
        let p4 = unsafe { p0.add(4096) };
        let p5 = unsafe { p0.add(5120) };
        let p6 = unsafe { p0.add(6144) };
        let p7 = unsafe { p0.add(7168) };

        let ctr_lo = unsafe { _mm256_setr_epi32(
            counter as i32,
            (counter + 1) as i32,
            (counter + 2) as i32,
            (counter + 3) as i32,
            (counter + 4) as i32,
            (counter + 5) as i32,
            (counter + 6) as i32,
            (counter + 7) as i32,
        ) };
        let ctr_hi = unsafe { _mm256_setr_epi32(
            (counter >> 32) as i32,
            ((counter + 1) >> 32) as i32,
            ((counter + 2) >> 32) as i32,
            ((counter + 3) >> 32) as i32,
            ((counter + 4) >> 32) as i32,
            ((counter + 5) >> 32) as i32,
            ((counter + 6) >> 32) as i32,
            ((counter + 7) >> 32) as i32,
        ) };

        let iv0 = unsafe { _mm256_set1_epi32(super::IV[0] as i32) };
        let iv1 = unsafe { _mm256_set1_epi32(super::IV[1] as i32) };
        let iv2 = unsafe { _mm256_set1_epi32(super::IV[2] as i32) };
        let iv3 = unsafe { _mm256_set1_epi32(super::IV[3] as i32) };
        let blen = unsafe { _mm256_set1_epi32(64) };

        let mut h0 = unsafe { _mm256_set1_epi32(key[0] as i32) };
        let mut h1 = unsafe { _mm256_set1_epi32(key[1] as i32) };
        let mut h2 = unsafe { _mm256_set1_epi32(key[2] as i32) };
        let mut h3 = unsafe { _mm256_set1_epi32(key[3] as i32) };
        let mut h4 = unsafe { _mm256_set1_epi32(key[4] as i32) };
        let mut h5 = unsafe { _mm256_set1_epi32(key[5] as i32) };
        let mut h6 = unsafe { _mm256_set1_epi32(key[6] as i32) };
        let mut h7 = unsafe { _mm256_set1_epi32(key[7] as i32) };

        for blk in 0u32..16 {
            let bf = match blk {
                0 => flags | super::CHUNK_START,
                15 => flags | super::CHUNK_END,
                _ => flags,
            };

            let mut s = [h0, h1, h2, h3, h4, h5, h6, h7,
                         iv0, iv1, iv2, iv3,
                         ctr_lo, ctr_hi, blen, unsafe { _mm256_set1_epi32(bf as i32) }];

            let byte_off = blk as usize * 64;

            // 128-bit loads + vinsertf128 + vshufps transpose (matches reference asm).
            let (m0,  m1,  m2,  m3)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off);
            let (m4,  m5,  m6,  m7)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off + 16);
            let (m8,  m9,  m10, m11) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off + 32);
            let (m12, m13, m14, m15) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off + 48);
            let msg = [m0, m1, m2, m3, m4, m5, m6, m7,
                       m8, m9, m10, m11, m12, m13, m14, m15];

            // Prefetch next block.
            unsafe {
                _mm_prefetch(p0.add(byte_off + 256) as *const i8, _MM_HINT_T0);
                _mm_prefetch(p1.add(byte_off + 256) as *const i8, _MM_HINT_T0);
                _mm_prefetch(p2.add(byte_off + 256) as *const i8, _MM_HINT_T0);
                _mm_prefetch(p3.add(byte_off + 256) as *const i8, _MM_HINT_T0);
                _mm_prefetch(p4.add(byte_off + 256) as *const i8, _MM_HINT_T0);
                _mm_prefetch(p5.add(byte_off + 256) as *const i8, _MM_HINT_T0);
                _mm_prefetch(p6.add(byte_off + 256) as *const i8, _MM_HINT_T0);
                _mm_prefetch(p7.add(byte_off + 256) as *const i8, _MM_HINT_T0);
            }

            // 7 rounds, fully interleaved.
            round_avx2!(s, msg, [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15]);
            round_avx2!(s, msg, [ 2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8]);
            round_avx2!(s, msg, [ 3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1]);
            round_avx2!(s, msg, [10, 7,12, 9,14, 3,13,15, 4, 0,11, 2, 5, 8, 1, 6]);
            round_avx2!(s, msg, [12,13, 9,11,15,10,14, 8, 7, 2, 5, 3, 0, 1, 6, 4]);
            round_avx2!(s, msg, [ 9,14,11, 5, 8,12,15, 1,13, 3, 0,10, 2, 6, 4, 7]);
            round_avx2!(s, msg, [11,15, 5, 0, 1, 9, 8, 6,14,10, 2,12, 3, 4, 7,13]);

            h0 = unsafe { _mm256_xor_si256(s[0], s[8]) };
            h1 = unsafe { _mm256_xor_si256(s[1], s[9]) };
            h2 = unsafe { _mm256_xor_si256(s[2], s[10]) };
            h3 = unsafe { _mm256_xor_si256(s[3], s[11]) };
            h4 = unsafe { _mm256_xor_si256(s[4], s[12]) };
            h5 = unsafe { _mm256_xor_si256(s[5], s[13]) };
            h6 = unsafe { _mm256_xor_si256(s[6], s[14]) };
            h7 = unsafe { _mm256_xor_si256(s[7], s[15]) };
        }

        // Extract per-chunk CVs via SIMD 8×8 transpose.
        unsafe {
            let t0 = _mm256_unpacklo_epi32(h0, h1);
            let t1 = _mm256_unpackhi_epi32(h0, h1);
            let t2 = _mm256_unpacklo_epi32(h2, h3);
            let t3 = _mm256_unpackhi_epi32(h2, h3);
            let t4 = _mm256_unpacklo_epi32(h4, h5);
            let t5 = _mm256_unpackhi_epi32(h4, h5);
            let t6 = _mm256_unpacklo_epi32(h6, h7);
            let t7 = _mm256_unpackhi_epi32(h6, h7);
            let u0 = _mm256_unpacklo_epi64(t0, t2);
            let u1 = _mm256_unpackhi_epi64(t0, t2);
            let u2 = _mm256_unpacklo_epi64(t1, t3);
            let u3 = _mm256_unpackhi_epi64(t1, t3);
            let u4 = _mm256_unpacklo_epi64(t4, t6);
            let u5 = _mm256_unpackhi_epi64(t4, t6);
            let u6 = _mm256_unpacklo_epi64(t5, t7);
            let u7 = _mm256_unpackhi_epi64(t5, t7);
            let mut out = [[0u32; 8]; 8];
            _mm256_storeu_si256(out[0].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u0, u4));
            _mm256_storeu_si256(out[1].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u1, u5));
            _mm256_storeu_si256(out[2].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u2, u6));
            _mm256_storeu_si256(out[3].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u3, u7));
            _mm256_storeu_si256(out[4].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u0, u4));
            _mm256_storeu_si256(out[5].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u1, u5));
            _mm256_storeu_si256(out[6].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u2, u6));
            _mm256_storeu_si256(out[7].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u3, u7));
            out
        }
    }

    /// Compress 8 independent parent nodes in parallel using AVX2.
    #[inline(always)]
    fn compress_parents_8_avx2(
        cvs: *const [u32; 8],
        key: &[u32; 8],
        flags: u32,
    ) -> [[u32; 8]; 8] {
        unsafe {
            let base = cvs as *const u8;
            let p0 = base;
            let p1 = base.add(64);
            let p2 = base.add(128);
            let p3 = base.add(192);
            let p4 = base.add(256);
            let p5 = base.add(320);
            let p6 = base.add(384);
            let p7 = base.add(448);
            let iv0 = _mm256_set1_epi32(super::IV[0] as i32);
            let iv1 = _mm256_set1_epi32(super::IV[1] as i32);
            let iv2 = _mm256_set1_epi32(super::IV[2] as i32);
            let iv3 = _mm256_set1_epi32(super::IV[3] as i32);
            let mut s = [
                _mm256_set1_epi32(key[0] as i32),
                _mm256_set1_epi32(key[1] as i32),
                _mm256_set1_epi32(key[2] as i32),
                _mm256_set1_epi32(key[3] as i32),
                _mm256_set1_epi32(key[4] as i32),
                _mm256_set1_epi32(key[5] as i32),
                _mm256_set1_epi32(key[6] as i32),
                _mm256_set1_epi32(key[7] as i32),
                iv0, iv1, iv2, iv3,
                _mm256_setzero_si256(),
                _mm256_setzero_si256(),
                _mm256_set1_epi32(64),
                _mm256_set1_epi32(flags as i32),
            ];

            // 128-bit loads + transpose for parent messages.
            let (m0,  m1,  m2,  m3)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 0usize);
            let (m4,  m5,  m6,  m7)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 16usize);
            let (m8,  m9,  m10, m11) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 32usize);
            let (m12, m13, m14, m15) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 48usize);
            let msg = [m0, m1, m2, m3, m4, m5, m6, m7,
                       m8, m9, m10, m11, m12, m13, m14, m15];

            round_avx2!(s, msg, [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15]);
            round_avx2!(s, msg, [ 2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8]);
            round_avx2!(s, msg, [ 3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1]);
            round_avx2!(s, msg, [10, 7,12, 9,14, 3,13,15, 4, 0,11, 2, 5, 8, 1, 6]);
            round_avx2!(s, msg, [12,13, 9,11,15,10,14, 8, 7, 2, 5, 3, 0, 1, 6, 4]);
            round_avx2!(s, msg, [ 9,14,11, 5, 8,12,15, 1,13, 3, 0,10, 2, 6, 4, 7]);
            round_avx2!(s, msg, [11,15, 5, 0, 1, 9, 8, 6,14,10, 2,12, 3, 4, 7,13]);

            let h0 = _mm256_xor_si256(s[0], s[8]);
            let h1 = _mm256_xor_si256(s[1], s[9]);
            let h2 = _mm256_xor_si256(s[2], s[10]);
            let h3 = _mm256_xor_si256(s[3], s[11]);
            let h4 = _mm256_xor_si256(s[4], s[12]);
            let h5 = _mm256_xor_si256(s[5], s[13]);
            let h6 = _mm256_xor_si256(s[6], s[14]);
            let h7 = _mm256_xor_si256(s[7], s[15]);
            let t0 = _mm256_unpacklo_epi32(h0, h1);
            let t1 = _mm256_unpackhi_epi32(h0, h1);
            let t2 = _mm256_unpacklo_epi32(h2, h3);
            let t3 = _mm256_unpackhi_epi32(h2, h3);
            let t4 = _mm256_unpacklo_epi32(h4, h5);
            let t5 = _mm256_unpackhi_epi32(h4, h5);
            let t6 = _mm256_unpacklo_epi32(h6, h7);
            let t7 = _mm256_unpackhi_epi32(h6, h7);
            let u0 = _mm256_unpacklo_epi64(t0, t2);
            let u1 = _mm256_unpackhi_epi64(t0, t2);
            let u2 = _mm256_unpacklo_epi64(t1, t3);
            let u3 = _mm256_unpackhi_epi64(t1, t3);
            let u4 = _mm256_unpacklo_epi64(t4, t6);
            let u5 = _mm256_unpackhi_epi64(t4, t6);
            let u6 = _mm256_unpacklo_epi64(t5, t7);
            let u7 = _mm256_unpackhi_epi64(t5, t7);
            let mut out = [[0u32; 8]; 8];
            _mm256_storeu_si256(out[0].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u0, u4));
            _mm256_storeu_si256(out[1].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u1, u5));
            _mm256_storeu_si256(out[2].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u2, u6));
            _mm256_storeu_si256(out[3].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x20>(u3, u7));
            _mm256_storeu_si256(out[4].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u0, u4));
            _mm256_storeu_si256(out[5].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u1, u5));
            _mm256_storeu_si256(out[6].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u2, u6));
            _mm256_storeu_si256(out[7].as_mut_ptr() as *mut __m256i,
                _mm256_permute2x128_si256::<0x31>(u3, u7));
            out
        }
    }
}

// Safe wrappers.
#[inline(always)]
pub(super) fn hash_8_chunks(
    input: &[u8; 8192],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 8] {
    Blake3::hash_8_chunks_avx2(input, key, counter, flags)
}

#[inline(always)]
fn compress_parents_8(
    cvs: *const [u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [[u32; 8]; 8] {
    Blake3::compress_parents_8_avx2(cvs, key, flags)
}

// 4-way fallback via AVX (VEX-encoded 128-bit).
#[inline(always)]
fn hash_4_chunks(
    input: &[u8; 4096],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 4] {
    super::x86_avx::hash_4_chunks(input, key, counter, flags)
}

#[inline(always)]
pub(super) unsafe fn compress_parents_8_inline(
    cvs: *const [u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [[u32; 8]; 8] {
    let base = cvs as *const u8;
    let p0 = base;
    let p1 = base.add(64);
    let p2 = base.add(128);
    let p3 = base.add(192);
    let p4 = base.add(256);
    let p5 = base.add(320);
    let p6 = base.add(384);
    let p7 = base.add(448);
    let iv0 = _mm256_set1_epi32(super::IV[0] as i32);
    let iv1 = _mm256_set1_epi32(super::IV[1] as i32);
    let iv2 = _mm256_set1_epi32(super::IV[2] as i32);
    let iv3 = _mm256_set1_epi32(super::IV[3] as i32);
    let mut s = [
        _mm256_set1_epi32(key[0] as i32),
        _mm256_set1_epi32(key[1] as i32),
        _mm256_set1_epi32(key[2] as i32),
        _mm256_set1_epi32(key[3] as i32),
        _mm256_set1_epi32(key[4] as i32),
        _mm256_set1_epi32(key[5] as i32),
        _mm256_set1_epi32(key[6] as i32),
        _mm256_set1_epi32(key[7] as i32),
        iv0, iv1, iv2, iv3,
        _mm256_setzero_si256(),
        _mm256_setzero_si256(),
        _mm256_set1_epi32(64),
        _mm256_set1_epi32(flags as i32),
    ];

    let (m0,  m1,  m2,  m3)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 0usize);
    let (m4,  m5,  m6,  m7)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 16usize);
    let (m8,  m9,  m10, m11) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 32usize);
    let (m12, m13, m14, m15) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, 48usize);
    let msg = [m0, m1, m2, m3, m4, m5, m6, m7,
               m8, m9, m10, m11, m12, m13, m14, m15];

    round_avx2_direct!(s, msg, [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15]);
    round_avx2_direct!(s, msg, [ 2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8]);
    round_avx2_direct!(s, msg, [ 3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1]);
    round_avx2_direct!(s, msg, [10, 7,12, 9,14, 3,13,15, 4, 0,11, 2, 5, 8, 1, 6]);
    round_avx2_direct!(s, msg, [12,13, 9,11,15,10,14, 8, 7, 2, 5, 3, 0, 1, 6, 4]);
    round_avx2_direct!(s, msg, [ 9,14,11, 5, 8,12,15, 1,13, 3, 0,10, 2, 6, 4, 7]);
    round_avx2_direct!(s, msg, [11,15, 5, 0, 1, 9, 8, 6,14,10, 2,12, 3, 4, 7,13]);

    let h0 = _mm256_xor_si256(s[0], s[8]);
    let h1 = _mm256_xor_si256(s[1], s[9]);
    let h2 = _mm256_xor_si256(s[2], s[10]);
    let h3 = _mm256_xor_si256(s[3], s[11]);
    let h4 = _mm256_xor_si256(s[4], s[12]);
    let h5 = _mm256_xor_si256(s[5], s[13]);
    let h6 = _mm256_xor_si256(s[6], s[14]);
    let h7 = _mm256_xor_si256(s[7], s[15]);
    let t0 = _mm256_unpacklo_epi32(h0, h1);
    let t1 = _mm256_unpackhi_epi32(h0, h1);
    let t2 = _mm256_unpacklo_epi32(h2, h3);
    let t3 = _mm256_unpackhi_epi32(h2, h3);
    let t4 = _mm256_unpacklo_epi32(h4, h5);
    let t5 = _mm256_unpackhi_epi32(h4, h5);
    let t6 = _mm256_unpacklo_epi32(h6, h7);
    let t7 = _mm256_unpackhi_epi32(h6, h7);
    let u0 = _mm256_unpacklo_epi64(t0, t2);
    let u1 = _mm256_unpackhi_epi64(t0, t2);
    let u2 = _mm256_unpacklo_epi64(t1, t3);
    let u3 = _mm256_unpackhi_epi64(t1, t3);
    let u4 = _mm256_unpacklo_epi64(t4, t6);
    let u5 = _mm256_unpackhi_epi64(t4, t6);
    let u6 = _mm256_unpacklo_epi64(t5, t7);
    let u7 = _mm256_unpackhi_epi64(t5, t7);
    let mut out = [[0u32; 8]; 8];
    _mm256_storeu_si256(out[0].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u0, u4));
    _mm256_storeu_si256(out[1].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u1, u5));
    _mm256_storeu_si256(out[2].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u2, u6));
    _mm256_storeu_si256(out[3].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u3, u7));
    _mm256_storeu_si256(out[4].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u0, u4));
    _mm256_storeu_si256(out[5].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u1, u5));
    _mm256_storeu_si256(out[6].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u2, u6));
    _mm256_storeu_si256(out[7].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u3, u7));
    out
}

/// Inline single-block transform (delegates to AVX/SSSE3 128-bit transform).
#[inline(always)]
unsafe fn transform_inline(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    super::x86_avx::transform_inline(chaining_value, block, block_len, counter, flags)
}

/// Inline 4-way chunk hash (delegates to AVX 128-bit).
#[inline(always)]
unsafe fn hash_4_chunks_inline(
    input: &[u8; 4096],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 4] {
    super::x86_avx::hash_4_chunks_inline(input, key, counter, flags)
}

/// Inline 4-way parallel parent compression (delegates to AVX/SSSE3).
#[inline(always)]
unsafe fn compress_parents_4_inline(
    cvs: *const [u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [[u32; 8]; 4] {
    super::x86_avx::compress_parents_4_inline(cvs, key, flags)
}

#[inline(always)]
pub(super) unsafe fn hash_8_chunks_inline(
    input: &[u8; 8192],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 8] {

    let p0 = input.as_ptr();
    let p1 = p0.add(1024);
    let p2 = p0.add(2048);
    let p3 = p0.add(3072);
    let p4 = p0.add(4096);
    let p5 = p0.add(5120);
    let p6 = p0.add(6144);
    let p7 = p0.add(7168);

    let ctr_lo = _mm256_setr_epi32(
        counter as i32,
        (counter + 1) as i32,
        (counter + 2) as i32,
        (counter + 3) as i32,
        (counter + 4) as i32,
        (counter + 5) as i32,
        (counter + 6) as i32,
        (counter + 7) as i32,
    );
    let ctr_hi = _mm256_setr_epi32(
        (counter >> 32) as i32,
        ((counter + 1) >> 32) as i32,
        ((counter + 2) >> 32) as i32,
        ((counter + 3) >> 32) as i32,
        ((counter + 4) >> 32) as i32,
        ((counter + 5) >> 32) as i32,
        ((counter + 6) >> 32) as i32,
        ((counter + 7) >> 32) as i32,
    );

    let iv0 = _mm256_set1_epi32(super::IV[0] as i32);
    let iv1 = _mm256_set1_epi32(super::IV[1] as i32);
    let iv2 = _mm256_set1_epi32(super::IV[2] as i32);
    let iv3 = _mm256_set1_epi32(super::IV[3] as i32);
    let blen = _mm256_set1_epi32(64);

    let mut h0 = _mm256_set1_epi32(key[0] as i32);
    let mut h1 = _mm256_set1_epi32(key[1] as i32);
    let mut h2 = _mm256_set1_epi32(key[2] as i32);
    let mut h3 = _mm256_set1_epi32(key[3] as i32);
    let mut h4 = _mm256_set1_epi32(key[4] as i32);
    let mut h5 = _mm256_set1_epi32(key[5] as i32);
    let mut h6 = _mm256_set1_epi32(key[6] as i32);
    let mut h7 = _mm256_set1_epi32(key[7] as i32);

    for blk in 0u32..16 {
        let bf = match blk {
            0 => flags | super::CHUNK_START,
            15 => flags | super::CHUNK_END,
            _ => flags,
        };

        let mut s = [h0, h1, h2, h3, h4, h5, h6, h7,
                     iv0, iv1, iv2, iv3,
                     ctr_lo, ctr_hi, blen, _mm256_set1_epi32(bf as i32)];

        let byte_off = blk as usize * 64;

        let (m0,  m1,  m2,  m3)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off);
        let (m4,  m5,  m6,  m7)  = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off + 16);
        let (m8,  m9,  m10, m11) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off + 32);
        let (m12, m13, m14, m15) = transpose_msg_128!(p0, p1, p2, p3, p4, p5, p6, p7, byte_off + 48);
        let msg = [m0, m1, m2, m3, m4, m5, m6, m7,
                   m8, m9, m10, m11, m12, m13, m14, m15];

        _mm_prefetch(p0.add(byte_off + 256) as *const i8, _MM_HINT_T0);
        _mm_prefetch(p1.add(byte_off + 256) as *const i8, _MM_HINT_T0);
        _mm_prefetch(p2.add(byte_off + 256) as *const i8, _MM_HINT_T0);
        _mm_prefetch(p3.add(byte_off + 256) as *const i8, _MM_HINT_T0);
        _mm_prefetch(p4.add(byte_off + 256) as *const i8, _MM_HINT_T0);
        _mm_prefetch(p5.add(byte_off + 256) as *const i8, _MM_HINT_T0);
        _mm_prefetch(p6.add(byte_off + 256) as *const i8, _MM_HINT_T0);
        _mm_prefetch(p7.add(byte_off + 256) as *const i8, _MM_HINT_T0);

        round_avx2!(s, msg, [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15]);
        round_avx2!(s, msg, [ 2, 6, 3,10, 7, 0, 4,13, 1,11,12, 5, 9,14,15, 8]);
        round_avx2!(s, msg, [ 3, 4,10,12,13, 2, 7,14, 6, 5, 9, 0,11,15, 8, 1]);
        round_avx2!(s, msg, [10, 7,12, 9,14, 3,13,15, 4, 0,11, 2, 5, 8, 1, 6]);
        round_avx2!(s, msg, [12,13, 9,11,15,10,14, 8, 7, 2, 5, 3, 0, 1, 6, 4]);
        round_avx2!(s, msg, [ 9,14,11, 5, 8,12,15, 1,13, 3, 0,10, 2, 6, 4, 7]);
        round_avx2!(s, msg, [11,15, 5, 0, 1, 9, 8, 6,14,10, 2,12, 3, 4, 7,13]);

        h0 = _mm256_xor_si256(s[0], s[8]);
        h1 = _mm256_xor_si256(s[1], s[9]);
        h2 = _mm256_xor_si256(s[2], s[10]);
        h3 = _mm256_xor_si256(s[3], s[11]);
        h4 = _mm256_xor_si256(s[4], s[12]);
        h5 = _mm256_xor_si256(s[5], s[13]);
        h6 = _mm256_xor_si256(s[6], s[14]);
        h7 = _mm256_xor_si256(s[7], s[15]);
    }

    // Extract per-chunk CVs via SIMD 8×8 transpose.
    let t0 = _mm256_unpacklo_epi32(h0, h1);
    let t1 = _mm256_unpackhi_epi32(h0, h1);
    let t2 = _mm256_unpacklo_epi32(h2, h3);
    let t3 = _mm256_unpackhi_epi32(h2, h3);
    let t4 = _mm256_unpacklo_epi32(h4, h5);
    let t5 = _mm256_unpackhi_epi32(h4, h5);
    let t6 = _mm256_unpacklo_epi32(h6, h7);
    let t7 = _mm256_unpackhi_epi32(h6, h7);
    let u0 = _mm256_unpacklo_epi64(t0, t2);
    let u1 = _mm256_unpackhi_epi64(t0, t2);
    let u2 = _mm256_unpacklo_epi64(t1, t3);
    let u3 = _mm256_unpackhi_epi64(t1, t3);
    let u4 = _mm256_unpacklo_epi64(t4, t6);
    let u5 = _mm256_unpackhi_epi64(t4, t6);
    let u6 = _mm256_unpacklo_epi64(t5, t7);
    let u7 = _mm256_unpackhi_epi64(t5, t7);
    let mut out = [[0u32; 8]; 8];
    _mm256_storeu_si256(out[0].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u0, u4));
    _mm256_storeu_si256(out[1].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u1, u5));
    _mm256_storeu_si256(out[2].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u2, u6));
    _mm256_storeu_si256(out[3].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x20>(u3, u7));
    _mm256_storeu_si256(out[4].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u0, u4));
    _mm256_storeu_si256(out[5].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u1, u5));
    _mm256_storeu_si256(out[6].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u2, u6));
    _mm256_storeu_si256(out[7].as_mut_ptr() as *mut __m256i,
        _mm256_permute2x128_si256::<0x31>(u3, u7));
    out
}

// ---------------------------------------------------------------------------
// Slice-level: two-tier (8-way AVX2 → 4-way AVX fallback)
// with 8-wide SIMD parent batching for tree merge.
// ---------------------------------------------------------------------------
blake3_impl!(transform, hash_8_chunks, 8, hash_4_chunks, 4;
    parent_batch: compress_parents_8, 8;
    oneshot_feature: "avx2");

#[cfg(test)]
mod tests {
    use super::Blake3;

    blake3_test_case!(require_hw: "x86" => ("avx2"), "x86_64" => ("avx2"));
}
