// BLAKE3 – x86/x86_64 AVX-512 implementation.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

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

#[inline(always)]
unsafe fn transform_inline(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
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

    macro_rules! round_vl {
        ($b:expr,
         $s0:expr,$s1:expr,$s2:expr,$s3:expr,
         $s4:expr,$s5:expr,$s6:expr,$s7:expr,
         $s8:expr,$s9:expr,$s10:expr,$s11:expr,
         $s12:expr,$s13:expr,$s14:expr,$s15:expr) => {{
            // Column half-round
            let mx_col = _mm_set_epi32(
                $b[$s6] as i32, $b[$s4] as i32,
                $b[$s2] as i32, $b[$s0] as i32,
            );
            let my_col = _mm_set_epi32(
                $b[$s7] as i32, $b[$s5] as i32,
                $b[$s3] as i32, $b[$s1] as i32,
            );
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), mx_col);
            r3 = _mm_ror_epi32::<16>(_mm_xor_si128(r3, r0));
            r2 = _mm_add_epi32(r2, r3);
            r1 = _mm_ror_epi32::<12>(_mm_xor_si128(r1, r2));
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), my_col);
            r3 = _mm_ror_epi32::<8>(_mm_xor_si128(r3, r0));
            r2 = _mm_add_epi32(r2, r3);
            r1 = _mm_ror_epi32::<7>(_mm_xor_si128(r1, r2));

            // Diagonal permutation
            const DIAG_R1: i32 = 0b_00_11_10_01; // 1,2,3,0
            const DIAG_R2: i32 = 0b_01_00_11_10; // 2,3,0,1
            const DIAG_R3: i32 = 0b_10_01_00_11; // 3,0,1,2
            r1 = _mm_shuffle_epi32(r1, DIAG_R1);
            r2 = _mm_shuffle_epi32(r2, DIAG_R2);
            r3 = _mm_shuffle_epi32(r3, DIAG_R3);

            // Diagonal half-round
            let mx_diag = _mm_set_epi32(
                $b[$s14] as i32, $b[$s12] as i32,
                $b[$s10] as i32, $b[$s8] as i32,
            );
            let my_diag = _mm_set_epi32(
                $b[$s15] as i32, $b[$s13] as i32,
                $b[$s11] as i32, $b[$s9] as i32,
            );
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), mx_diag);
            r3 = _mm_ror_epi32::<16>(_mm_xor_si128(r3, r0));
            r2 = _mm_add_epi32(r2, r3);
            r1 = _mm_ror_epi32::<12>(_mm_xor_si128(r1, r2));
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), my_diag);
            r3 = _mm_ror_epi32::<8>(_mm_xor_si128(r3, r0));
            r2 = _mm_add_epi32(r2, r3);
            r1 = _mm_ror_epi32::<7>(_mm_xor_si128(r1, r2));

            // Un-diagonalize
            r1 = _mm_shuffle_epi32(r1, DIAG_R3);
            r2 = _mm_shuffle_epi32(r2, DIAG_R2);
            r3 = _mm_shuffle_epi32(r3, DIAG_R1);
        }};
    }

    round_vl!(block, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    round_vl!(block, 2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8);
    round_vl!(block, 3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1);
    round_vl!(block, 10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6);
    round_vl!(block, 12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4);
    round_vl!(block, 9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7);
    round_vl!(block, 11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13);

    let lo = _mm_xor_si128(r0, r2);
    let hi = _mm_xor_si128(r1, r3);
    let lo2 = _mm_xor_si128(r2, cv0);
    let hi2 = _mm_xor_si128(r3, cv1);

    let mut out = [0u32; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, lo);
    _mm_storeu_si128(out.as_mut_ptr().add(4) as *mut __m128i, hi);
    _mm_storeu_si128(out.as_mut_ptr().add(8) as *mut __m128i, lo2);
    _mm_storeu_si128(out.as_mut_ptr().add(12) as *mut __m128i, hi2);
    out
}

macro_rules! avx512_load_pair {
    ($p:expr, $k:expr, $off:expr) => {{
        let lo = _mm256_loadu_si256($p[$k].add($off) as *const __m256i);
        _mm512_inserti64x4::<1>(
            _mm512_castsi256_si512(lo),
            _mm256_loadu_si256($p[$k + 8].add($off) as *const __m256i),
        )
    }};
}
macro_rules! avx512_shufps {
    ($a:expr, $b:expr, $imm:literal) => {
        _mm512_castps_si512(_mm512_shuffle_ps::<$imm>(
            _mm512_castsi512_ps($a),
            _mm512_castsi512_ps($b),
        ))
    };
}
macro_rules! avx512_transpose_half {
    ($p:expr, $off:expr, $idx0:expr, $idx1:expr) => {{
        let a0 = avx512_load_pair!($p, 0, $off);
        let a1 = avx512_load_pair!($p, 1, $off);
        let lo01 = _mm512_unpacklo_epi64(a0, a1);
        let hi01 = _mm512_unpackhi_epi64(a0, a1);
        let a2 = avx512_load_pair!($p, 2, $off);
        let a3 = avx512_load_pair!($p, 3, $off);
        let lo23 = _mm512_unpacklo_epi64(a2, a3);
        let hi23 = _mm512_unpackhi_epi64(a2, a3);
        let a4 = avx512_load_pair!($p, 4, $off);
        let a5 = avx512_load_pair!($p, 5, $off);
        let lo45 = _mm512_unpacklo_epi64(a4, a5);
        let hi45 = _mm512_unpackhi_epi64(a4, a5);
        let a6 = avx512_load_pair!($p, 6, $off);
        let a7 = avx512_load_pair!($p, 7, $off);
        let lo67 = _mm512_unpacklo_epi64(a6, a7);
        let hi67 = _mm512_unpackhi_epi64(a6, a7);
        // vshufps 0x88 = dwords [0,2] per lane; 0xDD = dwords [1,3].
        let t0 = avx512_shufps!(lo01, lo23, 0x88);
        let t1 = avx512_shufps!(lo45, lo67, 0x88);
        let w0 = _mm512_permutex2var_epi32(t0, $idx0, t1);
        let w4 = _mm512_permutex2var_epi32(t0, $idx1, t1);
        let t0 = avx512_shufps!(lo01, lo23, 0xDD);
        let t1 = avx512_shufps!(lo45, lo67, 0xDD);
        let w1 = _mm512_permutex2var_epi32(t0, $idx0, t1);
        let w5 = _mm512_permutex2var_epi32(t0, $idx1, t1);
        let t0 = avx512_shufps!(hi01, hi23, 0x88);
        let t1 = avx512_shufps!(hi45, hi67, 0x88);
        let w2 = _mm512_permutex2var_epi32(t0, $idx0, t1);
        let w6 = _mm512_permutex2var_epi32(t0, $idx1, t1);
        let t0 = avx512_shufps!(hi01, hi23, 0xDD);
        let t1 = avx512_shufps!(hi45, hi67, 0xDD);
        let w3 = _mm512_permutex2var_epi32(t0, $idx0, t1);
        let w7 = _mm512_permutex2var_epi32(t0, $idx1, t1);
        (w0, w1, w2, w3, w4, w5, w6, w7)
    }};
}

impl Blake3 {
    #[inline(always)]
    fn hash_16_chunks_avx512(
        input: &[u8; 16384],
        key: &[u32; 8],
        counter: u64,
        flags: u32,
    ) -> [[u32; 8]; 16] {
        unsafe {
            let p: [*const u8; 16] = [
                input.as_ptr(),
                input.as_ptr().add(1024),
                input.as_ptr().add(2048),
                input.as_ptr().add(3072),
                input.as_ptr().add(4096),
                input.as_ptr().add(5120),
                input.as_ptr().add(6144),
                input.as_ptr().add(7168),
                input.as_ptr().add(8192),
                input.as_ptr().add(9216),
                input.as_ptr().add(10240),
                input.as_ptr().add(11264),
                input.as_ptr().add(12288),
                input.as_ptr().add(13312),
                input.as_ptr().add(14336),
                input.as_ptr().add(15360),
            ];

            let ctr_lo = _mm512_setr_epi32(
                counter as i32,
                (counter + 1) as i32,
                (counter + 2) as i32,
                (counter + 3) as i32,
                (counter + 4) as i32,
                (counter + 5) as i32,
                (counter + 6) as i32,
                (counter + 7) as i32,
                (counter + 8) as i32,
                (counter + 9) as i32,
                (counter + 10) as i32,
                (counter + 11) as i32,
                (counter + 12) as i32,
                (counter + 13) as i32,
                (counter + 14) as i32,
                (counter + 15) as i32,
            );
            let ctr_hi = _mm512_setr_epi32(
                (counter >> 32) as i32,
                ((counter + 1) >> 32) as i32,
                ((counter + 2) >> 32) as i32,
                ((counter + 3) >> 32) as i32,
                ((counter + 4) >> 32) as i32,
                ((counter + 5) >> 32) as i32,
                ((counter + 6) >> 32) as i32,
                ((counter + 7) >> 32) as i32,
                ((counter + 8) >> 32) as i32,
                ((counter + 9) >> 32) as i32,
                ((counter + 10) >> 32) as i32,
                ((counter + 11) >> 32) as i32,
                ((counter + 12) >> 32) as i32,
                ((counter + 13) >> 32) as i32,
                ((counter + 14) >> 32) as i32,
                ((counter + 15) >> 32) as i32,
            );

            let mut h0 = _mm512_set1_epi32(key[0] as i32);
            let mut h1 = _mm512_set1_epi32(key[1] as i32);
            let mut h2 = _mm512_set1_epi32(key[2] as i32);
            let mut h3 = _mm512_set1_epi32(key[3] as i32);
            let mut h4 = _mm512_set1_epi32(key[4] as i32);
            let mut h5 = _mm512_set1_epi32(key[5] as i32);
            let mut h6 = _mm512_set1_epi32(key[6] as i32);
            let mut h7 = _mm512_set1_epi32(key[7] as i32);

            for blk in 0u32..16 {
                let bf = match blk {
                    0 => flags | super::CHUNK_START,
                    15 => flags | super::CHUNK_END,
                    _ => flags,
                };

                let byte_off = blk as usize * 64;

                // Full-zmm 16×16 transpose: load one 64-byte block
                let r0  = _mm512_loadu_si512(p[0].add(byte_off)  as *const __m512i);
                let r1  = _mm512_loadu_si512(p[1].add(byte_off)  as *const __m512i);
                let r2  = _mm512_loadu_si512(p[2].add(byte_off)  as *const __m512i);
                let r3  = _mm512_loadu_si512(p[3].add(byte_off)  as *const __m512i);
                let r4  = _mm512_loadu_si512(p[4].add(byte_off)  as *const __m512i);
                let r5  = _mm512_loadu_si512(p[5].add(byte_off)  as *const __m512i);
                let r6  = _mm512_loadu_si512(p[6].add(byte_off)  as *const __m512i);
                let r7  = _mm512_loadu_si512(p[7].add(byte_off)  as *const __m512i);
                let r8  = _mm512_loadu_si512(p[8].add(byte_off)  as *const __m512i);
                let r9  = _mm512_loadu_si512(p[9].add(byte_off)  as *const __m512i);
                let r10 = _mm512_loadu_si512(p[10].add(byte_off) as *const __m512i);
                let r11 = _mm512_loadu_si512(p[11].add(byte_off) as *const __m512i);
                let r12 = _mm512_loadu_si512(p[12].add(byte_off) as *const __m512i);
                let r13 = _mm512_loadu_si512(p[13].add(byte_off) as *const __m512i);
                let r14 = _mm512_loadu_si512(p[14].add(byte_off) as *const __m512i);
                let r15 = _mm512_loadu_si512(p[15].add(byte_off) as *const __m512i);

                // Stage 1: 32-bit interleave within 128-bit lanes.
                let t0  = _mm512_unpacklo_epi32(r0,  r1);
                let t1  = _mm512_unpackhi_epi32(r0,  r1);
                let t2  = _mm512_unpacklo_epi32(r2,  r3);
                let t3  = _mm512_unpackhi_epi32(r2,  r3);
                let t4  = _mm512_unpacklo_epi32(r4,  r5);
                let t5  = _mm512_unpackhi_epi32(r4,  r5);
                let t6  = _mm512_unpacklo_epi32(r6,  r7);
                let t7  = _mm512_unpackhi_epi32(r6,  r7);
                let t8  = _mm512_unpacklo_epi32(r8,  r9);
                let t9  = _mm512_unpackhi_epi32(r8,  r9);
                let t10 = _mm512_unpacklo_epi32(r10, r11);
                let t11 = _mm512_unpackhi_epi32(r10, r11);
                let t12 = _mm512_unpacklo_epi32(r12, r13);
                let t13 = _mm512_unpackhi_epi32(r12, r13);
                let t14 = _mm512_unpacklo_epi32(r14, r15);
                let t15 = _mm512_unpackhi_epi32(r14, r15);

                // Stage 2: 64-bit interleave within 128-bit lanes.
                let u0  = _mm512_unpacklo_epi64(t0, t2);
                let u1  = _mm512_unpackhi_epi64(t0, t2);
                let u2  = _mm512_unpacklo_epi64(t1, t3);
                let u3  = _mm512_unpackhi_epi64(t1, t3);
                let u4  = _mm512_unpacklo_epi64(t4, t6);
                let u5  = _mm512_unpackhi_epi64(t4, t6);
                let u6  = _mm512_unpacklo_epi64(t5, t7);
                let u7  = _mm512_unpackhi_epi64(t5, t7);
                let u8  = _mm512_unpacklo_epi64(t8,  t10);
                let u9  = _mm512_unpackhi_epi64(t8,  t10);
                let u10 = _mm512_unpacklo_epi64(t9,  t11);
                let u11 = _mm512_unpackhi_epi64(t9,  t11);
                let u12 = _mm512_unpacklo_epi64(t12, t14);
                let u13 = _mm512_unpackhi_epi64(t12, t14);
                let u14 = _mm512_unpacklo_epi64(t13, t15);
                let u15 = _mm512_unpackhi_epi64(t13, t15);

                // Stages 3-4: cross-lane 128-bit shuffles.
                macro_rules! merge4 {
                    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                        let ab_lo = _mm512_shuffle_i32x4::<0x44>($a, $b);
                        let ab_hi = _mm512_shuffle_i32x4::<0xEE>($a, $b);
                        let cd_lo = _mm512_shuffle_i32x4::<0x44>($c, $d);
                        let cd_hi = _mm512_shuffle_i32x4::<0xEE>($c, $d);
                        (
                            _mm512_shuffle_i32x4::<0x88>(ab_lo, cd_lo),
                            _mm512_shuffle_i32x4::<0xDD>(ab_lo, cd_lo),
                            _mm512_shuffle_i32x4::<0x88>(ab_hi, cd_hi),
                            _mm512_shuffle_i32x4::<0xDD>(ab_hi, cd_hi),
                        )
                    }};
                }
                let (m0,  m4,  m8,  m12) = merge4!(u0, u4, u8, u12);
                let (m1,  m5,  m9,  m13) = merge4!(u1, u5, u9, u13);
                let (m2,  m6,  m10, m14) = merge4!(u2, u6, u10, u14);
                let (m3,  m7,  m11, m15) = merge4!(u3, u7, u11, u15);

                let next_off = byte_off + 64;
                for i in 0..16 {
                    _mm_prefetch::<_MM_HINT_T0>(p[i].add(next_off) as *const i8);
                }

                let (mut s0, mut s1, mut s2, mut s3) = (h0, h1, h2, h3);
                let (mut s4, mut s5, mut s6, mut s7) = (h4, h5, h6, h7);

                // s8..s15: IV + counter + block_len + flags.
                let (mut s8, mut s9, mut s10, mut s11) = (
                    _mm512_set1_epi32(super::IV[0] as i32),
                    _mm512_set1_epi32(super::IV[1] as i32),
                    _mm512_set1_epi32(super::IV[2] as i32),
                    _mm512_set1_epi32(super::IV[3] as i32),
                );
                let (mut s12, mut s13, mut s14, mut s15) = (
                    ctr_lo, ctr_hi,
                    _mm512_set1_epi32(64),
                    _mm512_set1_epi32(bf as i32),
                );

                macro_rules! round16 {
                    ($ma:expr,$mb:expr,$mc:expr,$md:expr,
                     $me:expr,$mf:expr,$mg:expr,$mh:expr,
                     $mi:expr,$mj:expr,$mk:expr,$ml:expr,
                     $mm_:expr,$mn:expr,$mo:expr,$mp_:expr) => {{
                        // Column phase
                        s0 = _mm512_add_epi32(s0, s4);
                        s0 = _mm512_add_epi32(s0, $ma);
                        s1 = _mm512_add_epi32(s1, s5);
                        s1 = _mm512_add_epi32(s1, $mc);
                        s2 = _mm512_add_epi32(s2, s6);
                        s2 = _mm512_add_epi32(s2, $me);
                        s3 = _mm512_add_epi32(s3, s7);
                        s3 = _mm512_add_epi32(s3, $mg);
                        s12 = _mm512_xor_si512(s12, s0);
                        s13 = _mm512_xor_si512(s13, s1);
                        s14 = _mm512_xor_si512(s14, s2);
                        s15 = _mm512_xor_si512(s15, s3);
                        s12 = _mm512_rol_epi32::<16>(s12);
                        s13 = _mm512_rol_epi32::<16>(s13);
                        s14 = _mm512_rol_epi32::<16>(s14);
                        s15 = _mm512_rol_epi32::<16>(s15);
                        s8  = _mm512_add_epi32(s8,  s12);
                        s9  = _mm512_add_epi32(s9,  s13);
                        s10 = _mm512_add_epi32(s10, s14);
                        s11 = _mm512_add_epi32(s11, s15);
                        s4 = _mm512_xor_si512(s4, s8);
                        s5 = _mm512_xor_si512(s5, s9);
                        s6 = _mm512_xor_si512(s6, s10);
                        s7 = _mm512_xor_si512(s7, s11);
                        s4 = _mm512_rol_epi32::<20>(s4);
                        s5 = _mm512_rol_epi32::<20>(s5);
                        s6 = _mm512_rol_epi32::<20>(s6);
                        s7 = _mm512_rol_epi32::<20>(s7);
                        s0 = _mm512_add_epi32(s0, s4);
                        s0 = _mm512_add_epi32(s0, $mb);
                        s1 = _mm512_add_epi32(s1, s5);
                        s1 = _mm512_add_epi32(s1, $md);
                        s2 = _mm512_add_epi32(s2, s6);
                        s2 = _mm512_add_epi32(s2, $mf);
                        s3 = _mm512_add_epi32(s3, s7);
                        s3 = _mm512_add_epi32(s3, $mh);
                        s12 = _mm512_xor_si512(s12, s0);
                        s13 = _mm512_xor_si512(s13, s1);
                        s14 = _mm512_xor_si512(s14, s2);
                        s15 = _mm512_xor_si512(s15, s3);
                        s12 = _mm512_rol_epi32::<24>(s12);
                        s13 = _mm512_rol_epi32::<24>(s13);
                        s14 = _mm512_rol_epi32::<24>(s14);
                        s15 = _mm512_rol_epi32::<24>(s15);
                        s8  = _mm512_add_epi32(s8,  s12);
                        s9  = _mm512_add_epi32(s9,  s13);
                        s10 = _mm512_add_epi32(s10, s14);
                        s11 = _mm512_add_epi32(s11, s15);
                        s4 = _mm512_xor_si512(s4, s8);
                        s5 = _mm512_xor_si512(s5, s9);
                        s6 = _mm512_xor_si512(s6, s10);
                        s7 = _mm512_xor_si512(s7, s11);
                        s4 = _mm512_rol_epi32::<25>(s4);
                        s5 = _mm512_rol_epi32::<25>(s5);
                        s6 = _mm512_rol_epi32::<25>(s6);
                        s7 = _mm512_rol_epi32::<25>(s7);
                        // Diagonal phase
                        s0 = _mm512_add_epi32(s0, s5);
                        s0 = _mm512_add_epi32(s0, $mi);
                        s1 = _mm512_add_epi32(s1, s6);
                        s1 = _mm512_add_epi32(s1, $mk);
                        s2 = _mm512_add_epi32(s2, s7);
                        s2 = _mm512_add_epi32(s2, $mm_);
                        s3 = _mm512_add_epi32(s3, s4);
                        s3 = _mm512_add_epi32(s3, $mo);
                        s15 = _mm512_xor_si512(s15, s0);
                        s12 = _mm512_xor_si512(s12, s1);
                        s13 = _mm512_xor_si512(s13, s2);
                        s14 = _mm512_xor_si512(s14, s3);
                        s15 = _mm512_rol_epi32::<16>(s15);
                        s12 = _mm512_rol_epi32::<16>(s12);
                        s13 = _mm512_rol_epi32::<16>(s13);
                        s14 = _mm512_rol_epi32::<16>(s14);
                        s10 = _mm512_add_epi32(s10, s15);
                        s11 = _mm512_add_epi32(s11, s12);
                        s8  = _mm512_add_epi32(s8,  s13);
                        s9  = _mm512_add_epi32(s9,  s14);
                        s5 = _mm512_xor_si512(s5, s10);
                        s6 = _mm512_xor_si512(s6, s11);
                        s7 = _mm512_xor_si512(s7, s8);
                        s4 = _mm512_xor_si512(s4, s9);
                        s5 = _mm512_rol_epi32::<20>(s5);
                        s6 = _mm512_rol_epi32::<20>(s6);
                        s7 = _mm512_rol_epi32::<20>(s7);
                        s4 = _mm512_rol_epi32::<20>(s4);
                        s0 = _mm512_add_epi32(s0, s5);
                        s0 = _mm512_add_epi32(s0, $mj);
                        s1 = _mm512_add_epi32(s1, s6);
                        s1 = _mm512_add_epi32(s1, $ml);
                        s2 = _mm512_add_epi32(s2, s7);
                        s2 = _mm512_add_epi32(s2, $mn);
                        s3 = _mm512_add_epi32(s3, s4);
                        s3 = _mm512_add_epi32(s3, $mp_);
                        s15 = _mm512_xor_si512(s15, s0);
                        s12 = _mm512_xor_si512(s12, s1);
                        s13 = _mm512_xor_si512(s13, s2);
                        s14 = _mm512_xor_si512(s14, s3);
                        s15 = _mm512_rol_epi32::<24>(s15);
                        s12 = _mm512_rol_epi32::<24>(s12);
                        s13 = _mm512_rol_epi32::<24>(s13);
                        s14 = _mm512_rol_epi32::<24>(s14);
                        s10 = _mm512_add_epi32(s10, s15);
                        s11 = _mm512_add_epi32(s11, s12);
                        s8  = _mm512_add_epi32(s8,  s13);
                        s9  = _mm512_add_epi32(s9,  s14);
                        s5 = _mm512_xor_si512(s5, s10);
                        s6 = _mm512_xor_si512(s6, s11);
                        s7 = _mm512_xor_si512(s7, s8);
                        s4 = _mm512_xor_si512(s4, s9);
                        s5 = _mm512_rol_epi32::<25>(s5);
                        s6 = _mm512_rol_epi32::<25>(s6);
                        s7 = _mm512_rol_epi32::<25>(s7);
                        s4 = _mm512_rol_epi32::<25>(s4);
                    }};
                }

                round16!(m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15);
                round16!(m2,m6,m3,m10,m7,m0,m4,m13,m1,m11,m12,m5,m9,m14,m15,m8);
                round16!(m3,m4,m10,m12,m13,m2,m7,m14,m6,m5,m9,m0,m11,m15,m8,m1);
                round16!(m10,m7,m12,m9,m14,m3,m13,m15,m4,m0,m11,m2,m5,m8,m1,m6);
                round16!(m12,m13,m9,m11,m15,m10,m14,m8,m7,m2,m5,m3,m0,m1,m6,m4);
                round16!(m9,m14,m11,m5,m8,m12,m15,m1,m13,m3,m0,m10,m2,m6,m4,m7);
                round16!(m11,m15,m5,m0,m1,m9,m8,m6,m14,m10,m2,m12,m3,m4,m7,m13);

                h0 = _mm512_xor_si512(s0, s8);
                h1 = _mm512_xor_si512(s1, s9);
                h2 = _mm512_xor_si512(s2, s10);
                h3 = _mm512_xor_si512(s3, s11);
                h4 = _mm512_xor_si512(s4, s12);
                h5 = _mm512_xor_si512(s5, s13);
                h6 = _mm512_xor_si512(s6, s14);
                h7 = _mm512_xor_si512(s7, s15);
            }

            macro_rules! transpose_8x16_zmm {
                ($h0:expr, $h1:expr, $h2:expr, $h3:expr,
                 $h4:expr, $h5:expr, $h6:expr, $h7:expr) => {{
                    // Stage 1: 32-bit interleave
                    let t0 = _mm512_unpacklo_epi32($h0, $h1);
                    let t1 = _mm512_unpackhi_epi32($h0, $h1);
                    let t2 = _mm512_unpacklo_epi32($h2, $h3);
                    let t3 = _mm512_unpackhi_epi32($h2, $h3);
                    let t4 = _mm512_unpacklo_epi32($h4, $h5);
                    let t5 = _mm512_unpackhi_epi32($h4, $h5);
                    let t6 = _mm512_unpacklo_epi32($h6, $h7);
                    let t7 = _mm512_unpackhi_epi32($h6, $h7);
                    // Stage 2: 64-bit interleave
                    let u0 = _mm512_unpacklo_epi64(t0, t2);
                    let u1 = _mm512_unpackhi_epi64(t0, t2);
                    let u2 = _mm512_unpacklo_epi64(t1, t3);
                    let u3 = _mm512_unpackhi_epi64(t1, t3);
                    let u4 = _mm512_unpacklo_epi64(t4, t6);
                    let u5 = _mm512_unpackhi_epi64(t4, t6);
                    let u6 = _mm512_unpacklo_epi64(t5, t7);
                    let u7 = _mm512_unpackhi_epi64(t5, t7);
                    // Stage 3: 128-bit cross-lane shuffle
                    let v0 = _mm512_shuffle_i32x4::<0x88>(u0, u4);
                    let v1 = _mm512_shuffle_i32x4::<0x88>(u1, u5);
                    let v2 = _mm512_shuffle_i32x4::<0x88>(u2, u6);
                    let v3 = _mm512_shuffle_i32x4::<0x88>(u3, u7);
                    let v4 = _mm512_shuffle_i32x4::<0xDD>(u0, u4);
                    let v5 = _mm512_shuffle_i32x4::<0xDD>(u1, u5);
                    let v6 = _mm512_shuffle_i32x4::<0xDD>(u2, u6);
                    let v7 = _mm512_shuffle_i32x4::<0xDD>(u3, u7);
                    // Stage 4: final cross-lane
                    [
                        _mm512_shuffle_i32x4::<0x88>(v0, v1),
                        _mm512_shuffle_i32x4::<0x88>(v2, v3),
                        _mm512_shuffle_i32x4::<0x88>(v4, v5),
                        _mm512_shuffle_i32x4::<0x88>(v6, v7),
                        _mm512_shuffle_i32x4::<0xDD>(v0, v1),
                        _mm512_shuffle_i32x4::<0xDD>(v2, v3),
                        _mm512_shuffle_i32x4::<0xDD>(v4, v5),
                        _mm512_shuffle_i32x4::<0xDD>(v6, v7),
                    ]
                }};
            }

            let out_zmm = transpose_8x16_zmm!(h0, h1, h2, h3, h4, h5, h6, h7);
            let mut out = [[0u32; 8]; 16];
            // Each zmm = 64 bytes = 2 chunk CVs (each 32 bytes).
            let dst = out.as_mut_ptr() as *mut __m512i;
            for j in 0..8 {
                _mm512_storeu_si512(dst.add(j), out_zmm[j]);
            }
            out
        }
    }

    #[inline(always)]
    fn compress_parents_16_avx512(
        cvs: *const [u32; 8],
        key: &[u32; 8],
        flags: u32,
    ) -> [[u32; 8]; 16] {
        unsafe {
            let base = cvs as *const u8;
            let p: [*const u8; 16] = [
                base,
                base.add(64),
                base.add(128),
                base.add(192),
                base.add(256),
                base.add(320),
                base.add(384),
                base.add(448),
                base.add(512),
                base.add(576),
                base.add(640),
                base.add(704),
                base.add(768),
                base.add(832),
                base.add(896),
                base.add(960),
            ];

            let (mut s0, mut s1, mut s2, mut s3) = (
                _mm512_set1_epi32(key[0] as i32),
                _mm512_set1_epi32(key[1] as i32),
                _mm512_set1_epi32(key[2] as i32),
                _mm512_set1_epi32(key[3] as i32),
            );
            let (mut s4, mut s5, mut s6, mut s7) = (
                _mm512_set1_epi32(key[4] as i32),
                _mm512_set1_epi32(key[5] as i32),
                _mm512_set1_epi32(key[6] as i32),
                _mm512_set1_epi32(key[7] as i32),
            );

            let idx0 = _mm512_setr_epi32(
                0, 1, 2, 3, 16, 17, 18, 19,
                8, 9, 10, 11, 24, 25, 26, 27,
            );
            let idx1 = _mm512_setr_epi32(
                4, 5, 6, 7, 20, 21, 22, 23,
                12, 13, 14, 15, 28, 29, 30, 31,
            );
            let (m0, m1, m2, m3, m4, m5, m6, m7) =
                avx512_transpose_half!(p, 0usize, idx0, idx1);
            let (m8, m9, m10, m11, m12, m13, m14, m15) =
                avx512_transpose_half!(p, 32usize, idx0, idx1);

            let mut msg_buf = [_mm512_setzero_si512(); 16];
            let mp = msg_buf.as_mut_ptr() as *mut __m512i;
            _mm512_store_si512(mp.add(0),  m0);
            _mm512_store_si512(mp.add(1),  m1);
            _mm512_store_si512(mp.add(2),  m2);
            _mm512_store_si512(mp.add(3),  m3);
            _mm512_store_si512(mp.add(4),  m4);
            _mm512_store_si512(mp.add(5),  m5);
            _mm512_store_si512(mp.add(6),  m6);
            _mm512_store_si512(mp.add(7),  m7);
            _mm512_store_si512(mp.add(8),  m8);
            _mm512_store_si512(mp.add(9),  m9);
            _mm512_store_si512(mp.add(10), m10);
            _mm512_store_si512(mp.add(11), m11);
            _mm512_store_si512(mp.add(12), m12);
            _mm512_store_si512(mp.add(13), m13);
            _mm512_store_si512(mp.add(14), m14);
            _mm512_store_si512(mp.add(15), m15);

            let (mut s8, mut s9, mut s10, mut s11) = (
                _mm512_set1_epi32(super::IV[0] as i32),
                _mm512_set1_epi32(super::IV[1] as i32),
                _mm512_set1_epi32(super::IV[2] as i32),
                _mm512_set1_epi32(super::IV[3] as i32),
            );
            let (mut s12, mut s13, mut s14, mut s15) = (
                _mm512_setzero_si512(), // counter_lo = 0
                _mm512_setzero_si512(), // counter_hi = 0
                _mm512_set1_epi32(64),
                _mm512_set1_epi32(flags as i32),
            );

            macro_rules! round16_stk {
                ($i0:literal,$i1:literal,$i2:literal,$i3:literal,
                 $i4:literal,$i5:literal,$i6:literal,$i7:literal,
                 $i8:literal,$i9:literal,$i10:literal,$i11:literal,
                 $i12:literal,$i13:literal,$i14:literal,$i15:literal) => {{
                    s0 = _mm512_add_epi32(s0, s4);
                    s0 = _mm512_add_epi32(s0, _mm512_load_si512(mp.add($i0)));
                    s1 = _mm512_add_epi32(s1, s5);
                    s1 = _mm512_add_epi32(s1, _mm512_load_si512(mp.add($i2)));
                    s2 = _mm512_add_epi32(s2, s6);
                    s2 = _mm512_add_epi32(s2, _mm512_load_si512(mp.add($i4)));
                    s3 = _mm512_add_epi32(s3, s7);
                    s3 = _mm512_add_epi32(s3, _mm512_load_si512(mp.add($i6)));
                    s12 = _mm512_xor_si512(s12, s0);
                    s13 = _mm512_xor_si512(s13, s1);
                    s14 = _mm512_xor_si512(s14, s2);
                    s15 = _mm512_xor_si512(s15, s3);
                    s12 = _mm512_rol_epi32::<16>(s12);
                    s13 = _mm512_rol_epi32::<16>(s13);
                    s14 = _mm512_rol_epi32::<16>(s14);
                    s15 = _mm512_rol_epi32::<16>(s15);
                    s8  = _mm512_add_epi32(s8,  s12);
                    s9  = _mm512_add_epi32(s9,  s13);
                    s10 = _mm512_add_epi32(s10, s14);
                    s11 = _mm512_add_epi32(s11, s15);
                    s4 = _mm512_xor_si512(s4, s8);
                    s5 = _mm512_xor_si512(s5, s9);
                    s6 = _mm512_xor_si512(s6, s10);
                    s7 = _mm512_xor_si512(s7, s11);
                    s4 = _mm512_rol_epi32::<20>(s4);
                    s5 = _mm512_rol_epi32::<20>(s5);
                    s6 = _mm512_rol_epi32::<20>(s6);
                    s7 = _mm512_rol_epi32::<20>(s7);
                    s0 = _mm512_add_epi32(s0, s4);
                    s0 = _mm512_add_epi32(s0, _mm512_load_si512(mp.add($i1)));
                    s1 = _mm512_add_epi32(s1, s5);
                    s1 = _mm512_add_epi32(s1, _mm512_load_si512(mp.add($i3)));
                    s2 = _mm512_add_epi32(s2, s6);
                    s2 = _mm512_add_epi32(s2, _mm512_load_si512(mp.add($i5)));
                    s3 = _mm512_add_epi32(s3, s7);
                    s3 = _mm512_add_epi32(s3, _mm512_load_si512(mp.add($i7)));
                    s12 = _mm512_xor_si512(s12, s0);
                    s13 = _mm512_xor_si512(s13, s1);
                    s14 = _mm512_xor_si512(s14, s2);
                    s15 = _mm512_xor_si512(s15, s3);
                    s12 = _mm512_rol_epi32::<24>(s12);
                    s13 = _mm512_rol_epi32::<24>(s13);
                    s14 = _mm512_rol_epi32::<24>(s14);
                    s15 = _mm512_rol_epi32::<24>(s15);
                    s8  = _mm512_add_epi32(s8,  s12);
                    s9  = _mm512_add_epi32(s9,  s13);
                    s10 = _mm512_add_epi32(s10, s14);
                    s11 = _mm512_add_epi32(s11, s15);
                    s4 = _mm512_xor_si512(s4, s8);
                    s5 = _mm512_xor_si512(s5, s9);
                    s6 = _mm512_xor_si512(s6, s10);
                    s7 = _mm512_xor_si512(s7, s11);
                    s4 = _mm512_rol_epi32::<25>(s4);
                    s5 = _mm512_rol_epi32::<25>(s5);
                    s6 = _mm512_rol_epi32::<25>(s6);
                    s7 = _mm512_rol_epi32::<25>(s7);
                    // Diagonal phase
                    s0 = _mm512_add_epi32(s0, s5);
                    s0 = _mm512_add_epi32(s0, _mm512_load_si512(mp.add($i8)));
                    s1 = _mm512_add_epi32(s1, s6);
                    s1 = _mm512_add_epi32(s1, _mm512_load_si512(mp.add($i10)));
                    s2 = _mm512_add_epi32(s2, s7);
                    s2 = _mm512_add_epi32(s2, _mm512_load_si512(mp.add($i12)));
                    s3 = _mm512_add_epi32(s3, s4);
                    s3 = _mm512_add_epi32(s3, _mm512_load_si512(mp.add($i14)));
                    s15 = _mm512_xor_si512(s15, s0);
                    s12 = _mm512_xor_si512(s12, s1);
                    s13 = _mm512_xor_si512(s13, s2);
                    s14 = _mm512_xor_si512(s14, s3);
                    s15 = _mm512_rol_epi32::<16>(s15);
                    s12 = _mm512_rol_epi32::<16>(s12);
                    s13 = _mm512_rol_epi32::<16>(s13);
                    s14 = _mm512_rol_epi32::<16>(s14);
                    s10 = _mm512_add_epi32(s10, s15);
                    s11 = _mm512_add_epi32(s11, s12);
                    s8  = _mm512_add_epi32(s8,  s13);
                    s9  = _mm512_add_epi32(s9,  s14);
                    s5 = _mm512_xor_si512(s5, s10);
                    s6 = _mm512_xor_si512(s6, s11);
                    s7 = _mm512_xor_si512(s7, s8);
                    s4 = _mm512_xor_si512(s4, s9);
                    s5 = _mm512_rol_epi32::<20>(s5);
                    s6 = _mm512_rol_epi32::<20>(s6);
                    s7 = _mm512_rol_epi32::<20>(s7);
                    s4 = _mm512_rol_epi32::<20>(s4);
                    s0 = _mm512_add_epi32(s0, s5);
                    s0 = _mm512_add_epi32(s0, _mm512_load_si512(mp.add($i9)));
                    s1 = _mm512_add_epi32(s1, s6);
                    s1 = _mm512_add_epi32(s1, _mm512_load_si512(mp.add($i11)));
                    s2 = _mm512_add_epi32(s2, s7);
                    s2 = _mm512_add_epi32(s2, _mm512_load_si512(mp.add($i13)));
                    s3 = _mm512_add_epi32(s3, s4);
                    s3 = _mm512_add_epi32(s3, _mm512_load_si512(mp.add($i15)));
                    s15 = _mm512_xor_si512(s15, s0);
                    s12 = _mm512_xor_si512(s12, s1);
                    s13 = _mm512_xor_si512(s13, s2);
                    s14 = _mm512_xor_si512(s14, s3);
                    s15 = _mm512_rol_epi32::<24>(s15);
                    s12 = _mm512_rol_epi32::<24>(s12);
                    s13 = _mm512_rol_epi32::<24>(s13);
                    s14 = _mm512_rol_epi32::<24>(s14);
                    s10 = _mm512_add_epi32(s10, s15);
                    s11 = _mm512_add_epi32(s11, s12);
                    s8  = _mm512_add_epi32(s8,  s13);
                    s9  = _mm512_add_epi32(s9,  s14);
                    s5 = _mm512_xor_si512(s5, s10);
                    s6 = _mm512_xor_si512(s6, s11);
                    s7 = _mm512_xor_si512(s7, s8);
                    s4 = _mm512_xor_si512(s4, s9);
                    s5 = _mm512_rol_epi32::<25>(s5);
                    s6 = _mm512_rol_epi32::<25>(s6);
                    s7 = _mm512_rol_epi32::<25>(s7);
                    s4 = _mm512_rol_epi32::<25>(s4);
                }};
            }

            // Hard-coded BLAKE3 message schedule per round.
            round16_stk!(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
            round16_stk!(2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8);
            round16_stk!(3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1);
            round16_stk!(10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6);
            round16_stk!(12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4);
            round16_stk!(9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7);
            round16_stk!(11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13);

            // Finalize: XOR upper and lower halves of state.
            let h0 = _mm512_xor_si512(s0, s8);
            let h1 = _mm512_xor_si512(s1, s9);
            let h2 = _mm512_xor_si512(s2, s10);
            let h3 = _mm512_xor_si512(s3, s11);
            let h4 = _mm512_xor_si512(s4, s12);
            let h5 = _mm512_xor_si512(s5, s13);
            let h6 = _mm512_xor_si512(s6, s14);
            let h7 = _mm512_xor_si512(s7, s15);

            // Extract per-parent output CVs via full zmm transpose.
            let t0 = _mm512_unpacklo_epi32(h0, h1);
            let t1 = _mm512_unpackhi_epi32(h0, h1);
            let t2 = _mm512_unpacklo_epi32(h2, h3);
            let t3 = _mm512_unpackhi_epi32(h2, h3);
            let t4 = _mm512_unpacklo_epi32(h4, h5);
            let t5 = _mm512_unpackhi_epi32(h4, h5);
            let t6 = _mm512_unpacklo_epi32(h6, h7);
            let t7 = _mm512_unpackhi_epi32(h6, h7);
            let u0 = _mm512_unpacklo_epi64(t0, t2);
            let u1 = _mm512_unpackhi_epi64(t0, t2);
            let u2 = _mm512_unpacklo_epi64(t1, t3);
            let u3 = _mm512_unpackhi_epi64(t1, t3);
            let u4 = _mm512_unpacklo_epi64(t4, t6);
            let u5 = _mm512_unpackhi_epi64(t4, t6);
            let u6 = _mm512_unpacklo_epi64(t5, t7);
            let u7 = _mm512_unpackhi_epi64(t5, t7);
            let v0 = _mm512_shuffle_i32x4::<0x88>(u0, u4);
            let v1 = _mm512_shuffle_i32x4::<0x88>(u1, u5);
            let v2 = _mm512_shuffle_i32x4::<0x88>(u2, u6);
            let v3 = _mm512_shuffle_i32x4::<0x88>(u3, u7);
            let v4 = _mm512_shuffle_i32x4::<0xDD>(u0, u4);
            let v5 = _mm512_shuffle_i32x4::<0xDD>(u1, u5);
            let v6 = _mm512_shuffle_i32x4::<0xDD>(u2, u6);
            let v7 = _mm512_shuffle_i32x4::<0xDD>(u3, u7);

            let mut out = [[0u32; 8]; 16];
            let dst = out.as_mut_ptr() as *mut __m512i;
            _mm512_storeu_si512(dst.add(0), _mm512_shuffle_i32x4::<0x88>(v0, v1));
            _mm512_storeu_si512(dst.add(1), _mm512_shuffle_i32x4::<0x88>(v2, v3));
            _mm512_storeu_si512(dst.add(2), _mm512_shuffle_i32x4::<0x88>(v4, v5));
            _mm512_storeu_si512(dst.add(3), _mm512_shuffle_i32x4::<0x88>(v6, v7));
            _mm512_storeu_si512(dst.add(4), _mm512_shuffle_i32x4::<0xDD>(v0, v1));
            _mm512_storeu_si512(dst.add(5), _mm512_shuffle_i32x4::<0xDD>(v2, v3));
            _mm512_storeu_si512(dst.add(6), _mm512_shuffle_i32x4::<0xDD>(v4, v5));
            _mm512_storeu_si512(dst.add(7), _mm512_shuffle_i32x4::<0xDD>(v6, v7));
            out
        }
    }
}

#[inline(always)]
fn compress_parents_16(
    cvs: *const [u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [[u32; 8]; 16] {
    Blake3::compress_parents_16_avx512(cvs, key, flags)
}

#[inline(always)]
fn hash_16_chunks(
    input: &[u8; 16384],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 16] {
    Blake3::hash_16_chunks_avx512(input, key, counter, flags)
}

// 8-way fallback via AVX2.
#[inline(always)]
fn hash_8_chunks(
    input: &[u8; 8192],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 8] {
    super::x86_avx2::hash_8_chunks(input, key, counter, flags)
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
unsafe fn hash_4_chunks_inline(
    input: &[u8; 4096],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 4] {

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

        // G function using AVX-512VL vprold for all rotations.
        macro_rules! g4_vl {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {{
                $a = _mm_add_epi32(_mm_add_epi32($a, $b), $mx);
                $d = _mm_ror_epi32::<16>(_mm_xor_si128($d, $a));
                $c = _mm_add_epi32($c, $d);
                $b = _mm_ror_epi32::<12>(_mm_xor_si128($b, $c));
                $a = _mm_add_epi32(_mm_add_epi32($a, $b), $my);
                $d = _mm_ror_epi32::<8>(_mm_xor_si128($d, $a));
                $c = _mm_add_epi32($c, $d);
                $b = _mm_ror_epi32::<7>(_mm_xor_si128($b, $c));
            }};
        }

        macro_rules! round4 {
            () => {{
                g4_vl!(s0, s4, s8,  s12, m0,  m1);
                g4_vl!(s1, s5, s9,  s13, m2,  m3);
                g4_vl!(s2, s6, s10, s14, m4,  m5);
                g4_vl!(s3, s7, s11, s15, m6,  m7);
                g4_vl!(s0, s5, s10, s15, m8,  m9);
                g4_vl!(s1, s6, s11, s12, m10, m11);
                g4_vl!(s2, s7, s8,  s13, m12, m13);
                g4_vl!(s3, s4, s9,  s14, m14, m15);
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

#[inline(always)]
unsafe fn compress_parents_4_inline(
    cvs: *const [u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [[u32; 8]; 4] {
    let base = cvs as *const __m128i;
    // 4 parent nodes: each parent = 2 consecutive CVs = 64 bytes = 4 XMM.
    let p0 = base as *const u8;
    let p1 = p0.add(64);
    let p2 = p0.add(128);
    let p3 = p0.add(192);

    let p0x = p0 as *const __m128i;
    let p1x = p1 as *const __m128i;
    let p2x = p2 as *const __m128i;
    let p3x = p3 as *const __m128i;

    let iv0 = _mm_set1_epi32(super::IV[0] as i32);
    let iv1 = _mm_set1_epi32(super::IV[1] as i32);
    let iv2 = _mm_set1_epi32(super::IV[2] as i32);
    let iv3 = _mm_set1_epi32(super::IV[3] as i32);

    let (mut s0, mut s1, mut s2, mut s3) = (
        _mm_set1_epi32(key[0] as i32), _mm_set1_epi32(key[1] as i32),
        _mm_set1_epi32(key[2] as i32), _mm_set1_epi32(key[3] as i32),
    );
    let (mut s4, mut s5, mut s6, mut s7) = (
        _mm_set1_epi32(key[4] as i32), _mm_set1_epi32(key[5] as i32),
        _mm_set1_epi32(key[6] as i32), _mm_set1_epi32(key[7] as i32),
    );
    let (mut s8, mut s9, mut s10, mut s11) = (iv0, iv1, iv2, iv3);
    let (mut s12, mut s13, mut s14, mut s15) = (
        _mm_setzero_si128(), _mm_setzero_si128(),
        _mm_set1_epi32(64), _mm_set1_epi32(flags as i32),
    );

    // Transpose messages: load 4×64-byte parent blocks, transpose to
    // 16 XMM words where each XMM holds one word across all 4 parents.
    macro_rules! t4x4 {
        ($off:expr) => {{
            let a = _mm_loadu_si128(p0x.add($off));
            let b = _mm_loadu_si128(p1x.add($off));
            let c = _mm_loadu_si128(p2x.add($off));
            let d = _mm_loadu_si128(p3x.add($off));
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

    let (m0, m1, m2, m3) = t4x4!(0);
    let (m4, m5, m6, m7) = t4x4!(1);
    let (m8, m9, m10, m11) = t4x4!(2);
    let (m12, m13, m14, m15) = t4x4!(3);

    macro_rules! g4_vl {
        ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {{
            $a = _mm_add_epi32(_mm_add_epi32($a, $b), $mx);
            $d = _mm_ror_epi32::<16>(_mm_xor_si128($d, $a));
            $c = _mm_add_epi32($c, $d);
            $b = _mm_ror_epi32::<12>(_mm_xor_si128($b, $c));
            $a = _mm_add_epi32(_mm_add_epi32($a, $b), $my);
            $d = _mm_ror_epi32::<8>(_mm_xor_si128($d, $a));
            $c = _mm_add_epi32($c, $d);
            $b = _mm_ror_epi32::<7>(_mm_xor_si128($b, $c));
        }};
    }

    // 7 rounds with hard-coded message schedule (single block, no permute).
    macro_rules! round_sched {
        ($s0:expr,$s1:expr,$s2:expr,$s3:expr,$s4:expr,$s5:expr,$s6:expr,$s7:expr,
         $s8:expr,$s9:expr,$s10:expr,$s11:expr,$s12:expr,$s13:expr,$s14:expr,$s15:expr) => {{
            g4_vl!(s0, s4, s8,  s12, $s0,  $s1);
            g4_vl!(s1, s5, s9,  s13, $s2,  $s3);
            g4_vl!(s2, s6, s10, s14, $s4,  $s5);
            g4_vl!(s3, s7, s11, s15, $s6,  $s7);
            g4_vl!(s0, s5, s10, s15, $s8,  $s9);
            g4_vl!(s1, s6, s11, s12, $s10, $s11);
            g4_vl!(s2, s7, s8,  s13, $s12, $s13);
            g4_vl!(s3, s4, s9,  s14, $s14, $s15);
        }};
    }

    round_sched!(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15);
    round_sched!(m2, m6, m3, m10, m7, m0, m4, m13, m1, m11, m12, m5, m9, m14, m15, m8);
    round_sched!(m3, m4, m10, m12, m13, m2, m7, m14, m6, m5, m9, m0, m11, m15, m8, m1);
    round_sched!(m10, m7, m12, m9, m14, m3, m13, m15, m4, m0, m11, m2, m5, m8, m1, m6);
    round_sched!(m12, m13, m9, m11, m15, m10, m14, m8, m7, m2, m5, m3, m0, m1, m6, m4);
    round_sched!(m9, m14, m11, m5, m8, m12, m15, m1, m13, m3, m0, m10, m2, m6, m4, m7);
    round_sched!(m11, m15, m5, m0, m1, m9, m8, m6, m14, m10, m2, m12, m3, m4, m7, m13);

    let h0 = _mm_xor_si128(s0, s8);
    let h1 = _mm_xor_si128(s1, s9);
    let h2 = _mm_xor_si128(s2, s10);
    let h3 = _mm_xor_si128(s3, s11);
    let h4 = _mm_xor_si128(s4, s12);
    let h5 = _mm_xor_si128(s5, s13);
    let h6 = _mm_xor_si128(s6, s14);
    let h7 = _mm_xor_si128(s7, s15);

    // Transpose back and extract per-parent CVs.
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
unsafe fn compress_parents_8_inline(
    cvs: *const [u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [[u32; 8]; 8] {
    super::x86_avx2::compress_parents_8_inline(cvs, key, flags)
}

blake3_impl!(transform, transform_inline,
    hash_16_chunks, 16, hash_8_chunks, 8, hash_4_chunks, 4;
    hash_inline: hash_16_chunks, hash_8_chunks, hash_4_chunks_inline;
    parent_batch: compress_parents_16, 16;
    parent_batch_inline: compress_parents_8_inline, 8, compress_parents_4_inline, 4;
    oneshot_feature: "avx512f,avx512vl");

#[cfg(test)]
mod tests {
    use super::Blake3;

    blake3_test_case!(require_hw: "x86" => ("avx512f", "avx512vl"), "x86_64" => ("avx512f", "avx512vl"));
}
