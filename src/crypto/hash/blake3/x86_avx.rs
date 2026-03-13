// BLAKE3 – x86/x86_64 AVX (VEX-encoded 128-bit) implementation.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use unsafe_target_feature::unsafe_target_feature;

#[allow(unused_imports)]
use super::x86_ssse3::hash_4_chunks_v6_core;

blake3_x86_128_impl!("avx,sse4.1,ssse3");

/// Core transform body using register-held message vectors.
///
/// # Safety
/// Caller must ensure AVX + SSE4.1 + SSSE3 are available.
#[inline(always)]
unsafe fn transform_v2_core(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    let rot16_tbl = _mm_loadu_si128(ROT16.as_ptr() as *const __m128i);
    let rot8_tbl = _mm_loadu_si128(ROT8.as_ptr() as *const __m128i);

    // ---- state ----
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

    // ---- initial message vectors (4 loads + 4 shufps + 2 pshufd) ----
    let q0 = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let q1 = _mm_loadu_si128(block.as_ptr().add(4) as *const __m128i);
    let q2 = _mm_loadu_si128(block.as_ptr().add(8) as *const __m128i);
    let q3 = _mm_loadu_si128(block.as_ptr().add(12) as *const __m128i);

    let q0f = _mm_castsi128_ps(q0);
    let q1f = _mm_castsi128_ps(q1);
    let q2f = _mm_castsi128_ps(q2);
    let q3f = _mm_castsi128_ps(q3);

    // m0 = evens of (q0, q1): [b0, b2, b4, b6]
    let mut m0 = _mm_castps_si128(_mm_shuffle_ps(q0f, q1f, 0x88));
    // m1 = odds  of (q0, q1): [b1, b3, b5, b7]
    let mut m1 = _mm_castps_si128(_mm_shuffle_ps(q0f, q1f, 0xDD));
    // m2 = evens of (q2, q3) rotated: [b14, b8, b10, b12]
    let t = _mm_castps_si128(_mm_shuffle_ps(q2f, q3f, 0x88));
    let mut m2 = _mm_shuffle_epi32(t, 0x93);
    // m3 = odds  of (q2, q3) rotated: [b15, b9, b11, b13]
    let t = _mm_castps_si128(_mm_shuffle_ps(q2f, q3f, 0xDD));
    let mut m3 = _mm_shuffle_epi32(t, 0x93);

    // ---- rotation helpers ----
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

    // ---- round body (reference diagonal layout: rotate r0, not r1) ----
    macro_rules! round_body {
        () => {
            // Column half
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), m0);
            r3 = ror!(_mm_xor_si128(r3, r0), 16);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 12);
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), m1);
            r3 = ror!(_mm_xor_si128(r3, r0), 8);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 7);
            // Diagonalize (reference layout)
            r0 = _mm_shuffle_epi32(r0, 0x93);
            r3 = _mm_shuffle_epi32(r3, 0x4E);
            r2 = _mm_shuffle_epi32(r2, 0x39);
            // Diagonal half
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), m2);
            r3 = ror!(_mm_xor_si128(r3, r0), 16);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 12);
            r0 = _mm_add_epi32(_mm_add_epi32(r0, r1), m3);
            r3 = ror!(_mm_xor_si128(r3, r0), 8);
            r2 = _mm_add_epi32(r2, r3);
            r1 = ror!(_mm_xor_si128(r1, r2), 7);
            // Undiagonalize
            r0 = _mm_shuffle_epi32(r0, 0x39);
            r3 = _mm_shuffle_epi32(r3, 0x4E);
            r2 = _mm_shuffle_epi32(r2, 0x93);
        };
    }

    // ---- message schedule permutation (reference SSE4.1 assembly) ----
    // Transliterated from blake3_sse41_x86-64_unix.S.
    macro_rules! permute_msg {
        () => {
            let t0 = _mm_castps_si128(_mm_shuffle_ps(
                _mm_castsi128_ps(m0),
                _mm_castsi128_ps(m1),
                0xD6,
            ));
            let mut t1 = _mm_shuffle_epi32(m0, 0x0F);
            m0 = _mm_shuffle_epi32(t0, 0x39);

            let t0 = _mm_castps_si128(_mm_shuffle_ps(
                _mm_castsi128_ps(m2),
                _mm_castsi128_ps(m3),
                0xFA,
            ));
            t1 = _mm_blend_epi16(t1, t0, 0xCC);

            let mut t0 = _mm_unpacklo_epi64(m3, m1);
            t0 = _mm_blend_epi16(t0, m2, 0xC0);
            t0 = _mm_shuffle_epi32(t0, 0x78);

            m1 = _mm_unpackhi_epi32(m1, m3);
            m2 = _mm_unpacklo_epi32(m2, m1);
            m3 = _mm_shuffle_epi32(m2, 0x1E);
            m1 = t1;
            m2 = t0;
        };
    }

    // ---- 7 rounds with 6 inter-round permutations ----
    round_body!();
    permute_msg!();
    round_body!();
    permute_msg!();
    round_body!();
    permute_msg!();
    round_body!();
    permute_msg!();
    round_body!();
    permute_msg!();
    round_body!();
    permute_msg!();
    round_body!();

    // ---- finalize ----
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

/// Safe wrapper with `#[target_feature]` for the optimised transform.
#[target_feature(enable = "avx,sse4.1,ssse3")]
unsafe fn transform_v2_featured(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    transform_v2_core(chaining_value, block, block_len, counter, flags)
}

/// AVX transform using register-based message schedule (safe to call).
#[inline(always)]
pub(super) fn transform_v2(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    // SAFETY: x86_avx module is only entered after runtime AVX detection.
    unsafe { transform_v2_featured(chaining_value, block, block_len, counter, flags) }
}

/// Caller must ensure AVX + SSE4.1 + SSSE3 are available in context.
#[inline(always)]
pub(super) unsafe fn transform_v2_inline(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    transform_v2_core(chaining_value, block, block_len, counter, flags)
}

#[inline(always)]
unsafe fn hash_4_chunks_avx_core(
    input: &[u8; 4096], key: &[u32; 8], counter: u64, flags: u32,
) -> [[u32; 8]; 4] {
    { return hash_4_chunks_v6_core(input, key, counter, flags); }
}

// ---------------------------------------------------------------------------
// Slice-level
// ---------------------------------------------------------------------------
blake3_impl!(transform_v2, transform_v2_inline, hash_4_chunks, 4;
    hash_inline: hash_4_chunks_avx_core;
    parent_batch_inline: compress_parents_4_inline, 4, compress_parents_4_inline, 4;
    oneshot_feature: "avx");

#[cfg(test)]
mod tests {
    use super::Blake3;

    blake3_test_case!(require_hw: "x86" => ("avx"), "x86_64" => ("avx"));
}
