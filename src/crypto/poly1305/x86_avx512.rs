#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

const MASK26: u64 = (1 << 26) - 1;
const HIBIT: u64 = 1 << 24;
const MASK44: u64 = (1 << 44) - 1;
const MASK42: u64 = (1 << 42) - 1;
const HIBIT44: u64 = 1 << 40;

#[derive(Clone)]
pub struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u32; 4],
    powers: [[u64; 3]; 64],
    powers_rev44_lo: [[[u64; 8]; 3]; 4],
    powers_rev44_hi: [[[u64; 8]; 3]; 4],
}

#[unsafe_target_feature::unsafe_target_feature("avx512f,avx512dq,avx512ifma")]
impl Poly1305 {
    pub const KEY_LEN: usize = 32;
    pub const TAG_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;

    #[inline]
    pub fn new(key: [u8; 32]) -> Self {
        let r = limbs26_to44(&key_to_r(&key));
        let pad = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];

        let mut powers = [[0u64; 3]; 64];
        powers[0] = r;
        for i in 1..powers.len() {
            powers[i] = mul_reduce_44(&powers[i - 1], &r);
        }

        let mut powers_rev44_lo = [[[0u64; 8]; 3]; 4];
        let mut powers_rev44_hi = [[[0u64; 8]; 3]; 4];
        for (window, start) in [63usize, 47, 31, 15].into_iter().enumerate() {
            for lane in 0..16 {
                let idx = lane & 7;
                if lane < 8 {
                    powers_rev44_lo[window][0][idx] = powers[start - lane][0];
                    powers_rev44_lo[window][1][idx] = powers[start - lane][1];
                    powers_rev44_lo[window][2][idx] = powers[start - lane][2];
                } else {
                    powers_rev44_hi[window][0][idx] = powers[start - lane][0];
                    powers_rev44_hi[window][1][idx] = powers[start - lane][1];
                    powers_rev44_hi[window][2][idx] = powers[start - lane][2];
                }
            }
        }

        Self {
            r,
            h: [0; 3],
            pad,
            powers,
            powers_rev44_lo,
            powers_rev44_hi,
        }
    }

    #[inline]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        let mut k = [0u8; Self::KEY_LEN];
        k.copy_from_slice(key);
        Self::new(k)
    }

    #[inline(always)]
    fn block(&mut self, m: &[u8; 16], hibit: u64) {
        let block = block_to_limbs_44(m, hibit << 16);
        let acc = add_reduce_44(&self.h, &block);
        self.h = mul_reduce_44(&acc, &self.r);
    }

    #[inline]
    pub fn update(&mut self, m: &[u8]) {
        let mut start = 0;
        let mut mlen = m.len();

        while mlen >= Self::BLOCK_LEN * 64 {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.update_64_blocks(chunk);
            start += Self::BLOCK_LEN * 64;
            mlen -= Self::BLOCK_LEN * 64;
        }

        while mlen >= Self::BLOCK_LEN * 16 {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.update_16_blocks(chunk);
            start += Self::BLOCK_LEN * 16;
            mlen -= Self::BLOCK_LEN * 16;
        }

        while mlen >= Self::BLOCK_LEN {
            let chunk = unsafe { crate::utils::slice_to_array_at(m, start) };
            self.block(chunk, HIBIT);
            start += Self::BLOCK_LEN;
            mlen -= Self::BLOCK_LEN;
        }

        if mlen > 0 {
            let mut padding_block = [0u8; Self::BLOCK_LEN];
            core::hint::black_box(padding_block.as_mut_ptr());
            unsafe {
                crate::utils::copy_chunks_u8(
                    padding_block.as_mut_ptr(),
                    m.as_ptr().add(start),
                    mlen,
                );
            }
            padding_block[mlen] = 1;
            self.block(&padding_block, 0);
        }
    }

    pub(crate) fn update_16_blocks(&mut self, m: &[u8; 256]) {
        let h_mul = mul_reduce_44(&self.h, &self.powers[15]);

        let batch_sum = batch_mul_sum_16_fused_ifma(m, &self.powers_rev44_lo[3], &self.powers_rev44_hi[3]);
        self.h = add_reduce_44(&h_mul, &batch_sum);
    }

    pub(crate) fn update_64_blocks(&mut self, m: &[u8; 1024]) {
        let h_mul = mul_reduce_44(&self.h, &self.powers[63]);

        let batch_sum = batch_mul_sum_64_fused_ifma(m, &self.powers_rev44_lo, &self.powers_rev44_hi);

        self.h = add_reduce_44(&h_mul, &batch_sum);
    }

    #[inline]
    pub fn finalize(self) -> [u8; 16] {
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = limbs44_to26(&self.h);

        let mut c = h1 >> 26;
        h1 &= MASK26;
        h2 += c;
        c = h2 >> 26;
        h2 &= MASK26;
        h3 += c;
        c = h3 >> 26;
        h3 &= MASK26;
        h4 += c;
        c = h4 >> 26;
        h4 &= MASK26;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= MASK26;
        h1 += c;

        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= MASK26;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= MASK26;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= MASK26;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= MASK26;
        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mut mask = (g4 >> 63).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        h0 = (h0 | (h1 << 26)) & 0xffff_ffff;
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

        let mut f = h0 + self.pad[0] as u64;
        h0 = f & 0xffff_ffff;
        f = h1 + self.pad[1] as u64 + (f >> 32);
        h1 = f & 0xffff_ffff;
        f = h2 + self.pad[2] as u64 + (f >> 32);
        h2 = f & 0xffff_ffff;
        f = h3 + self.pad[3] as u64 + (f >> 32);
        h3 = f & 0xffff_ffff;

        let mut tag = [0u8; Self::TAG_LEN];
        tag[0..4].copy_from_slice(&(h0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(h1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(h2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(h3 as u32).to_le_bytes());
        tag
    }
}

#[inline]
fn key_to_r(key: &[u8; 32]) -> [u64; 5] {
    [
        (u32::from_le_bytes([key[0], key[1], key[2], key[3]]) & 0x3ffffff) as u64,
        ((u32::from_le_bytes([key[3], key[4], key[5], key[6]]) >> 2) & 0x3ffff03) as u64,
        ((u32::from_le_bytes([key[6], key[7], key[8], key[9]]) >> 4) & 0x3ffc0ff) as u64,
        ((u32::from_le_bytes([key[9], key[10], key[11], key[12]]) >> 6) & 0x3f03fff) as u64,
        ((u32::from_le_bytes([key[12], key[13], key[14], key[15]]) >> 8) & 0x00fffff) as u64,
    ]
}

#[inline(always)]
fn block_to_limbs_44(m: &[u8; 16], hibit: u64) -> [u64; 3] {
    let lo = u64::from_le_bytes([m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]]);
    let hi = u64::from_le_bytes([m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]]);

    [
        lo & MASK44,
        ((lo >> 44) | (hi << 20)) & MASK44,
        ((hi >> 24) & MASK42) | hibit,
    ]
}

#[inline(always)]
fn limbs26_to44(limbs: &[u64; 5]) -> [u64; 3] {
    [
        limbs[0] | ((limbs[1] & 0x3ffff) << 26),
        (limbs[1] >> 18) | (limbs[2] << 8) | ((limbs[3] & 0x3ff) << 34),
        (limbs[3] >> 10) | (limbs[4] << 16),
    ]
}

#[inline(always)]
fn limbs44_to26(limbs: &[u64; 3]) -> [u64; 5] {
    [
        limbs[0] & MASK26,
        ((limbs[0] >> 26) | ((limbs[1] & 0xff) << 18)) & MASK26,
        (limbs[1] >> 8) & MASK26,
        ((limbs[1] >> 34) | ((limbs[2] & 0xffff) << 10)) & MASK26,
        (limbs[2] >> 16) & MASK26,
    ]
}

#[inline(always)]
fn carry_reduce_44(h: &mut [u128; 3]) {
    let mut c = h[0] >> 44;
    h[0] &= MASK44 as u128;
    h[1] += c;
    c = h[1] >> 44;
    h[1] &= MASK44 as u128;
    h[2] += c;
    c = h[2] >> 42;
    h[2] &= MASK42 as u128;
    h[0] += c * 5;
    c = h[0] >> 44;
    h[0] &= MASK44 as u128;
    h[1] += c;
}

#[inline(always)]
fn add_reduce_44(a: &[u64; 3], b: &[u64; 3]) -> [u64; 3] {
    let mut out = [a[0] as u128 + b[0] as u128, a[1] as u128 + b[1] as u128, a[2] as u128 + b[2] as u128];
    carry_reduce_44(&mut out);
    carry_reduce_44(&mut out);
    [out[0] as u64, out[1] as u64, out[2] as u64]
}

#[inline(always)]
fn mul_reduce_44(a: &[u64; 3], b: &[u64; 3]) -> [u64; 3] {
    let s1 = (b[1] as u128) * 20;
    let s2 = (b[2] as u128) * 20;

    let mut d0 = (a[0] as u128) * (b[0] as u128) + (a[1] as u128) * s2 + (a[2] as u128) * s1;
    let mut d1 = (a[0] as u128) * (b[1] as u128) + (a[1] as u128) * (b[0] as u128) + (a[2] as u128) * s2;
    let mut d2 = (a[0] as u128) * (b[2] as u128) + (a[1] as u128) * (b[1] as u128) + (a[2] as u128) * (b[0] as u128);

    let mut c = d0 >> 44;
    d0 &= MASK44 as u128;
    d1 += c;
    c = d1 >> 44;
    d1 &= MASK44 as u128;
    d2 += c;
    c = d2 >> 42;
    d2 &= MASK42 as u128;
    d0 += c * 5;
    c = d0 >> 44;
    d0 &= MASK44 as u128;
    d1 += c;

    [d0 as u64, d1 as u64, d2 as u64]
}

#[inline(always)]
fn fill_transposed_blocks_16_u64(src: &[u8], start: usize, out_lo: &mut [[u64; 8]; 3], out_hi: &mut [[u64; 8]; 3]) {
    for lane in 0..8 {
        let chunk = unsafe { crate::utils::slice_to_array_at(src, start + lane * 16) };
        let [l0, l1, l2] = block_to_limbs_44(chunk, HIBIT44);
        out_lo[0][lane] = l0 as u64;
        out_lo[1][lane] = l1 as u64;
        out_lo[2][lane] = l2 as u64;
    }
    for lane in 0..8 {
        let chunk = unsafe { crate::utils::slice_to_array_at(src, start + (lane + 8) * 16) };
        let [l0, l1, l2] = block_to_limbs_44(chunk, HIBIT44);
        out_hi[0][lane] = l0 as u64;
        out_hi[1][lane] = l1 as u64;
        out_hi[2][lane] = l2 as u64;
    }
}

#[inline(always)]
unsafe fn load_u64x8(values: &[u64; 8]) -> __m512i {
    _mm512_loadu_si512(values.as_ptr() as *const __m512i)
}

#[inline(always)]
unsafe fn parse_8blocks_avx512(ptr: *const u8) -> (__m512i, __m512i, __m512i) {
    // Load 128 bytes as two ZMM u64x8 registers:
    //   raw0 = [b0_lo, b0_hi, b1_lo, b1_hi, b2_lo, b2_hi, b3_lo, b3_hi]
    //   raw1 = [b4_lo, b4_hi, b5_lo, b5_hi, b6_lo, b6_hi, b7_lo, b7_hi]
    let raw0 = _mm512_loadu_si512(ptr as *const __m512i);
    let raw1 = _mm512_loadu_si512(ptr.add(64) as *const __m512i);

    // permutex2var index semantics: bit[3]=0 → from raw0, bit[3]=1 → from raw1; bits[2:0] = lane
    let even_idx = _mm512_set_epi64(14, 12, 10, 8, 6, 4, 2, 0); // even u64 elements
    let odd_idx  = _mm512_set_epi64(15, 13, 11, 9, 7, 5, 3, 1); // odd u64 elements
    let vlo = _mm512_permutex2var_epi64(raw0, even_idx, raw1); // [b0_lo..b7_lo]
    let vhi = _mm512_permutex2var_epi64(raw0, odd_idx,  raw1); // [b0_hi..b7_hi]

    let mask44 = _mm512_set1_epi64(MASK44 as i64);
    let mask42 = _mm512_set1_epi64(MASK42 as i64);
    let hibit  = _mm512_set1_epi64(HIBIT44 as i64);

    let limb0 = _mm512_and_si512(vlo, mask44);
    let limb1 = _mm512_and_si512(
        _mm512_or_si512(_mm512_srli_epi64::<44>(vlo), _mm512_slli_epi64::<20>(vhi)),
        mask44,
    );
    let limb2 = _mm512_or_si512(
        _mm512_and_si512(_mm512_srli_epi64::<24>(vhi), mask42),
        hibit,
    );
    (limb0, limb1, limb2)
}

#[inline(always)]
unsafe fn parse_accumulate_8blocks_ifma(
    ptr: *const u8,
    powers: &[[u64; 8]; 3],
    d0l: &mut __m512i, d0h: &mut __m512i,
    d1l: &mut __m512i, d1h: &mut __m512i,
    d2l: &mut __m512i, d2h: &mut __m512i,
) {
    let (m0, m1, m2) = parse_8blocks_avx512(ptr);
    let p0   = load_u64x8(&powers[0]);
    let p1   = load_u64x8(&powers[1]);
    let p2   = load_u64x8(&powers[2]);
    let p1_20 = mul20_u64x8(p1);
    let p2_20 = mul20_u64x8(p2);

    // d0 += m0·p0 + m1·p2·20 + m2·p1·20
    *d0l = _mm512_madd52lo_epu64(*d0l, m0, p0);   *d0h = _mm512_madd52hi_epu64(*d0h, m0, p0);
    *d0l = _mm512_madd52lo_epu64(*d0l, m1, p2_20); *d0h = _mm512_madd52hi_epu64(*d0h, m1, p2_20);
    *d0l = _mm512_madd52lo_epu64(*d0l, m2, p1_20); *d0h = _mm512_madd52hi_epu64(*d0h, m2, p1_20);
    // d1 += m0·p1 + m1·p0 + m2·p2·20
    *d1l = _mm512_madd52lo_epu64(*d1l, m0, p1);   *d1h = _mm512_madd52hi_epu64(*d1h, m0, p1);
    *d1l = _mm512_madd52lo_epu64(*d1l, m1, p0);   *d1h = _mm512_madd52hi_epu64(*d1h, m1, p0);
    *d1l = _mm512_madd52lo_epu64(*d1l, m2, p2_20); *d1h = _mm512_madd52hi_epu64(*d1h, m2, p2_20);
    // d2 += m0·p2 + m1·p1 + m2·p0
    *d2l = _mm512_madd52lo_epu64(*d2l, m0, p2);   *d2h = _mm512_madd52hi_epu64(*d2h, m0, p2);
    *d2l = _mm512_madd52lo_epu64(*d2l, m1, p1);   *d2h = _mm512_madd52hi_epu64(*d2h, m1, p1);
    *d2l = _mm512_madd52lo_epu64(*d2l, m2, p0);   *d2h = _mm512_madd52hi_epu64(*d2h, m2, p0);
}

#[inline(always)]
#[unsafe_target_feature::unsafe_target_feature("avx512f,avx512ifma")]
fn batch_mul_sum_16_fused_ifma(m: &[u8; 256], p_lo: &[[u64; 8]; 3], p_hi: &[[u64; 8]; 3]) -> [u64; 3] {
    unsafe {
        let zero = _mm512_setzero_si512();
        let (mut d0l, mut d0h) = (zero, zero);
        let (mut d1l, mut d1h) = (zero, zero);
        let (mut d2l, mut d2h) = (zero, zero);
        let base = m.as_ptr();
        parse_accumulate_8blocks_ifma(base,           p_lo, &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(128),  p_hi, &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        finalize_6accumulators(d0l, d0h, d1l, d1h, d2l, d2h)
    }
}

#[inline(always)]
#[unsafe_target_feature::unsafe_target_feature("avx512f,avx512ifma")]
fn batch_mul_sum_64_fused_ifma(
    m: &[u8; 1024],
    powers_lo: &[[[u64; 8]; 3]; 4],
    powers_hi: &[[[u64; 8]; 3]; 4],
) -> [u64; 3] {
    unsafe {
        let zero = _mm512_setzero_si512();
        let (mut d0l, mut d0h) = (zero, zero);
        let (mut d1l, mut d1h) = (zero, zero);
        let (mut d2l, mut d2h) = (zero, zero);
        let base = m.as_ptr();
        parse_accumulate_8blocks_ifma(base,           &powers_lo[0], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(128),  &powers_hi[0], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(256),  &powers_lo[1], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(384),  &powers_hi[1], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(512),  &powers_lo[2], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(640),  &powers_hi[2], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(768),  &powers_lo[3], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        parse_accumulate_8blocks_ifma(base.add(896),  &powers_hi[3], &mut d0l, &mut d0h, &mut d1l, &mut d1h, &mut d2l, &mut d2h);
        finalize_6accumulators(d0l, d0h, d1l, d1h, d2l, d2h)
    }
}

#[inline(always)]
unsafe fn hsum_u64x8(v: __m512i) -> u64 {
    // 8 → 4 lanes: add upper half to lower half
    let lo4 = _mm512_castsi512_si256(v);                 // cast, free
    let hi4 = _mm512_extracti64x4_epi64::<1>(v);         // upper 256 bits
    let sum4 = _mm256_add_epi64(lo4, hi4);               // 4 lanes
    // 4 → 2 lanes
    let lo2 = _mm256_castsi256_si128(sum4);               // cast, free
    let hi2 = _mm256_extracti128_si256::<1>(sum4);        // upper 128 bits
    let sum2 = _mm_add_epi64(lo2, hi2);                   // 2 lanes
    // 2 → 1
    let lane0 = _mm_cvtsi128_si64(sum2) as u64;
    let lane1 = _mm_extract_epi64::<1>(sum2) as u64;
    lane0.wrapping_add(lane1)
}

#[inline(always)]
unsafe fn hsum_madd52_u128(lo: __m512i, hi: __m512i) -> u128 {
    hsum_u64x8(lo) as u128 + ((hsum_u64x8(hi) as u128) << 52)
}

#[inline(always)]
fn batch_mul_sum_16_scalar44(m_lo: &[[u64; 8]; 3], m_hi: &[[u64; 8]; 3], p_lo: &[[u64; 8]; 3], p_hi: &[[u64; 8]; 3]) -> [u64; 3] {
    let mut out = [0u64; 3];
    for lane in 0..8 {
        let m = [m_lo[0][lane], m_lo[1][lane], m_lo[2][lane]];
        let p = [p_lo[0][lane], p_lo[1][lane], p_lo[2][lane]];
        let prod = mul_reduce_44(&m, &p);
        out = add_reduce_44(&out, &prod);
    }
    for lane in 0..8 {
        let m = [m_hi[0][lane], m_hi[1][lane], m_hi[2][lane]];
        let p = [p_hi[0][lane], p_hi[1][lane], p_hi[2][lane]];
        let prod = mul_reduce_44(&m, &p);
        out = add_reduce_44(&out, &prod);
    }
    out
}

#[inline(always)]
unsafe fn mul20_u64x8(v: __m512i) -> __m512i {
    _mm512_add_epi64(_mm512_slli_epi64::<4>(v), _mm512_slli_epi64::<2>(v))
}

#[inline(always)]
unsafe fn finalize_6accumulators(
    d0l: __m512i, d0h: __m512i,
    d1l: __m512i, d1h: __m512i,
    d2l: __m512i, d2h: __m512i,
) -> [u64; 3] {
    let mut out = [
        hsum_madd52_u128(d0l, d0h),
        hsum_madd52_u128(d1l, d1h),
        hsum_madd52_u128(d2l, d2h),
    ];
    carry_reduce_44(&mut out);
    carry_reduce_44(&mut out);
    [out[0] as u64, out[1] as u64, out[2] as u64]
}


#[cfg(test)]
mod tests {
    use super::Poly1305 as Avx512Poly1305;
    use super::{batch_mul_sum_16_fused_ifma, batch_mul_sum_16_scalar44, fill_transposed_blocks_16_u64};
    use crate::crypto::poly1305::Poly1305 as ScalarPoly1305;

    #[test]
    #[cfg(all(avx512_feature, any(target_arch = "x86", target_arch = "x86_64")))]
    fn avx512_update_16_matches_scalar() {
        if !crate::is_hw_feature_detected!("avx512f") || !crate::is_hw_feature_detected!("avx512dq") || !crate::is_hw_feature_detected!("avx512ifma") {
            return;
        }

        let key = [0x5au8; 32];
        let mut blocks = [0u8; 256];
        for (i, b) in blocks.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(3);
        }

        let mut scalar = ScalarPoly1305::new(key);
        scalar.update_16_blocks(&blocks);

        let mut avx = Avx512Poly1305::new(key);
        avx.update_16_blocks(&blocks);

        assert_eq!(scalar.finalize(), avx.finalize());
    }

    #[test]
    #[cfg(all(avx512_feature, any(target_arch = "x86", target_arch = "x86_64")))]
    fn avx512_update_64_matches_scalar() {
        if !crate::is_hw_feature_detected!("avx512f") || !crate::is_hw_feature_detected!("avx512dq") || !crate::is_hw_feature_detected!("avx512ifma") {
            return;
        }

        let key = [0xa5u8; 32];
        let mut blocks = [0u8; 1024];
        for (i, b) in blocks.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(11);
        }

        let mut scalar = ScalarPoly1305::new(key);
        for chunk in blocks.chunks_exact(256) {
            scalar.update_16_blocks(chunk.try_into().unwrap());
        }

        let mut avx = Avx512Poly1305::new(key);
        avx.update_64_blocks(&blocks);

        assert_eq!(scalar.finalize(), avx.finalize());
    }

    #[test]
    #[cfg(all(avx512_feature, any(target_arch = "x86", target_arch = "x86_64")))]
    fn avx512_ifma_batch_matches_scalar_reference() {
        if !crate::is_hw_feature_detected!("avx512f") || !crate::is_hw_feature_detected!("avx512ifma") {
            return;
        }

        let key = [0x3cu8; 32];
        let poly = Avx512Poly1305::new(key);
        let mut input = [0u8; 256];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(9);
        }

        let reference = {
            let mut blocks_lo = [[0u64; 8]; 3];
            let mut blocks_hi = [[0u64; 8]; 3];
            fill_transposed_blocks_16_u64(&input, 0, &mut blocks_lo, &mut blocks_hi);
            batch_mul_sum_16_scalar44(&blocks_lo, &blocks_hi, &poly.powers_rev44_lo[3], &poly.powers_rev44_hi[3])
        };

        let fused = batch_mul_sum_16_fused_ifma(&input, &poly.powers_rev44_lo[3], &poly.powers_rev44_hi[3]);
        assert_eq!(reference, fused);
    }

}