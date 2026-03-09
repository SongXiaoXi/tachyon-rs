#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

macro_rules! vror_u32 {
    ($v:expr, 7) => {
        vsliq_n_u32(vshrq_n_u32($v, 7), $v, 25)
    };
    ($v:expr, 8, $rot8:expr) => {
        vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32($v), $rot8))
    };
    ($v:expr, 12) => {
        vsliq_n_u32(vshrq_n_u32($v, 12), $v, 20)
    };
    ($v:expr, 16) => {
        vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32($v)))
    };
}

// ---------------------------------------------------------------------------
// Message permutation indices for vqtbl4q_u8.
// ---------------------------------------------------------------------------
const PERM_M0: [u8; 16] = [ 8, 9,10,11, 24,25,26,27, 12,13,14,15, 40,41,42,43];
const PERM_M1: [u8; 16] = [28,29,30,31,  0, 1, 2, 3, 16,17,18,19, 52,53,54,55];
const PERM_M2: [u8; 16] = [ 4, 5, 6, 7, 44,45,46,47, 48,49,50,51, 20,21,22,23];
const PERM_M3: [u8; 16] = [36,37,38,39, 56,57,58,59, 60,61,62,63, 32,33,34,35];
const ROT8_TBL: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

// ---------------------------------------------------------------------------
// Block-level: NEON compression function
// ---------------------------------------------------------------------------
#[inline(always)]
fn transform(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    unsafe {
        let rot8 = vld1q_u8(ROT8_TBL.as_ptr());
        let pm0  = vld1q_u8(PERM_M0.as_ptr());
        let pm1  = vld1q_u8(PERM_M1.as_ptr());
        let pm2  = vld1q_u8(PERM_M2.as_ptr());
        let pm3  = vld1q_u8(PERM_M3.as_ptr());

        // Chaining value.
        let cv0 = vld1q_u32(chaining_value.as_ptr());
        let cv1 = vld1q_u32(chaining_value.as_ptr().add(4));

        // Initialise state rows.
        let mut r0 = cv0;
        let mut r1 = cv1;
        let mut r2 = vld1q_u32(super::IV.as_ptr());
        let mut r3 = vld1q_u32(
            [counter as u32, (counter >> 32) as u32, block_len as u32, flags].as_ptr(),
        );

        // Messages in 4 NEON registers.
        let mut m0 = vld1q_u32(block.as_ptr());
        let mut m1 = vld1q_u32(block.as_ptr().add(4));
        let mut m2 = vld1q_u32(block.as_ptr().add(8));
        let mut m3 = vld1q_u32(block.as_ptr().add(12));

        // ---------------------------------------------------------------
        // One full round (columns + diagonals).
        // ---------------------------------------------------------------
        macro_rules! g_round {
            () => {{
                // Column G: mx=[w0,w2,w4,w6], my=[w1,w3,w5,w7]
                let mx = vuzp1q_u32(m0, m1);
                let my = vuzp2q_u32(m0, m1);

                r0 = vaddq_u32(vaddq_u32(r0, r1), mx);
                r3 = vror_u32!(veorq_u32(r3, r0), 16);
                r2 = vaddq_u32(r2, r3);
                r1 = vror_u32!(veorq_u32(r1, r2), 12);
                r0 = vaddq_u32(vaddq_u32(r0, r1), my);
                r3 = vror_u32!(veorq_u32(r3, r0), 8, rot8);
                r2 = vaddq_u32(r2, r3);
                r1 = vror_u32!(veorq_u32(r1, r2), 7);

                // Diagonalise.
                r1 = vextq_u32(r1, r1, 1);
                r2 = vextq_u32(r2, r2, 2);
                r3 = vextq_u32(r3, r3, 3);

                // Diagonal G: mx=[w8,w10,w12,w14], my=[w9,w11,w13,w15]
                let mx = vuzp1q_u32(m2, m3);
                let my = vuzp2q_u32(m2, m3);

                r0 = vaddq_u32(vaddq_u32(r0, r1), mx);
                r3 = vror_u32!(veorq_u32(r3, r0), 16);
                r2 = vaddq_u32(r2, r3);
                r1 = vror_u32!(veorq_u32(r1, r2), 12);
                r0 = vaddq_u32(vaddq_u32(r0, r1), my);
                r3 = vror_u32!(veorq_u32(r3, r0), 8, rot8);
                r2 = vaddq_u32(r2, r3);
                r1 = vror_u32!(veorq_u32(r1, r2), 7);

                // Un-diagonalise.
                r1 = vextq_u32(r1, r1, 3);
                r2 = vextq_u32(r2, r2, 2);
                r3 = vextq_u32(r3, r3, 1);
            }};
        }

        // Message-word permutation via TBL4 (stays entirely in NEON).
        macro_rules! permute {
            () => {{
                let tbl = uint8x16x4_t(
                    vreinterpretq_u8_u32(m0),
                    vreinterpretq_u8_u32(m1),
                    vreinterpretq_u8_u32(m2),
                    vreinterpretq_u8_u32(m3),
                );
                m0 = vreinterpretq_u32_u8(vqtbl4q_u8(tbl, pm0));
                m1 = vreinterpretq_u32_u8(vqtbl4q_u8(tbl, pm1));
                m2 = vreinterpretq_u32_u8(vqtbl4q_u8(tbl, pm2));
                m3 = vreinterpretq_u32_u8(vqtbl4q_u8(tbl, pm3));
            }};
        }

        // 7 rounds: 6 × (round + permute) + 1 × round.
        g_round!(); permute!();
        g_round!(); permute!();
        g_round!(); permute!();
        g_round!(); permute!();
        g_round!(); permute!();
        g_round!(); permute!();
        g_round!();

        // Finalise: state[0..8] ^= state[8..16]; state[8..16] ^= CV.
        r0 = veorq_u32(r0, r2);
        r1 = veorq_u32(r1, r3);
        r2 = veorq_u32(r2, cv0);
        r3 = veorq_u32(r3, cv1);

        let mut out = [0u32; 16];
        vst1q_u32(out.as_mut_ptr(),         r0);
        vst1q_u32(out.as_mut_ptr().add(4),  r1);
        vst1q_u32(out.as_mut_ptr().add(8),  r2);
        vst1q_u32(out.as_mut_ptr().add(12), r3);
        out
    }
}

// ---------------------------------------------------------------------------
// 4-way parallel chunk hashing – compresses 4 × 1024-byte chunks at once.
// Each NEON lane handles one independent chunk.  Message transpose via
// TRN1/TRN2 (u32 + u64).  16-block loop fully unrolled via const_loop!;
// message permutation baked into round4! arguments (immutable messages).
// ---------------------------------------------------------------------------
#[inline(always)]
fn hash_4_chunks(
    input: &[u8; 4096],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 4] {
    unsafe {
        let rot8 = vld1q_u8(ROT8_TBL.as_ptr());

        // Pointers to the 4 chunks (byte → u32 for vld1q_u32).
        let p0 = input.as_ptr() as *const u32;
        let p1 = input.as_ptr().add(1024) as *const u32;
        let p2 = input.as_ptr().add(2048) as *const u32;
        let p3 = input.as_ptr().add(3072) as *const u32;

        // Counter low/high for the 4 chunks.
        let ctr_lo = {
            let v = [
                counter as u32,
                (counter + 1) as u32,
                (counter + 2) as u32,
                (counter + 3) as u32,
            ];
            vld1q_u32(v.as_ptr())
        };
        let ctr_hi = {
            let v = [
                (counter >> 32) as u32,
                ((counter + 1) >> 32) as u32,
                ((counter + 2) >> 32) as u32,
                ((counter + 3) >> 32) as u32,
            ];
            vld1q_u32(v.as_ptr())
        };

        let iv0 = vdupq_n_u32(super::IV[0]);
        let iv1 = vdupq_n_u32(super::IV[1]);
        let iv2 = vdupq_n_u32(super::IV[2]);
        let iv3 = vdupq_n_u32(super::IV[3]);
        let blen = vdupq_n_u32(64);

        // Chaining values – broadcast key to all 4 lanes.
        let mut h0 = vdupq_n_u32(key[0]);
        let mut h1 = vdupq_n_u32(key[1]);
        let mut h2 = vdupq_n_u32(key[2]);
        let mut h3 = vdupq_n_u32(key[3]);
        let mut h4 = vdupq_n_u32(key[4]);
        let mut h5 = vdupq_n_u32(key[5]);
        let mut h6 = vdupq_n_u32(key[6]);
        let mut h7 = vdupq_n_u32(key[7]);

        // G function operating on 4 chunks simultaneously.
        macro_rules! g4 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {{
                $a = vaddq_u32(vaddq_u32($a, $b), $mx);
                let xd = veorq_u32($d, $a);
                $d = vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(xd)));
                $c = vaddq_u32($c, $d);
                let xb = veorq_u32($b, $c);
                $b = vsliq_n_u32(vshrq_n_u32(xb, 12), xb, 20);
                $a = vaddq_u32(vaddq_u32($a, $b), $my);
                let xd = veorq_u32($d, $a);
                $d = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(xd), rot8));
                $c = vaddq_u32($c, $d);
                let xb = veorq_u32($b, $c);
                $b = vsliq_n_u32(vshrq_n_u32(xb, 7), xb, 25);
            }};
        }

        // One block of 4-way compression:
        //   - load 16 message words from 4 chunks, 4×4-transpose
        //   - update chaining values
        macro_rules! compress_block {
            ($bf:expr, $wo:expr) => {{
                // State initialisation.
                let (mut s0, mut s1, mut s2, mut s3) = (h0, h1, h2, h3);
                let (mut s4, mut s5, mut s6, mut s7) = (h4, h5, h6, h7);
                let (mut s8, mut s9, mut s10, mut s11) = (iv0, iv1, iv2, iv3);
                let (mut s12, mut s13, mut s14, mut s15) =
                    (ctr_lo, ctr_hi, blen, vdupq_n_u32($bf));

                // Load + 4×4-transpose (TRN32 + TRN64).
                macro_rules! t4x4 {
                    ($off:expr) => {{
                        let a = vld1q_u32(p0.add($wo + $off));
                        let b = vld1q_u32(p1.add($wo + $off));
                        let c = vld1q_u32(p2.add($wo + $off));
                        let d = vld1q_u32(p3.add($wo + $off));
                        let ab_l = vtrn1q_u32(a, b);
                        let ab_h = vtrn2q_u32(a, b);
                        let cd_l = vtrn1q_u32(c, d);
                        let cd_h = vtrn2q_u32(c, d);
                        (
                            vreinterpretq_u32_u64(vtrn1q_u64(
                                vreinterpretq_u64_u32(ab_l), vreinterpretq_u64_u32(cd_l))),
                            vreinterpretq_u32_u64(vtrn1q_u64(
                                vreinterpretq_u64_u32(ab_h), vreinterpretq_u64_u32(cd_h))),
                            vreinterpretq_u32_u64(vtrn2q_u64(
                                vreinterpretq_u64_u32(ab_l), vreinterpretq_u64_u32(cd_l))),
                            vreinterpretq_u32_u64(vtrn2q_u64(
                                vreinterpretq_u64_u32(ab_h), vreinterpretq_u64_u32(cd_h))),
                        )
                    }};
                }

                let (mut m0, mut m1, mut m2, mut m3) = t4x4!(0);
                let (mut m4, mut m5, mut m6, mut m7) = t4x4!(4);
                let (mut m8, mut m9, mut m10, mut m11) = t4x4!(8);
                let (mut m12, mut m13, mut m14, mut m15) = t4x4!(12);

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

                // 7 rounds: 6 × (round + permute) + 1 × round.
                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!(); perm4!();
                round4!();

                // Finalize – update chaining values for next block.
                h0 = veorq_u32(s0, s8);
                h1 = veorq_u32(s1, s9);
                h2 = veorq_u32(s2, s10);
                h3 = veorq_u32(s3, s11);
                h4 = veorq_u32(s4, s12);
                h5 = veorq_u32(s5, s13);
                h6 = veorq_u32(s6, s14);
                h7 = veorq_u32(s7, s15);
            }};
        }

        // -------------------------------------------------------------------
        // 16 blocks per chunk – fully unrolled via const_loop! so LLVM can
        // schedule loads/computation across block boundaries and flags become
        // compile-time constants (CHUNK_START for block 0, CHUNK_END for 15).
        // -------------------------------------------------------------------
        crate::const_loop!(blk, 0, 16, {
            let bf = match blk {
                0 => flags | super::CHUNK_START,
                15 => flags | super::CHUNK_END,
                _ => flags,
            };
            compress_block!(bf, blk as usize * 16);
        });

        // Extract per-chunk chaining values (transpose back).
        let mut t = [[0u32; 4]; 8];
        vst1q_u32(t[0].as_mut_ptr(), h0);
        vst1q_u32(t[1].as_mut_ptr(), h1);
        vst1q_u32(t[2].as_mut_ptr(), h2);
        vst1q_u32(t[3].as_mut_ptr(), h3);
        vst1q_u32(t[4].as_mut_ptr(), h4);
        vst1q_u32(t[5].as_mut_ptr(), h5);
        vst1q_u32(t[6].as_mut_ptr(), h6);
        vst1q_u32(t[7].as_mut_ptr(), h7);
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

// ---------------------------------------------------------------------------
// 8-way parallel chunk hashing – two interleaved groups of 4 chunks.
// Doubles instruction-level parallelism: the OOO engine fills pipeline
// bubbles in group A's dependency chain with group B's independent work.
// ---------------------------------------------------------------------------
#[inline(always)]
fn hash_8_chunks(
    input: &[u8; 8192],
    key: &[u32; 8],
    counter: u64,
    flags: u32,
) -> [[u32; 8]; 8] {
    unsafe {
        let rot8 = vld1q_u8(ROT8_TBL.as_ptr());

        // Group A: chunks 0-3, Group B: chunks 4-7.
        let pa0 = input.as_ptr() as *const u32;
        let pa1 = input.as_ptr().add(1024) as *const u32;
        let pa2 = input.as_ptr().add(2048) as *const u32;
        let pa3 = input.as_ptr().add(3072) as *const u32;
        let pb0 = input.as_ptr().add(4096) as *const u32;
        let pb1 = input.as_ptr().add(5120) as *const u32;
        let pb2 = input.as_ptr().add(6144) as *const u32;
        let pb3 = input.as_ptr().add(7168) as *const u32;

        // Counter vectors.
        let ctr_lo_a = {
            let v = [
                counter as u32, (counter + 1) as u32,
                (counter + 2) as u32, (counter + 3) as u32,
            ];
            vld1q_u32(v.as_ptr())
        };
        let ctr_hi_a = {
            let v = [
                (counter >> 32) as u32, ((counter + 1) >> 32) as u32,
                ((counter + 2) >> 32) as u32, ((counter + 3) >> 32) as u32,
            ];
            vld1q_u32(v.as_ptr())
        };
        let ctr_lo_b = {
            let v = [
                (counter + 4) as u32, (counter + 5) as u32,
                (counter + 6) as u32, (counter + 7) as u32,
            ];
            vld1q_u32(v.as_ptr())
        };
        let ctr_hi_b = {
            let v = [
                ((counter + 4) >> 32) as u32, ((counter + 5) >> 32) as u32,
                ((counter + 6) >> 32) as u32, ((counter + 7) >> 32) as u32,
            ];
            vld1q_u32(v.as_ptr())
        };

        let iv0 = vdupq_n_u32(super::IV[0]);
        let iv1 = vdupq_n_u32(super::IV[1]);
        let iv2 = vdupq_n_u32(super::IV[2]);
        let iv3 = vdupq_n_u32(super::IV[3]);
        let blen = vdupq_n_u32(64);

        // Chaining values – broadcast key to all lanes.
        let k0 = vdupq_n_u32(key[0]);
        let k1 = vdupq_n_u32(key[1]);
        let k2 = vdupq_n_u32(key[2]);
        let k3 = vdupq_n_u32(key[3]);
        let k4 = vdupq_n_u32(key[4]);
        let k5 = vdupq_n_u32(key[5]);
        let k6 = vdupq_n_u32(key[6]);
        let k7 = vdupq_n_u32(key[7]);
        let (mut ha0, mut ha1, mut ha2, mut ha3) = (k0, k1, k2, k3);
        let (mut ha4, mut ha5, mut ha6, mut ha7) = (k4, k5, k6, k7);
        let (mut hb0, mut hb1, mut hb2, mut hb3) = (k0, k1, k2, k3);
        let (mut hb4, mut hb5, mut hb6, mut hb7) = (k4, k5, k6, k7);

        // G function – identical to hash_4_chunks version.
        macro_rules! g4 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {{
                $a = vaddq_u32(vaddq_u32($a, $b), $mx);
                let xd = veorq_u32($d, $a);
                $d = vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(xd)));
                $c = vaddq_u32($c, $d);
                let xb = veorq_u32($b, $c);
                $b = vsliq_n_u32(vshrq_n_u32(xb, 12), xb, 20);
                $a = vaddq_u32(vaddq_u32($a, $b), $my);
                let xd = veorq_u32($d, $a);
                $d = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(xd), rot8));
                $c = vaddq_u32($c, $d);
                let xb = veorq_u32($b, $c);
                $b = vsliq_n_u32(vshrq_n_u32(xb, 7), xb, 25);
            }};
        }

        macro_rules! compress_block_8 {
            ($bf:expr, $wo:expr) => {{
                // ---- Group A state ----
                let (mut sa0, mut sa1, mut sa2, mut sa3) = (ha0, ha1, ha2, ha3);
                let (mut sa4, mut sa5, mut sa6, mut sa7) = (ha4, ha5, ha6, ha7);
                let (mut sa8, mut sa9, mut sa10, mut sa11) = (iv0, iv1, iv2, iv3);
                let (mut sa12, mut sa13, mut sa14, mut sa15) =
                    (ctr_lo_a, ctr_hi_a, blen, vdupq_n_u32($bf));

                // ---- Group B state ----
                let (mut sb0, mut sb1, mut sb2, mut sb3) = (hb0, hb1, hb2, hb3);
                let (mut sb4, mut sb5, mut sb6, mut sb7) = (hb4, hb5, hb6, hb7);
                let (mut sb8, mut sb9, mut sb10, mut sb11) = (iv0, iv1, iv2, iv3);
                let (mut sb12, mut sb13, mut sb14, mut sb15) =
                    (ctr_lo_b, ctr_hi_b, blen, vdupq_n_u32($bf));

                // ---- Load + 4×4-transpose ----
                macro_rules! t4x4 {
                    ($p0:expr, $p1:expr, $p2:expr, $p3:expr, $off:expr) => {{
                        let a = vld1q_u32($p0.add($wo + $off));
                        let b = vld1q_u32($p1.add($wo + $off));
                        let c = vld1q_u32($p2.add($wo + $off));
                        let d = vld1q_u32($p3.add($wo + $off));
                        let ab_l = vtrn1q_u32(a, b);
                        let ab_h = vtrn2q_u32(a, b);
                        let cd_l = vtrn1q_u32(c, d);
                        let cd_h = vtrn2q_u32(c, d);
                        (
                            vreinterpretq_u32_u64(vtrn1q_u64(
                                vreinterpretq_u64_u32(ab_l), vreinterpretq_u64_u32(cd_l))),
                            vreinterpretq_u32_u64(vtrn1q_u64(
                                vreinterpretq_u64_u32(ab_h), vreinterpretq_u64_u32(cd_h))),
                            vreinterpretq_u32_u64(vtrn2q_u64(
                                vreinterpretq_u64_u32(ab_l), vreinterpretq_u64_u32(cd_l))),
                            vreinterpretq_u32_u64(vtrn2q_u64(
                                vreinterpretq_u64_u32(ab_h), vreinterpretq_u64_u32(cd_h))),
                        )
                    }};
                }

                // Group A messages.
                let (mut ma0, mut ma1, mut ma2, mut ma3) = t4x4!(pa0, pa1, pa2, pa3, 0);
                let (mut ma4, mut ma5, mut ma6, mut ma7) = t4x4!(pa0, pa1, pa2, pa3, 4);
                let (mut ma8, mut ma9, mut ma10, mut ma11) = t4x4!(pa0, pa1, pa2, pa3, 8);
                let (mut ma12, mut ma13, mut ma14, mut ma15) = t4x4!(pa0, pa1, pa2, pa3, 12);

                // Group B messages.
                let (mut mb0, mut mb1, mut mb2, mut mb3) = t4x4!(pb0, pb1, pb2, pb3, 0);
                let (mut mb4, mut mb5, mut mb6, mut mb7) = t4x4!(pb0, pb1, pb2, pb3, 4);
                let (mut mb8, mut mb9, mut mb10, mut mb11) = t4x4!(pb0, pb1, pb2, pb3, 8);
                let (mut mb12, mut mb13, mut mb14, mut mb15) = t4x4!(pb0, pb1, pb2, pb3, 12);

                macro_rules! round8 {
                    () => {{
                        g4!(sa0, sa4, sa8,  sa12, ma0,  ma1);
                        g4!(sb0, sb4, sb8,  sb12, mb0,  mb1);
                        g4!(sa1, sa5, sa9,  sa13, ma2,  ma3);
                        g4!(sb1, sb5, sb9,  sb13, mb2,  mb3);
                        g4!(sa2, sa6, sa10, sa14, ma4,  ma5);
                        g4!(sb2, sb6, sb10, sb14, mb4,  mb5);
                        g4!(sa3, sa7, sa11, sa15, ma6,  ma7);
                        g4!(sb3, sb7, sb11, sb15, mb6,  mb7);
                        g4!(sa0, sa5, sa10, sa15, ma8,  ma9);
                        g4!(sb0, sb5, sb10, sb15, mb8,  mb9);
                        g4!(sa1, sa6, sa11, sa12, ma10, ma11);
                        g4!(sb1, sb6, sb11, sb12, mb10, mb11);
                        g4!(sa2, sa7, sa8,  sa13, ma12, ma13);
                        g4!(sb2, sb7, sb8,  sb13, mb12, mb13);
                        g4!(sa3, sa4, sa9,  sa14, ma14, ma15);
                        g4!(sb3, sb4, sb9,  sb14, mb14, mb15);
                    }};
                }

                macro_rules! perm_a {
                    () => {{
                        let (t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15)
                            = (ma2,ma6,ma3,ma10,ma7,ma0,ma4,ma13,
                               ma1,ma11,ma12,ma5,ma9,ma14,ma15,ma8);
                        ma0=t0; ma1=t1; ma2=t2; ma3=t3;
                        ma4=t4; ma5=t5; ma6=t6; ma7=t7;
                        ma8=t8; ma9=t9; ma10=t10; ma11=t11;
                        ma12=t12; ma13=t13; ma14=t14; ma15=t15;
                    }};
                }

                macro_rules! perm_b {
                    () => {{
                        let (t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15)
                            = (mb2,mb6,mb3,mb10,mb7,mb0,mb4,mb13,
                               mb1,mb11,mb12,mb5,mb9,mb14,mb15,mb8);
                        mb0=t0; mb1=t1; mb2=t2; mb3=t3;
                        mb4=t4; mb5=t5; mb6=t6; mb7=t7;
                        mb8=t8; mb9=t9; mb10=t10; mb11=t11;
                        mb12=t12; mb13=t13; mb14=t14; mb15=t15;
                    }};
                }

                // 7 rounds: 6 × (round + permute) + 1 × round.
                round8!(); perm_a!(); perm_b!();
                round8!(); perm_a!(); perm_b!();
                round8!(); perm_a!(); perm_b!();
                round8!(); perm_a!(); perm_b!();
                round8!(); perm_a!(); perm_b!();
                round8!(); perm_a!(); perm_b!();
                round8!();

                // Finalize group A.
                ha0 = veorq_u32(sa0, sa8);
                ha1 = veorq_u32(sa1, sa9);
                ha2 = veorq_u32(sa2, sa10);
                ha3 = veorq_u32(sa3, sa11);
                ha4 = veorq_u32(sa4, sa12);
                ha5 = veorq_u32(sa5, sa13);
                ha6 = veorq_u32(sa6, sa14);
                ha7 = veorq_u32(sa7, sa15);

                // Finalize group B.
                hb0 = veorq_u32(sb0, sb8);
                hb1 = veorq_u32(sb1, sb9);
                hb2 = veorq_u32(sb2, sb10);
                hb3 = veorq_u32(sb3, sb11);
                hb4 = veorq_u32(sb4, sb12);
                hb5 = veorq_u32(sb5, sb13);
                hb6 = veorq_u32(sb6, sb14);
                hb7 = veorq_u32(sb7, sb15);
            }};
        }

        // 16 blocks per chunk.  Not const_loop! — the 8-way body is so large
        // that full 16× unrolling hurts throughput.
        for blk in 0u32..16 {
            let bf = match blk {
                0 => flags | super::CHUNK_START,
                15 => flags | super::CHUNK_END,
                _ => flags,
            };
            compress_block_8!(bf, blk as usize * 16);
        }

        // Extract per-chunk chaining values for both groups.
        let mut ta = [[0u32; 4]; 8];
        vst1q_u32(ta[0].as_mut_ptr(), ha0);
        vst1q_u32(ta[1].as_mut_ptr(), ha1);
        vst1q_u32(ta[2].as_mut_ptr(), ha2);
        vst1q_u32(ta[3].as_mut_ptr(), ha3);
        vst1q_u32(ta[4].as_mut_ptr(), ha4);
        vst1q_u32(ta[5].as_mut_ptr(), ha5);
        vst1q_u32(ta[6].as_mut_ptr(), ha6);
        vst1q_u32(ta[7].as_mut_ptr(), ha7);
        let mut tb = [[0u32; 4]; 8];
        vst1q_u32(tb[0].as_mut_ptr(), hb0);
        vst1q_u32(tb[1].as_mut_ptr(), hb1);
        vst1q_u32(tb[2].as_mut_ptr(), hb2);
        vst1q_u32(tb[3].as_mut_ptr(), hb3);
        vst1q_u32(tb[4].as_mut_ptr(), hb4);
        vst1q_u32(tb[5].as_mut_ptr(), hb5);
        vst1q_u32(tb[6].as_mut_ptr(), hb6);
        vst1q_u32(tb[7].as_mut_ptr(), hb7);
        let mut out = [[0u32; 8]; 8];
        for j in 0..4 {
            out[j] = [
                ta[0][j], ta[1][j], ta[2][j], ta[3][j],
                ta[4][j], ta[5][j], ta[6][j], ta[7][j],
            ];
        }
        for j in 0..4 {
            out[4 + j] = [
                tb[0][j], tb[1][j], tb[2][j], tb[3][j],
                tb[4][j], tb[5][j], tb[6][j], tb[7][j],
            ];
        }
        out
    }
}

blake3_impl!(transform, hash_8_chunks, 8, hash_4_chunks, 4);

#[cfg(test)]
mod tests {
    use super::Blake3;

    blake3_test_case!();
}
