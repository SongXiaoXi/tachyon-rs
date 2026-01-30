#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "arm")]
use core::arch::arm::*;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha256 {
    sha256_define_const!();
    
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("neon")]
impl Sha256 {
    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;

        if self.offset > 0 {
            while i < data.len() {
                if self.offset < Self::BLOCK_LEN {
                    unsafe { crate::utils::assume(i < data.len()) };
                    self.buffer[self.offset] = data[i];
                    self.offset += 1;
                    i += 1;
                }
                if self.offset == Self::BLOCK_LEN {
                    self.offset = 0;
                    self.process_block();
                    self.len += Self::BLOCK_LEN as u64;
                    break;
                }
            }
        }
        while i + Self::BLOCK_LEN <= data.len() {
            self.process_block_with(unsafe { crate::utils::slice_to_array_at(data, i) });
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            self.offset = remain;
            self.buffer[..remain].copy_from_slice(&data[i..]);
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; 32] {
        let mlen = self.len + self.offset as u64; // in bytes
        let mlen_bits = mlen * 8; // in bits

        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert_eq!(
            (mlen + plen + Self::MLEN_SIZE as u64) % Self::BLOCK_LEN as u64,
            0
        );

        let plen = plen as usize;

        let mut padding: [u8; Self::MAX_PAD_LEN] = [0u8; Self::MAX_PAD_LEN];
        // Magic: black_box is used to prevent the compiler from using bzero
        core::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha256 = self;
        sha256.update(data);

        debug_assert_eq!(sha256.offset, 0);

        let state = sha256.state;
        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&state[0].to_be_bytes());
        output[4..8].copy_from_slice(&state[1].to_be_bytes());
        output[8..12].copy_from_slice(&state[2].to_be_bytes());
        output[12..16].copy_from_slice(&state[3].to_be_bytes());
        output[16..20].copy_from_slice(&state[4].to_be_bytes());
        output[20..24].copy_from_slice(&state[5].to_be_bytes());
        output[24..28].copy_from_slice(&state[6].to_be_bytes());
        output[28..32].copy_from_slice(&state[7].to_be_bytes());
        output
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline(always)]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; Self::BLOCK_LEN], &[u8; Self::BLOCK_LEN]>(&self.buffer) };
        self.process_block_with(block);
    }

    #[inline(always)]
    fn process_block_with(&mut self, block: &[u8; 64]) {
        transform(&mut self.state, block);
    }
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn transform(state: &mut [u32; 8], block: &[u8; Sha256::BLOCK_LEN]) {

    let mut block0 = vld1q_u8(block.as_ptr().add(0));
    let mut block1 = vld1q_u8(block.as_ptr().add(16));
    let mut block2 = vld1q_u8(block.as_ptr().add(32));
    let mut block3 = vld1q_u8(block.as_ptr().add(48));

    if cfg!(target_endian = "little") {
        block0 = vrev32q_u8(block0);
        block1 = vrev32q_u8(block1);
        block2 = vrev32q_u8(block2);
        block3 = vrev32q_u8(block3);
    }

    let msg0 = vreinterpretq_u32_u8(block0);
    let msg1 = vreinterpretq_u32_u8(block1);
    let msg2 = vreinterpretq_u32_u8(block2);
    let msg3 = vreinterpretq_u32_u8(block3);

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    #[allow(non_snake_case)]
    let K32 = crate::utils::black_box(super::K32.as_ptr());

    let mut w_add_k = [0u32; 16];

    vst1q_u32(w_add_k.as_mut_ptr().add(0), vaddq_u32(msg0, vld1q_u32(K32.add(0))));
    vst1q_u32(w_add_k.as_mut_ptr().add(4), vaddq_u32(msg1, vld1q_u32(K32.add(4))));
    vst1q_u32(w_add_k.as_mut_ptr().add(8), vaddq_u32(msg2, vld1q_u32(K32.add(8))));
    vst1q_u32(w_add_k.as_mut_ptr().add(12), vaddq_u32(msg3, vld1q_u32(K32.add(12))));

    macro_rules! compiler_barrier {
        () => {
            // std::hint::black_box(w_add_k.as_mut_ptr());
            core::arch::asm!("/* {0} */", in(reg) w_add_k.as_mut_ptr(), options(nostack, preserves_flags));
        }
    }

    use crate::utils::merge_bits;
    #[allow(non_snake_case)]
    #[inline(always)]
    fn CH(x: u32, y: u32, z: u32) -> u32 {
        merge_bits(z, y, x)
    }

    #[allow(non_snake_case)]
    #[inline(always)]
    fn MAJ(x: u32, y: u32, z: u32) -> u32 {
        // (x & y) ^ (x & z) ^ (y & z)
        (x & (y ^ z)) | (y & z)
    }

    #[allow(non_snake_case)]
    #[inline(always)]
    fn EP0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    
    #[allow(non_snake_case)]
    #[inline(always)]
    fn EP1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    macro_rules! sha256_round {
        ($i:expr) => {
            let t1 = h
                .wrapping_add(EP1(e))
                .wrapping_add(CH(e, f, g))
                .wrapping_add(w_add_k[$i]);
            let t2 = EP0(a).wrapping_add(MAJ(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        };
    }

    macro_rules! vsrr_n_u32 {
        ($v:expr, $r:literal) => {
            vsri_n_u32(vshl_n_u32($v, 32 - $r), $v, $r)
        };
    }

    macro_rules! update {
        ($msg0:ident,$msg1:ident,$msg2:ident,$msg3:ident,$msg4:ident,$msg5:ident,$msg6:ident,$msg7:ident) => {{
            let t0 = vext_u32($msg0, $msg1, 1);
            let t3 = vext_u32($msg4, $msg5, 1);

            let sigma0 = veor_u32(
                vsrr_n_u32!(t0, 7),
                veor_u32(
                    vsrr_n_u32!(t0, 18),
                    vshr_n_u32(t0, 3),
                )
            );
            let sigma1 = veor_u32(
                vsrr_n_u32!($msg7, 17),
                veor_u32(
                    vsrr_n_u32!($msg7, 19),
                    vshr_n_u32($msg7, 10),
                )
            );

            $msg0 = vadd_u32(
                vadd_u32($msg0, sigma0),
                vadd_u32(t3, sigma1),
            )
        }};
    }

    let (
        mut msg0, mut msg1,
        mut msg2, mut msg3,
        mut msg4, mut msg5,
        mut msg6, mut msg7,
    ) = (
        vget_low_u32(msg0), vget_high_u32(msg0),
        vget_low_u32(msg1), vget_high_u32(msg1),
        vget_low_u32(msg2), vget_high_u32(msg2),
        vget_low_u32(msg3), vget_high_u32(msg3),
    );

    crate::const_loop!(j, 1, 3, {
        sha256_round!(0);
        update!(msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7);
        sha256_round!(1);
        vst1_u32(w_add_k.as_mut_ptr().add(0), vadd_u32(msg0, vld1_u32(K32.add(16 * j + 0))));

        sha256_round!(2);
        update!(msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg0);
        sha256_round!(3);
        vst1_u32(w_add_k.as_mut_ptr().add(2), vadd_u32(msg1, vld1_u32(K32.add(16 * j + 2))));

        sha256_round!(4);
        update!(msg2, msg3, msg4, msg5, msg6, msg7, msg0, msg1);
        sha256_round!(5);
        vst1_u32(w_add_k.as_mut_ptr().add(4), vadd_u32(msg2, vld1_u32(K32.add(16 * j + 4))));

        sha256_round!(6);
        update!(msg3, msg4, msg5, msg6, msg7, msg0, msg1, msg2);
        sha256_round!(7);
        vst1_u32(w_add_k.as_mut_ptr().add(6), vadd_u32(msg3, vld1_u32(K32.add(16 * j + 6))));

        sha256_round!(8);
        update!(msg4, msg5, msg6, msg7, msg0, msg1, msg2, msg3);
        sha256_round!(9);
        vst1_u32(w_add_k.as_mut_ptr().add(8), vadd_u32(msg4, vld1_u32(K32.add(16 * j + 8))));

        sha256_round!(10);
        update!(msg5, msg6, msg7, msg0, msg1, msg2, msg3, msg4);
        sha256_round!(11);
        vst1_u32(w_add_k.as_mut_ptr().add(10), vadd_u32(msg5, vld1_u32(K32.add(16 * j + 10))));

        sha256_round!(12);
        update!(msg6, msg7, msg0, msg1, msg2, msg3, msg4, msg5);
        sha256_round!(13);
        vst1_u32(w_add_k.as_mut_ptr().add(12), vadd_u32(msg6, vld1_u32(K32.add(16 * j + 12))));

        sha256_round!(14);
        update!(msg7, msg0, msg1, msg2, msg3, msg4, msg5, msg6);
        sha256_round!(15);
        vst1_u32(w_add_k.as_mut_ptr().add(14), vadd_u32(msg7, vld1_u32(K32.add(16 * j + 14))));
    
        // std::hint::black_box(w_add_k.as_mut_ptr());
        compiler_barrier!();
    });

    /*
    let mut msg0 = msg0;
    let mut msg1 = msg1;
    let mut msg2 = msg2;
    let mut msg3 = msg3;

    macro_rules! vsrrq_n_u32 {
        ($v:expr, $r:literal) => {
            vsriq_n_u32(vshlq_n_u32($v, 32 - $r), $v, $r)
        };
    }

    macro_rules! update2 {
        ($msg0:ident,$msg1:ident,$msg2:ident,$msg3:ident) => {{
            let t0 = vextq_u32($msg0, $msg1, 1);
            let t3 = vextq_u32($msg2, $msg3, 1);

            let sigma0 = veorq_u32(
                vsrrq_n_u32!(t0, 7),
                veorq_u32(
                    vsrrq_n_u32!(t0, 18),
                    vshrq_n_u32(t0, 3),
                )
            );

            let s14_s15 = vextq_u32($msg3, vdupq_n_u32(0), 2);
            let sigma1_0 = veorq_u32(
                vsrrq_n_u32!(s14_s15, 17),
                veorq_u32(
                    vsrrq_n_u32!(s14_s15, 19),
                    vshrq_n_u32(s14_s15, 10),
                )
            );

            let tmp = vaddq_u32(
                vaddq_u32($msg0, sigma0),
                vaddq_u32(t3, sigma1_0),
            );

            let tmp_lo = vget_low_u32(tmp);
            let sigma1_1 = veor_u32(
                vsrr_n_u32!(tmp_lo, 17),
                veor_u32(
                    vsrr_n_u32!(tmp_lo, 19),
                    vshr_n_u32(tmp_lo, 10),
                )
            );

            $msg0 = vaddq_u32(tmp, vcombine_u32(vdup_n_u32(0), sigma1_1));
        }}
    }

    crate::const_loop!(j, 1, 3, {
        sha256_round!(0);
        update2!(msg0, msg1, msg2, msg3);
        sha256_round!(1);
        sha256_round!(2);
        sha256_round!(3);
        vst1q_u32(w_add_k.as_mut_ptr().add(0), vaddq_u32(msg0, vld1q_u32(K32.add(16 * j + 0))));

        sha256_round!(4);
        update2!(msg1, msg2, msg3, msg0);
        sha256_round!(5);
        sha256_round!(6);
        sha256_round!(7);
        vst1q_u32(w_add_k.as_mut_ptr().add(4), vaddq_u32(msg1, vld1q_u32(K32.add(16 * j + 4))));

        sha256_round!(8);
        update2!(msg2, msg3, msg0, msg1);
        sha256_round!(9);
        sha256_round!(10);
        sha256_round!(11);
        vst1q_u32(w_add_k.as_mut_ptr().add(8), vaddq_u32(msg2, vld1q_u32(K32.add(16 * j + 8))));

        sha256_round!(12);
        update2!(msg3, msg0, msg1, msg2);
        sha256_round!(13);
        sha256_round!(14);
        sha256_round!(15);
        vst1q_u32(w_add_k.as_mut_ptr().add(12), vaddq_u32(msg3, vld1q_u32(K32.add(16 * j + 12))));
    
        std::hint::black_box(w_add_k.as_mut_ptr());
    });
    */

    crate::const_loop!(i, 0, 16, {
        sha256_round!(i);
    });

    state[0] = crate::utils::black_box(a.wrapping_add(state[0]));
    state[1] = crate::utils::black_box(b.wrapping_add(state[1]));
    state[2] = crate::utils::black_box(c.wrapping_add(state[2]));
    state[3] = crate::utils::black_box(d.wrapping_add(state[3]));
    state[4] = crate::utils::black_box(e.wrapping_add(state[4]));
    state[5] = crate::utils::black_box(f.wrapping_add(state[5]));
    state[6] = crate::utils::black_box(g.wrapping_add(state[6]));
    state[7] = crate::utils::black_box(h.wrapping_add(state[7]));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        #[cfg(target_arch = "aarch64")]
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }
        #[cfg(target_arch = "arm")]
        if !std::arch::is_arm_feature_detected!("neon") {
            return;
        }
        sha256_test_case!();
    }
}