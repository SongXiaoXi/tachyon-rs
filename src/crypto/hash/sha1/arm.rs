#[cfg(target_arch = "arm")]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

#[derive(Clone, Copy)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha1 {
    sha1_define_const!();

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }
}

#[unsafe_target_feature::unsafe_target_feature("neon")]
impl Sha1 {
    #[inline]
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
                    self.process_block();
                    self.offset = 0;
                    self.len += Self::BLOCK_LEN as u64;
                    break;
                }
            }
        }
        while i + Self::BLOCK_LEN <= data.len() {
            let block = unsafe { crate::utils::slice_to_array_at::<u8, 64>(data, i) };
            process_block_with!(self.state, block);
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            self.offset = remain;
            // SAFETY: remain is less than BLOCK_LEN
            unsafe {
                self.buffer.get_unchecked_mut(..remain).copy_from_slice(&data[i..]);
            }
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; 20] {
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
        std::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha1 = self;
        sha1.update(data);

        debug_assert_eq!(sha1.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&sha1.state[0].to_be_bytes());
        output[4..8].copy_from_slice(&sha1.state[1].to_be_bytes());
        output[8..12].copy_from_slice(&sha1.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&sha1.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&sha1.state[4].to_be_bytes());
        output
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 20] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline(always)]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; 64], &[u8; 64]>(&self.buffer) };
        process_block_with!(self.state, block);
    }
}

#[macro_use]
mod macros {

macro_rules! process_block_with {
    ($state:expr, $block:expr) => {{
        let block = $block;
        let mut state = $state;

        let mut s0 = vld1q_u32(block.as_ptr() as *const u32);
        let mut s1 = vld1q_u32(block.as_ptr().add(16) as *const u32);
        let mut s2 = vld1q_u32(block.as_ptr().add(32) as *const u32);
        let mut s3 = vld1q_u32(block.as_ptr().add(48) as *const u32);

        // if little endian
        if cfg!(target_endian = "little") {
            s0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(s0)));
            s1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(s1)));
            s2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(s2)));
            s3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(s3)));
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];

        let mut w_add_k = [0u32; 16];

        let k32 = vdupq_n_u32(0x5a827999);

        vst1q_u32(w_add_k.as_mut_ptr().add(0) as *mut _, vaddq_u32(s0, k32));
        vst1q_u32(w_add_k.as_mut_ptr().add(4) as *mut _, vaddq_u32(s1, k32));
        vst1q_u32(w_add_k.as_mut_ptr().add(8) as *mut _, vaddq_u32(s2, k32));
        vst1q_u32(w_add_k.as_mut_ptr().add(12) as *mut _, vaddq_u32(s3, k32));

        use crate::utils::merge_bits;

        macro_rules! sha1_round {
            ($i:expr, $r:literal) => {{
                let f = match $r {
                    0 => merge_bits(d, c, b),
                    1 => b ^ d ^ c,
                    2 => (c & (b ^ d)) | (b & d),
                    3 => b ^ d ^ c,
                    _ => unreachable!(),
                };
                let temp = a.rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e.wrapping_add(w_add_k[$i % 16]));
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }};
        }

        macro_rules! sha1_round1 {
            ($i:expr) => {{ sha1_round!($i, 0); }};
        }

        macro_rules! sha1_round2 {
            ($i:expr) => {{ sha1_round!($i, 1); }};
        }

        macro_rules! sha1_round3 {
            ($i:expr) => {{ sha1_round!($i, 2); }};
        }

        macro_rules! sha1_round4 {
            ($i:expr) => {{ sha1_round2!($i); }};
        }
        /*
        macro_rules! vslr_u32 {
            ($x:expr, 1) => {
                vsri_n_u32(vadd_u32($x, $x), $x, 31)
            };
            ($x:expr, $n:expr) => {
                vsli_n_u32(vshr_n_u32($x, 32 - $n), $x, $n)
            };
        }

        macro_rules! update {
            ($s0:ident,$s1:ident,$s2:ident,$s3:ident,$s4:ident,$s5:ident,$s6:ident,$s7:ident) => {{
                let t1 = veor_u32(
                    veor_u32(
                        $s0,
                        $s1,
                    ),
                    veor_u32(
                        $s4,
                        vext_u32($s6, $s7, 1),
                    ),
                );
                $s0 = vslr_u32!(t1, 1);
            }};
        }

        let (
            mut s0, mut s1,
            mut s2, mut s3,
            mut s4, mut s5,
            mut s6, mut s7,
        ) = (
            vget_low_u32(s0), vget_high_u32(s0),
            vget_low_u32(s1), vget_high_u32(s1),
            vget_low_u32(s2), vget_high_u32(s2),
            vget_low_u32(s3), vget_high_u32(s3),
        );

        let k32 = vget_low_u32(k32);

        sha1_round1!(0);
        update!(s0, s1, s2, s3, s4, s5, s6, s7);
        sha1_round1!(1);
        vst1_u32(w_add_k.as_mut_ptr().add(0), vadd_u32(s0, k32));
        sha1_round1!(2);
        update!(s1, s2, s3, s4, s5, s6, s7, s0);
        sha1_round1!(3);
        vst1_u32(w_add_k.as_mut_ptr().add(2), vadd_u32(s1, k32));
        sha1_round1!(4);
        update!(s2, s3, s4, s5, s6, s7, s0, s1);
        sha1_round1!(5);
        let k32 = vdup_n_u32(0x6ed9eba1u32);
        vst1_u32(w_add_k.as_mut_ptr().add(4), vadd_u32(s2, k32));
        sha1_round1!(6);
        update!(s3, s4, s5, s6, s7, s0, s1, s2);
        sha1_round1!(7);
        vst1_u32(w_add_k.as_mut_ptr().add(6), vadd_u32(s3, k32));
        sha1_round1!(8);
        update!(s4, s5, s6, s7, s0, s1, s2, s3);
        sha1_round1!(9);
        vst1_u32(w_add_k.as_mut_ptr().add(8), vadd_u32(s4, k32));
        sha1_round1!(10);
        update!(s5, s6, s7, s0, s1, s2, s3, s4);
        sha1_round1!(11);
        vst1_u32(w_add_k.as_mut_ptr().add(10), vadd_u32(s5, k32));
        sha1_round1!(12);
        update!(s6, s7, s0, s1, s2, s3, s4, s5);
        sha1_round1!(13);
        vst1_u32(w_add_k.as_mut_ptr().add(12), vadd_u32(s6, k32));
        sha1_round1!(14);
        update!(s7, s0, s1, s2, s3, s4, s5, s6);
        sha1_round1!(15);
        vst1_u32(w_add_k.as_mut_ptr().add(14), vadd_u32(s7, k32));

        std::hint::black_box(w_add_k.as_mut_ptr());

        sha1_round1!(0);
        update!(s0, s1, s2, s3, s4, s5, s6, s7);
        sha1_round1!(1);
        vst1_u32(w_add_k.as_mut_ptr().add(0), vadd_u32(s0, k32));
        sha1_round1!(2);
        update!(s1, s2, s3, s4, s5, s6, s7, s0);
        sha1_round1!(3);
        vst1_u32(w_add_k.as_mut_ptr().add(2), vadd_u32(s1, k32));

        sha1_round2!(4);
        update!(s2, s3, s4, s5, s6, s7, s0, s1);
        sha1_round2!(5);
        vst1_u32(w_add_k.as_mut_ptr().add(4), vadd_u32(s2, k32));
        sha1_round2!(6);
        update!(s3, s4, s5, s6, s7, s0, s1, s2);
        sha1_round2!(7);
        vst1_u32(w_add_k.as_mut_ptr().add(6), vadd_u32(s3, k32));
        sha1_round2!(8);
        update!(s4, s5, s6, s7, s0, s1, s2, s3);
        sha1_round2!(9);
        let k32 = vdup_n_u32(0x8f1bbcdc);
        vst1_u32(w_add_k.as_mut_ptr().add(8), vadd_u32(s4, k32));
        sha1_round2!(10);
        update!(s5, s6, s7, s0, s1, s2, s3, s4);
        sha1_round2!(11);
        vst1_u32(w_add_k.as_mut_ptr().add(10), vadd_u32(s5, k32));
        sha1_round2!(12);
        update!(s6, s7, s0, s1, s2, s3, s4, s5);
        sha1_round2!(13);
        vst1_u32(w_add_k.as_mut_ptr().add(12), vadd_u32(s6, k32));
        sha1_round2!(14);
        update!(s7, s0, s1, s2, s3, s4, s5, s6);
        sha1_round2!(15);
        vst1_u32(w_add_k.as_mut_ptr().add(14), vadd_u32(s7, k32));

        std::hint::black_box(w_add_k.as_mut_ptr());

        sha1_round2!(0);
        update!(s0, s1, s2, s3, s4, s5, s6, s7);
        sha1_round2!(1);
        vst1_u32(w_add_k.as_mut_ptr().add(0), vadd_u32(s0, k32));
        sha1_round2!(2);
        update!(s1, s2, s3, s4, s5, s6, s7, s0);
        sha1_round2!(3);
        vst1_u32(w_add_k.as_mut_ptr().add(2), vadd_u32(s1, k32));
        sha1_round2!(4);
        update!(s2, s3, s4, s5, s6, s7, s0, s1);
        sha1_round2!(5);
        vst1_u32(w_add_k.as_mut_ptr().add(4), vadd_u32(s2, k32));
        sha1_round2!(6);
        update!(s3, s4, s5, s6, s7, s0, s1, s2);
        sha1_round2!(7);
        vst1_u32(w_add_k.as_mut_ptr().add(6), vadd_u32(s3, k32));

        sha1_round3!(8);
        update!(s4, s5, s6, s7, s0, s1, s2, s3);
        sha1_round3!(9);
        vst1_u32(w_add_k.as_mut_ptr().add(8), vadd_u32(s4, k32));
        sha1_round3!(10);
        update!(s5, s6, s7, s0, s1, s2, s3, s4);
        sha1_round3!(11);
        vst1_u32(w_add_k.as_mut_ptr().add(10), vadd_u32(s5, k32));
        sha1_round3!(12);
        update!(s6, s7, s0, s1, s2, s3, s4, s5);
        sha1_round3!(13);
        let k32 = vdup_n_u32(0xca62c1d6);
        vst1_u32(w_add_k.as_mut_ptr().add(12), vadd_u32(s6, k32));
        sha1_round3!(14);
        update!(s7, s0, s1, s2, s3, s4, s5, s6);
        sha1_round3!(15);
        vst1_u32(w_add_k.as_mut_ptr().add(14), vadd_u32(s7, k32));

        std::hint::black_box(w_add_k.as_mut_ptr());

        sha1_round3!(0);
        update!(s0, s1, s2, s3, s4, s5, s6, s7);
        sha1_round3!(1);
        vst1_u32(w_add_k.as_mut_ptr().add(0), vadd_u32(s0, k32));
        sha1_round3!(2);
        update!(s1, s2, s3, s4, s5, s6, s7, s0);
        sha1_round3!(3);
        vst1_u32(w_add_k.as_mut_ptr().add(2), vadd_u32(s1, k32));
        sha1_round3!(4);
        update!(s2, s3, s4, s5, s6, s7, s0, s1);
        sha1_round3!(5);
        vst1_u32(w_add_k.as_mut_ptr().add(4), vadd_u32(s2, k32));
        sha1_round3!(6);
        update!(s3, s4, s5, s6, s7, s0, s1, s2);
        sha1_round3!(7);
        vst1_u32(w_add_k.as_mut_ptr().add(6), vadd_u32(s3, k32));
        sha1_round3!(8);
        update!(s4, s5, s6, s7, s0, s1, s2, s3);
        sha1_round3!(9);
        vst1_u32(w_add_k.as_mut_ptr().add(8), vadd_u32(s4, k32));
        sha1_round3!(10);
        update!(s5, s6, s7, s0, s1, s2, s3, s4);
        sha1_round3!(11);
        vst1_u32(w_add_k.as_mut_ptr().add(10), vadd_u32(s5, k32));

        sha1_round4!(12);
        update!(s6, s7, s0, s1, s2, s3, s4, s5);
        sha1_round4!(13);
        vst1_u32(w_add_k.as_mut_ptr().add(12), vadd_u32(s6, k32));
        sha1_round4!(14);
        update!(s7, s0, s1, s2, s3, s4, s5, s6);
        sha1_round4!(15);
        vst1_u32(w_add_k.as_mut_ptr().add(14), vadd_u32(s7, k32));

        std::hint::black_box(w_add_k.as_mut_ptr());

        crate::const_loop!(i, 0, 16, {
            sha1_round4!(i);
        });
        */

        macro_rules! vslrq_u32 {
            ($x:expr, 1) => {
                vsriq_n_u32(vaddq_u32($x, $x), $x, 31)
            };
            ($x:expr, $n:expr) => {
                vsliq_n_u32(vshrq_n_u32($x, 32 - $n), $x, $n)
            };
        }

        macro_rules! update2 {
            ($s0:expr,$s1:expr,$s2:expr,$s3:expr) => {{
                let t0 = vextq_u32($s0, $s1, 2);
                let t1 = vextq_u32($s3, vdupq_n_u32(0), 1);

                let t2 = veorq_u32(
                    veorq_u32($s2, t1),
                    veorq_u32($s0, t0),
                );

                let t4 = vslrq_u32!(vextq_u32(vdupq_n_u32(0), t2, 1), 2);
                let t3 = vslrq_u32!(t2, 1);

                $s0 = veorq_u32(t3, t4);
            }};
        }

        macro_rules! write_w_add_k {
            ($i:expr, $s:expr, $k32:expr) => {{
                vst1q_u32(w_add_k.as_mut_ptr().add($i), vaddq_u32($s, $k32));
            }};
        }

        macro_rules! compiler_barrier {
            () => {
                // std::hint::black_box(w_add_k.as_mut_ptr());
                core::arch::asm!("/* {0} */", in(reg) w_add_k.as_mut_ptr(), options(nostack, preserves_flags));
            }
        }

        sha1_round1!(0);
        update2!(s0, s1, s2, s3);
        sha1_round1!(1);
        sha1_round1!(2);
        sha1_round1!(3);
        write_w_add_k!(0, s0, k32);
        let k32 = vdupq_n_u32(0x6ed9eba1);
        sha1_round1!(4);
        update2!(s1, s2, s3, s0);
        sha1_round1!(5);
        sha1_round1!(6);
        sha1_round1!(7);
        write_w_add_k!(4, s1, k32);
        sha1_round1!(8);
        update2!(s2, s3, s0, s1);
        sha1_round1!(9);
        sha1_round1!(10);
        sha1_round1!(11);
        write_w_add_k!(8, s2, k32);
        sha1_round1!(12);
        update2!(s3, s0, s1, s2);
        sha1_round1!(13);
        sha1_round1!(14);
        sha1_round1!(15);
        write_w_add_k!(12, s3, k32);
        compiler_barrier!();

        sha1_round1!(0);
        update2!(s0, s1, s2, s3);
        sha1_round1!(1);
        sha1_round1!(2);
        sha1_round1!(3);
        write_w_add_k!(0, s0, k32);
        sha1_round2!(4);
        update2!(s1, s2, s3, s0);
        sha1_round2!(5);
        sha1_round2!(6);
        sha1_round2!(7);
        write_w_add_k!(4, s1, k32);
        let k32 = vdupq_n_u32(0x8f1bbcdc);
        sha1_round2!(8);
        update2!(s2, s3, s0, s1);
        sha1_round2!(9);
        sha1_round2!(10);
        sha1_round2!(11);
        write_w_add_k!(8, s2, k32);
        sha1_round2!(12);
        update2!(s3, s0, s1, s2);
        sha1_round2!(13);
        sha1_round2!(14);
        sha1_round2!(15);
        write_w_add_k!(12, s3, k32);
        compiler_barrier!();

        sha1_round2!(0);
        update2!(s0, s1, s2, s3);
        sha1_round2!(1);
        sha1_round2!(2);
        sha1_round2!(3);
        write_w_add_k!(0, s0, k32);
        sha1_round2!(4);
        update2!(s1, s2, s3, s0);
        sha1_round2!(5);
        sha1_round2!(6);
        sha1_round2!(7);
        write_w_add_k!(4, s1, k32);
        sha1_round3!(8);
        update2!(s2, s3, s0, s1);
        sha1_round3!(9);
        sha1_round3!(10);
        sha1_round3!(11);
        write_w_add_k!(8, s2, k32);
        let k32 = vdupq_n_u32(0xca62c1d6);
        sha1_round3!(12);
        update2!(s3, s0, s1, s2);
        sha1_round3!(13);
        sha1_round3!(14);
        sha1_round3!(15);
        write_w_add_k!(12, s3, k32);
        compiler_barrier!();

        sha1_round3!(0);
        update2!(s0, s1, s2, s3);
        sha1_round3!(1);
        sha1_round3!(2);
        sha1_round3!(3);
        write_w_add_k!(0, s0, k32);
        sha1_round3!(4);
        update2!(s1, s2, s3, s0);
        sha1_round3!(5);
        sha1_round3!(6);
        sha1_round3!(7);
        write_w_add_k!(4, s1, k32);
        sha1_round3!(8);
        update2!(s2, s3, s0, s1);
        sha1_round3!(9);
        sha1_round3!(10);
        sha1_round3!(11);
        write_w_add_k!(8, s2, k32);
        sha1_round4!(12);
        update2!(s3, s0, s1, s2);
        sha1_round4!(13);
        sha1_round4!(14);
        sha1_round4!(15);
        write_w_add_k!(12, s3, k32);
        compiler_barrier!();

        crate::const_loop!(i, 0, 16, {
            sha1_round4!(i);
        });

        state[0] = crate::utils::black_box(state[0].wrapping_add(a));
        state[1] = crate::utils::black_box(state[1].wrapping_add(b));
        state[2] = crate::utils::black_box(state[2].wrapping_add(c));
        state[3] = crate::utils::black_box(state[3].wrapping_add(d));
        state[4] = crate::utils::black_box(state[4].wrapping_add(e));
        $state = state;
    }};
}
}

pub(crate) use process_block_with;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        if !crate::is_hw_feature_detected!("neon") {
            return;
        }
        sha1_test_case!();
    }
}