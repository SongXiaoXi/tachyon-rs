#[cfg(target_arch = "arm")]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha512 {
    state: [u64; 8],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha512 {
    sha512_define_const!();

    #[inline]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 128],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("neon")]
impl Sha512 {
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
                    self.offset = 0;
                    self.process_block();
                    self.len += Self::BLOCK_LEN as u64;
                    break;
                }
            }
        }
        while i + Self::BLOCK_LEN <= data.len() {
            process_block_with!(self.state, unsafe { crate::utils::slice_to_array_at::<_, {Self::BLOCK_LEN}>(data, i) });
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            // SAFETY: remain is less than BLOCK_LEN
            unsafe {
                self.buffer.get_unchecked_mut(..remain).copy_from_slice(&data[i..]);
            }
            self.offset = remain;
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; 64] {
        let mlen = self.len as u128 + self.offset as u128; // in bytes
        let mlen_bits = mlen * 8; // in bits

        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert_eq!(
            (mlen + plen + Self::MLEN_SIZE as u128) % Self::BLOCK_LEN as u128,
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
        let mut sha512 = self;
        sha512.update(data);

        debug_assert_eq!(sha512.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..8].copy_from_slice(&sha512.state[0].to_be_bytes());
        output[8..16].copy_from_slice(&sha512.state[1].to_be_bytes());
        output[16..24].copy_from_slice(&sha512.state[2].to_be_bytes());
        output[24..32].copy_from_slice(&sha512.state[3].to_be_bytes());
        output[32..40].copy_from_slice(&sha512.state[4].to_be_bytes());
        output[40..48].copy_from_slice(&sha512.state[5].to_be_bytes());
        output[48..56].copy_from_slice(&sha512.state[6].to_be_bytes());
        output[56..64].copy_from_slice(&sha512.state[7].to_be_bytes());
        output
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 64] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; Self::BLOCK_LEN], &[u8; Self::BLOCK_LEN]>(&self.buffer) };
        process_block_with!(self.state, block);
    }
}

#[macro_use]
mod macros {
macro_rules! process_block_with {
    ($state:expr, $block:expr) => {
        {
            let block = $block;
            let mut state = $state;
            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];

            let mut s0 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(0 * 16)));
            let mut s1 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(1 * 16)));
            let mut s2 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(2 * 16)));
            let mut s3 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(3 * 16)));
            let mut s4 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(4 * 16)));
            let mut s5 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(5 * 16)));
            let mut s6 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(6 * 16)));
            let mut s7 = vreinterpretq_u64_u8(vld1q_u8(block.as_ptr().add(7 * 16)));

            // if little endian
            if cfg!(target_endian = "little") {
                s0 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s0)));
                s1 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s1)));
                s2 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s2)));
                s3 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s3)));
                s4 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s4)));
                s5 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s5)));
                s6 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s6)));
                s7 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(s7)));
            }

            // Magic: black_box is used to prevent the compiler from using load immediate instructions
            #[allow(non_snake_case)]
            let K = std::hint::black_box(super::K.as_ptr());
            let mut w_add_k = [0u64; 16];

            vst1q_u64(w_add_k.as_mut_ptr().add(0), vaddq_u64(s0, vld1q_u64(K.add(0))));
            vst1q_u64(w_add_k.as_mut_ptr().add(2), vaddq_u64(s1, vld1q_u64(K.add(2))));
            vst1q_u64(w_add_k.as_mut_ptr().add(4), vaddq_u64(s2, vld1q_u64(K.add(4))));
            vst1q_u64(w_add_k.as_mut_ptr().add(6), vaddq_u64(s3, vld1q_u64(K.add(6))));
            vst1q_u64(w_add_k.as_mut_ptr().add(8), vaddq_u64(s4, vld1q_u64(K.add(8))));
            vst1q_u64(w_add_k.as_mut_ptr().add(10), vaddq_u64(s5, vld1q_u64(K.add(10))));
            vst1q_u64(w_add_k.as_mut_ptr().add(12), vaddq_u64(s6, vld1q_u64(K.add(12))));
            vst1q_u64(w_add_k.as_mut_ptr().add(14), vaddq_u64(s7, vld1q_u64(K.add(14))));

            macro_rules! sha512_round {
                ($i:expr) => {
                    let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                    let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                    let maj = (a & b) ^ (a & c) ^ (b & c);
                    let ch = crate::utils::merge_bits(g, f, e);
                    let t2 = s0.wrapping_add(maj);
                    let t1 = h
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(w_add_k[$i]);

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

            macro_rules! vsrrq_n_u64 {
                ($v:expr, 8) => {
                    {
                        let maskb = [1u8, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8];
                        let mask = vld1q_u8(maskb.as_ptr());
                        vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64($v), mask))
                    }
                };
                ($v:expr, $r:literal) => {
                    vsriq_n_u64(vshlq_n_u64($v, 64 - $r), $v, $r)
                };
            }

            macro_rules! update {
                ($s0:ident,$s1:ident,$s2:ident,$s3:ident,$s4:ident,$s5:ident,$s6:ident,$s7:ident) => {
                    {
                        let t0 = vextq_u64($s0, $s1, 1);
                        let t3 = vextq_u64($s4, $s5, 1);
                        
                        let sigma0 = veorq_u64(veorq_u64(vsrrq_n_u64!(t0, 1), vsrrq_n_u64!(t0, 8)), vshrq_n_u64(t0, 7));
                        let sigma1 = veorq_u64(veorq_u64(vsrrq_n_u64!($s7, 19), vsrrq_n_u64!($s7, 61)), vshrq_n_u64($s7, 6));

                        $s0 = vaddq_u64(vaddq_u64(t3, sigma0), vaddq_u64(sigma1, $s0));
                    }
                };
            }

            crate::const_loop!(j, 1, 4, {
                sha512_round!(0);
                sha512_round!(1);
                update!(s0, s1, s2, s3, s4, s5, s6, s7);
                vst1q_u64(w_add_k.as_mut_ptr().add(0), vaddq_u64(s0, vld1q_u64(K.add(16 * j + 0))));

                sha512_round!(2);
                sha512_round!(3);
                update!(s1, s2, s3, s4, s5, s6, s7, s0);
                vst1q_u64(w_add_k.as_mut_ptr().add(2), vaddq_u64(s1, vld1q_u64(K.add(16 * j + 2))));

                sha512_round!(4);
                sha512_round!(5);
                update!(s2, s3, s4, s5, s6, s7, s0, s1);
                vst1q_u64(w_add_k.as_mut_ptr().add(4), vaddq_u64(s2, vld1q_u64(K.add(16 * j + 4))));

                sha512_round!(6);
                sha512_round!(7);
                update!(s3, s4, s5, s6, s7, s0, s1, s2);
                vst1q_u64(w_add_k.as_mut_ptr().add(6), vaddq_u64(s3, vld1q_u64(K.add(16 * j + 6))));

                sha512_round!(8);
                sha512_round!(9);
                update!(s4, s5, s6, s7, s0, s1, s2, s3);
                vst1q_u64(w_add_k.as_mut_ptr().add(8), vaddq_u64(s4, vld1q_u64(K.add(16 * j + 8))));

                sha512_round!(10);
                sha512_round!(11);
                update!(s5, s6, s7, s0, s1, s2, s3, s4);
                vst1q_u64(w_add_k.as_mut_ptr().add(10), vaddq_u64(s5, vld1q_u64(K.add(16 * j + 10))));

                sha512_round!(12);
                sha512_round!(13);
                update!(s6, s7, s0, s1, s2, s3, s4, s5);
                vst1q_u64(w_add_k.as_mut_ptr().add(12), vaddq_u64(s6, vld1q_u64(K.add(16 * j + 12))));

                sha512_round!(14);
                sha512_round!(15);
                update!(s7, s0, s1, s2, s3, s4, s5, s6);
                vst1q_u64(w_add_k.as_mut_ptr().add(14), vaddq_u64(s7, vld1q_u64(K.add(16 * j + 14))));

                // Magic: black_box is used to prevent the compiler from generating bad re-ordering instructions.
                // For example, the compiler may generate all NEON instructions first and save all w_add_k values to the stack.
                std::hint::black_box(w_add_k.as_mut_ptr());
            });

            crate::const_loop!(i, 0, 16, {
                sha512_round!(i);
            });

            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);

            $state = state;
        }
    }
}
}

use process_block_with;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha512() {
        if std::arch::is_aarch64_feature_detected!("neon") {
            sha512_test_case!();
        }
    }
}