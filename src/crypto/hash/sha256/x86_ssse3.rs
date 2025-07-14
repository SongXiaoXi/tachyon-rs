#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
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

#[unsafe_target_feature("ssse3")]
impl Sha256 {

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
            let block = unsafe { crate::utils::slice_to_array_at::<_, { Self::BLOCK_LEN }>(data, i) };
            _mm_prefetch(block.as_ptr().add(64) as *const _, _MM_HINT_T0);
            _mm_prefetch(block.as_ptr().add(128) as *const _, _MM_HINT_T0);
            process_block_with!(self.state, block);
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            self.offset = remain;
            self.buffer[..remain].copy_from_slice(&data[i..]);
        }
    }

    #[inline]
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
        std::hint::black_box(padding.as_mut_ptr());
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

    #[inline(always)]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline(always)]
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
    
            let mut s0 = _mm_loadu_si128(block.as_ptr().add(0 * 16) as *const __m128i);
            let mut s1 = _mm_loadu_si128(block.as_ptr().add(1 * 16) as *const __m128i);
            let mut s2 = _mm_loadu_si128(block.as_ptr().add(2 * 16) as *const __m128i);
            let mut s3 = _mm_loadu_si128(block.as_ptr().add(3 * 16) as *const __m128i);
    
            // little-endian to big-endian
            let mask = _mm_set_epi64x(
                0x0c0d0e0f08090a0b,
                0x0405060700010203
            );
            s0 = _mm_shuffle_epi8(s0, mask);
            s1 = _mm_shuffle_epi8(s1, mask);
            s2 = _mm_shuffle_epi8(s2, mask);
            s3 = _mm_shuffle_epi8(s3, mask);

            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];
    
            // Magic: black_box is used to prevent the compiler from using load immediate instructions
            #[allow(non_snake_case)]
            let K32 = crate::utils::black_box(super::K32.as_ptr());

            let mut w_add_k = [0u32; 16];
    
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(0) as _, _mm_add_epi32(s0, _mm_loadu_si128(K32.add(0) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(4) as _, _mm_add_epi32(s1, _mm_loadu_si128(K32.add(4) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(8) as _, _mm_add_epi32(s2, _mm_loadu_si128(K32.add(8) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(12) as _, _mm_add_epi32(s3, _mm_loadu_si128(K32.add(12) as _)));
            macro_rules! compiler_barrier {
                () => {
                    // std::hint::black_box(w_add_k.as_mut_ptr());
                    core::arch::asm!("/* {0} */", in(reg) w_add_k.as_mut_ptr(), options(nostack, preserves_flags));
                }
            }

            // use merge_bits;
    
            #[allow(non_snake_case)]
            #[inline(always)]
            fn CH(x: u32, y: u32, z: u32) -> u32 {
                crate::utils::merge_bits(z, y, x)
                // (x & y) ^ (!x & z)
                // ((y ^ z) & x) ^ z
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

            macro_rules! _mm_srri_epi32 {
                ($v:expr, $r:expr) => {{
                    _mm_xor_si128(
                        _mm_srli_epi32($v, $r),
                        _mm_slli_epi32($v, 32 - $r)
                    )
                }};
            }

            macro_rules! update2 {
                ($s0:ident,$s1:ident,$s2:ident,$s3:ident) => {
                    let t0 = _mm_alignr_epi8($s1, $s0, 4);
                    let t3 = _mm_alignr_epi8($s3, $s2, 4);

                    let sigma0 = _mm_xor_si128(
                        _mm_srri_epi32!(t0, 7),
                        _mm_xor_si128(
                            _mm_srri_epi32!(t0, 18),
                            _mm_srli_epi32(t0, 3),
                        )
                    );
                    let s14_s15 = _mm_srli_si128($s3, 8);
                    let sigma1_0 = _mm_xor_si128(
                        _mm_srri_epi32!(s14_s15, 17),
                        _mm_xor_si128(
                            _mm_srri_epi32!(s14_s15, 19),
                            _mm_srli_epi32(s14_s15, 10),
                        )
                    );

                    let tmp = _mm_add_epi32(
                        _mm_add_epi32($s0, sigma0),
                        _mm_add_epi32(t3, sigma1_0),
                    );
                    let sigma1_1 = _mm_xor_si128(
                        _mm_srri_epi32!(tmp, 17),
                        _mm_xor_si128(
                            _mm_srri_epi32!(tmp, 19),
                            _mm_srli_epi32(tmp, 10),
                        )
                    );
                    $s0 = _mm_add_epi32(tmp, _mm_slli_si128(sigma1_1, 8));
                };
            }

            let mut msg0 = s0;
            let mut msg1 = s1;
            let mut msg2 = s2;
            let mut msg3 = s3;
    
            compiler_barrier!();
            crate::const_loop!(j, 1, 3, {
                sha256_round!(0);
                update2!(msg0, msg1, msg2, msg3);
                sha256_round!(1);
                sha256_round!(2);
                sha256_round!(3);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(0) as _, _mm_add_epi32(msg0, _mm_loadu_si128(K32.add(16 * j + 0) as _)));

                sha256_round!(4);
                update2!(msg1, msg2, msg3, msg0);
                sha256_round!(5);
                sha256_round!(6);
                sha256_round!(7);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(4) as _, _mm_add_epi32(msg1, _mm_loadu_si128(K32.add(16 * j + 4) as _)));


                sha256_round!(8);
                update2!(msg2, msg3, msg0, msg1);
                sha256_round!(9);
                sha256_round!(10);
                sha256_round!(11);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(8) as _, _mm_add_epi32(msg2, _mm_loadu_si128(K32.add(16 * j + 8) as _)));

                sha256_round!(12);
                update2!(msg3, msg0, msg1, msg2);
                sha256_round!(13);
                sha256_round!(14);
                sha256_round!(15);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(12) as _, _mm_add_epi32(msg3, _mm_loadu_si128(K32.add(16 * j + 12) as _)));
            
                // std::hint::black_box(w_add_k.as_mut_ptr());
                compiler_barrier!();
            });
    
            crate::const_loop!(i, 0, 16, {
                sha256_round!(i);
            });
    
            state[0] = crate::utils::black_box(state[0].wrapping_add(a));
            state[1] = crate::utils::black_box(state[1].wrapping_add(b));
            state[2] = crate::utils::black_box(state[2].wrapping_add(c));
            state[3] = crate::utils::black_box(state[3].wrapping_add(d));
            state[4] = crate::utils::black_box(state[4].wrapping_add(e));
            state[5] = crate::utils::black_box(state[5].wrapping_add(f));
            state[6] = crate::utils::black_box(state[6].wrapping_add(g));
            state[7] = crate::utils::black_box(state[7].wrapping_add(h));

            $state = state;
        }
    };
}

}

pub(crate) use process_block_with;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        if !std::arch::is_x86_feature_detected!("ssse3") {
            return;
        }
        sha256_test_case!();
    }
}