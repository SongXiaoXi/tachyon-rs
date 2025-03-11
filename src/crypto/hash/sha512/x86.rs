#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
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

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 128],
            offset: 0,
        }
    }

}

#[unsafe_target_feature("sse2,ssse3")]
impl Sha512 {
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;

        if self.offset > 0 {
            while i < data.len() {
                if self.offset < Self::BLOCK_LEN {
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
            process_block_with!(self.state, unsafe { crate::utils::slice_to_array_at::<_, 128>(data, i) });
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
        debug_assert!(plen > 1);
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
    
            let mut s0 = _mm_loadu_si128(block.as_ptr().add(0 * 16) as *const __m128i);
            let mut s1 = _mm_loadu_si128(block.as_ptr().add(1 * 16) as *const __m128i);
            let mut s2 = _mm_loadu_si128(block.as_ptr().add(2 * 16) as *const __m128i);
            let mut s3 = _mm_loadu_si128(block.as_ptr().add(3 * 16) as *const __m128i);
            let mut s4 = _mm_loadu_si128(block.as_ptr().add(4 * 16) as *const __m128i);
            let mut s5 = _mm_loadu_si128(block.as_ptr().add(5 * 16) as *const __m128i);
            let mut s6 = _mm_loadu_si128(block.as_ptr().add(6 * 16) as *const __m128i);
            let mut s7 = _mm_loadu_si128(block.as_ptr().add(7 * 16) as *const __m128i);
    
            // little-endian to big-endian
            let mask = _mm_set_epi64x(
                0x08090a0b0c0d0e0f,
                0x0001020304050607,
            );
            s0 = _mm_shuffle_epi8(s0, mask);
            s1 = _mm_shuffle_epi8(s1, mask);
            s2 = _mm_shuffle_epi8(s2, mask);
            s3 = _mm_shuffle_epi8(s3, mask);
            s4 = _mm_shuffle_epi8(s4, mask);
            s5 = _mm_shuffle_epi8(s5, mask);
            s6 = _mm_shuffle_epi8(s6, mask);
            s7 = _mm_shuffle_epi8(s7, mask);
    
            static _K: [u64; 80] = super::K;
            #[allow(non_snake_case)]
            let mut K = _K.as_ptr();
            // Magic: black_box is used to prevent the compiler from using load immediate instructions
            std::hint::black_box(&mut K);

            let mut w_add_k = [0u64; 16];
    
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(0) as _, _mm_add_epi64(s0, _mm_loadu_si128(K.add(0) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(2) as _, _mm_add_epi64(s1, _mm_loadu_si128(K.add(2) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(4) as _, _mm_add_epi64(s2, _mm_loadu_si128(K.add(4) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(6) as _, _mm_add_epi64(s3, _mm_loadu_si128(K.add(6) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(8) as _, _mm_add_epi64(s4, _mm_loadu_si128(K.add(8) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(10) as _, _mm_add_epi64(s5, _mm_loadu_si128(K.add(10) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(12) as _, _mm_add_epi64(s6, _mm_loadu_si128(K.add(12) as _)));
            _mm_storeu_si128(w_add_k.as_mut_ptr().add(14) as _, _mm_add_epi64(s7, _mm_loadu_si128(K.add(14) as _)));
    
            macro_rules! sha512_round {
                ($i:expr) => {
                    let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                    let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                    let maj = (a & b) ^ (a & c) ^ (b & c);
                    let ch = (e & f) ^ ((!e) & g);
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
            #[allow(non_upper_case_globals)]
            const sigma0: [i32; 3] = [1, 8, 7];
            #[allow(non_upper_case_globals)]
            const sigma1: [i32; 3] = [19, 61, 6];

            macro_rules! update {
                ($s0:ident,$s1:ident,$s2:ident,$s3:ident,$s4:ident,$s5:ident,$s6:ident,$s7:ident) => {
                    let mut t0 = _mm_alignr_epi8($s1, $s0, 8); // X[1..2]
                    let mut t3 = _mm_alignr_epi8($s5, $s4, 8); // X[9..10]
                    let mut t2 = _mm_srli_epi64(t0, sigma0[0]);
                    $s0 = _mm_add_epi64($s0, t3); // X[0..1] += X[9..10]
                    t3 = _mm_srli_epi64(t0, sigma0[2]);
                    let mut t1 = _mm_slli_epi64(t0, 64 - sigma0[1]);
                    t0 = _mm_xor_si128(t2, t3);
                    t2 = _mm_srli_epi64(t2, sigma0[1] - sigma0[0]);
                    t0 = _mm_xor_si128(t0, t1);
                    t1 = _mm_slli_epi64(t1, sigma0[1] - sigma0[0]);
                    t0 = _mm_xor_si128(t0, t2);
                    t3 = _mm_srli_epi64($s7, sigma1[2]);
                    t0 = _mm_xor_si128(t0, t1); // sigma0(X[1..2])
                    t2 = _mm_slli_epi64($s7, 64 - sigma1[1]);
                    $s0 = _mm_add_epi64($s0, t0); // X[0..1] += sigma0(X[1..2])
                    t1 = _mm_srli_epi64($s7, sigma1[0]);
                    t3 = _mm_xor_si128(t3, t2);
                    t2 = _mm_slli_epi64(t2, sigma1[1] - sigma1[0]);
                    t3 = _mm_xor_si128(t3, t1);
                    t1 = _mm_srli_epi64(t1, sigma1[1] - sigma1[0]);
                    t3 = _mm_xor_si128(t3, t2);
                    t3 = _mm_xor_si128(t3, t1); // sigma1(X[14..15])
                    $s0 = _mm_add_epi64($s0, t3); // X[0..1] += sigma1(X[14..15])
                };
            }
    
            crate::const_loop!(j, 1, 4, {
                
                sha512_round!(0);
                sha512_round!(1);
                update!(s0, s1, s2, s3, s4, s5, s6, s7);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(0) as _, _mm_add_epi64(s0, _mm_loadu_si128(K.add(j * 16 + 0) as _)));

                sha512_round!(2);
                sha512_round!(3);
                update!(s1, s2, s3, s4, s5, s6, s7, s0);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(2) as _, _mm_add_epi64(s1, _mm_loadu_si128(K.add(j * 16 + 2) as _)));

                sha512_round!(4);
                sha512_round!(5);
                update!(s2, s3, s4, s5, s6, s7, s0, s1);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(4) as _, _mm_add_epi64(s2, _mm_loadu_si128(K.add(j * 16 + 4) as _)));

                sha512_round!(6);
                sha512_round!(7);
                update!(s3, s4, s5, s6, s7, s0, s1, s2);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(6) as _, _mm_add_epi64(s3, _mm_loadu_si128(K.add(j * 16 + 6) as _)));

                sha512_round!(8);
                sha512_round!(9);
                update!(s4, s5, s6, s7, s0, s1, s2, s3);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(8) as _, _mm_add_epi64(s4, _mm_loadu_si128(K.add(j * 16 + 8) as _)));

                sha512_round!(10);
                sha512_round!(11);
                update!(s5, s6, s7, s0, s1, s2, s3, s4);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(10) as _, _mm_add_epi64(s5, _mm_loadu_si128(K.add(j * 16 + 10) as _)));

                sha512_round!(12);
                sha512_round!(13);
                update!(s6, s7, s0, s1, s2, s3, s4, s5);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(12) as _, _mm_add_epi64(s6, _mm_loadu_si128(K.add(j * 16 + 12) as _)));

                sha512_round!(14);
                sha512_round!(15);
                update!(s7, s0, s1, s2, s3, s4, s5, s6);
                _mm_storeu_si128(w_add_k.as_mut_ptr().add(14) as _, _mm_add_epi64(s7, _mm_loadu_si128(K.add(j * 16 + 14) as _)));
                // Magic: black_box is used to prevent the compiler from generating bad re-ordering instructions.
                // For example, the compiler may generate all SSE/AVX instructions first and save all w_add_k values to the stack.
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
    };
}

}

pub(crate) use process_block_with;

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_sha512() {
        if std::arch::is_x86_feature_detected!("sse2") && std::arch::is_x86_feature_detected!("ssse3") {
            sha512_test_case!();
        }
    }
}