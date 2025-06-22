#![allow(non_camel_case_types)]
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use core::mem::transmute;

#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn vmull_low(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let t1 = vget_low_p64(vreinterpretq_p64_u8(a));
    let t2 = vget_low_p64(vreinterpretq_p64_u8(b));

    let r = vmull_p64(transmute(t1), transmute(t2));

    return vreinterpretq_u8_p128(r);
}

#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn vmull_high(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let t1: poly64x2_t = vreinterpretq_p64_u8(a);
    let t2: poly64x2_t = vreinterpretq_p64_u8(b);

    let r = vmull_high_p64(t1, t2);

    return vreinterpretq_u8_p128(r);
}

#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn gf_mul_no_reduce_pre_k(a: uint8x16_t, b: uint8x16_t, a_k: uint8x8_t) -> (uint8x16_t, uint8x16_t, uint8x16_t) {
    let a_p = a;
    let b_p = b;

    let r0 = vmull_low(a_p, b_p);
    let r1 = vmull_high(a_p, b_p);
    let t1 = vreinterpretq_u8_p128(vmull_p64(transmute(a_k), transmute(veor_u8(vget_low_u8(b_p), vget_high_u8(b_p)))));
    return (r0, t1, r1);
}

#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn gf_mul_reduce_pre_k(a: (uint8x16_t, uint8x16_t, uint8x16_t)) -> uint8x16_t {
    let mut r0 = a.0;
    let mut t1 = a.1;
    let r1 = a.2;

    let p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087));
    let mut t0 = veorq_u8(r0, r1); 
    t0 = veorq_u8(t0, t1);
    
    let t2 = vmull_high(r1, p);

    cfg_if::cfg_if! {
        if #[cfg(target_vendor = "apple")] {
            // Apple has magic optimizations
            let z = vdupq_n_u8(0);
            let mut r1 = veorq_u8(r1, vextq_u8(t0, z, 8));
            r1 = veorq_u8(r1, vextq_u8(t2, z, 8));
            let t3 = vmull_low(r1, p);

            t1 = vextq_u8(z, t0, 8);
            r0 = veorq_u8(r0, t1);
            t1 = vextq_u8(z, t2, 8);
            r0 = veorq_u8(r0, t1);
        } else {
            t1 = vextq_u8(t0, t0, 8);
            let mut r1 = vget_low_u8(veorq_u8(r1, t1));
            r1 = veor_u8(r1, vget_high_u8(t2));
            let t3 = vreinterpretq_u8_p128(vmull_p64(transmute(r1), transmute(vget_low_u8(p))));

            r0 = veorq_u8(r0, t1);
            t1 = vextq_u8(t0, t2, 8);
            r0 = veorq_u8(r0, t1);
        }
    }

    veorq_u8(r0, t3)
}

#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn gf_mul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let r0 = gf_mul_no_reduce_pre_k(a, b, veor_u8(vget_low_u8(a), vget_high_u8(a)));
    gf_mul_reduce_pre_k(r0)
}

// Perform the multiplication and reduction in GF(2^128)
#[target_feature(enable = "neon", enable = "aes")]
#[inline]
unsafe fn gf_mul_to_tag(key: uint8x16_t, m: uint8x16_t, tag: &mut uint8x16_t) {
    let m = vrbitq_u8(m);

    let a_p = key;
    let b_p = veorq_u8(m, *tag);

    let res = gf_mul(a_p, b_p);
    *tag = res;
}

#[derive(Clone, Copy)]
pub struct GHash {
    key: uint8x16_t,
    tag: uint8x16_t,
    key2: uint8x16_t,
    key3: uint8x16_t,
    key4: uint8x16_t,
    #[cfg(ghash_block_x6)]
    key5: uint8x16_t,
    #[cfg(ghash_block_x6)]
    key6: uint8x16_t,
    key_k: uint8x8_t,
    key_k2: uint8x8_t,
    key_k3: uint8x8_t,
    key_k4: uint8x8_t,
    #[cfg(ghash_block_x6)]
    key_k5: uint8x8_t,
    #[cfg(ghash_block_x6)]
    key_k6: uint8x8_t,
}

#[unsafe_target_feature::unsafe_target_feature("neon,aes")]
impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;

    #[inline(always)]
    pub fn new(h: &[u8; 16]) -> Self {
        unsafe {
            let key: uint8x16_t = vrbitq_u8(vld1q_u8(h.as_ptr()));
            let key2 = gf_mul(key, key);
            let key3 = gf_mul(key2, key);
            let key4 = gf_mul(key2, key2);
            #[cfg(ghash_block_x6)]
            let key5 = gf_mul(key3, key2);
            #[cfg(ghash_block_x6)]
            let key6 = gf_mul(key3, key3);

            let key_k = veor_u8(vget_low_u8(key), vget_high_u8(key));
            let key_k2 = veor_u8(vget_low_u8(key2), vget_high_u8(key2));
            let key_k3 = veor_u8(vget_low_u8(key3), vget_high_u8(key3));
            let key_k4 = veor_u8(vget_low_u8(key4), vget_high_u8(key4));
            #[cfg(ghash_block_x6)]
            let key_k5 = veor_u8(vget_low_u8(key5), vget_high_u8(key5));
            #[cfg(ghash_block_x6)]
            let key_k6 = veor_u8(vget_low_u8(key6), vget_high_u8(key6));

            Self {
                key,
                tag: vdupq_n_u8(0),
                key2,
                key3,
                key4,
                #[cfg(ghash_block_x6)]
                key5,
                #[cfg(ghash_block_x6)]
                key6,
                key_k,
                key_k2,
                key_k3,
                key_k4,
                #[cfg(ghash_block_x6)]
                key_k5,
                #[cfg(ghash_block_x6)]
                key_k6,
            }
        }
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        let mut mlen = m.len();

        let mut start = 0;
        while mlen >= Self::BLOCK_LEN {
            unsafe {
                let block = vld1q_u8(m.as_ptr().add(start));
                gf_mul_to_tag(self.key, block, &mut self.tag);
            }
            mlen -= Self::BLOCK_LEN;
            start += Self::BLOCK_LEN;
        }

        if mlen != 0 {
            let rem = &m[start..];
            let rlen = rem.len();

            let mut last_block = [0u8; Self::BLOCK_LEN];
            // Magic: black_box is used to prevent the compiler from using bzero
            core::hint::black_box(last_block.as_mut_ptr());
            unsafe {
                crate::utils::assume(rlen <= Self::BLOCK_LEN);

                crate::utils::copy_chunks_u8(
                    last_block.as_mut_ptr(),
                    rem.as_ptr(),
                    rlen,
                );
            }
            // last_block[..rlen].copy_from_slice(rem);

            unsafe {
                gf_mul_to_tag(self.key, vld1q_u8(last_block.as_ptr()), &mut self.tag);
            }
        }
    }
    
    #[inline(always)]
    pub(crate) fn update_4block_for_aes(&mut self, m: [&[u8; 16]; 4]) {
        unsafe {
            let block0 = vld1q_u8(m[0].as_ptr());
            let block1 = vld1q_u8(m[1].as_ptr());
            let block2 = vld1q_u8(m[2].as_ptr());
            let block3 = vld1q_u8(m[3].as_ptr());

            let block0 = vrbitq_u8(block0);
            let block1 = vrbitq_u8(block1);
            let block2 = vrbitq_u8(block2);
            let block3 = vrbitq_u8(block3);
            
            let block0 = veorq_u8(block0, self.tag);
            let ret0 = gf_mul_no_reduce_pre_k(self.key4, block0, self.key_k4);
            let ret1 = gf_mul_no_reduce_pre_k(self.key3, block1, self.key_k3);
            let ret2 = gf_mul_no_reduce_pre_k(self.key2, block2, self.key_k2);
            let ret3 = gf_mul_no_reduce_pre_k(self.key, block3, self.key_k);

            let ret_0 = veorq_u8(veorq_u8(ret0.0, ret1.0), veorq_u8(ret2.0, ret3.0));
            let ret_1 = veorq_u8(veorq_u8(ret0.1, ret1.1), veorq_u8(ret2.1, ret3.1));
            let ret_2 = veorq_u8(veorq_u8(ret0.2, ret1.2), veorq_u8(ret2.2, ret3.2));

            self.tag = gf_mul_reduce_pre_k((ret_0, ret_1, ret_2));
        }
    }

    #[cfg(ghash_block_x6)]
    #[inline(always)]
    pub(crate) fn update_6block_for_aes(&mut self, m:[&[u8; 16]; 6]) {
        unsafe {
            let block0 = vld1q_u8(m[0].as_ptr());
            let block1 = vld1q_u8(m[1].as_ptr());
            let block2 = vld1q_u8(m[2].as_ptr());
            let block3 = vld1q_u8(m[3].as_ptr());
            let block4 = vld1q_u8(m[4].as_ptr());
            let block5 = vld1q_u8(m[5].as_ptr());

            let block0 = vrbitq_u8(block0);
            let block1 = vrbitq_u8(block1);
            let block2 = vrbitq_u8(block2);
            let block3 = vrbitq_u8(block3);
            let block4 = vrbitq_u8(block4);
            let block5 = vrbitq_u8(block5);

            let block0 = veorq_u8(block0, self.tag);
            let ret0 = gf_mul_no_reduce_pre_k(self.key6, block0, self.key_k6);
            let ret1 = gf_mul_no_reduce_pre_k(self.key5, block1, self.key_k5);
            let ret2 = gf_mul_no_reduce_pre_k(self.key4, block2, self.key_k4);
            let ret3 = gf_mul_no_reduce_pre_k(self.key3, block3, self.key_k3);
            let ret4 = gf_mul_no_reduce_pre_k(self.key2, block4, self.key_k2);
            let ret5 = gf_mul_no_reduce_pre_k(self.key,  block5, self.key_k);

            let ret_0 = veorq_u8(veorq_u8(ret0.0, ret1.0), veorq_u8(veorq_u8(ret2.0, ret3.0), veorq_u8(ret4.0, ret5.0)));
            let ret_1 = veorq_u8(veorq_u8(ret0.1, ret1.1), veorq_u8(veorq_u8(ret2.1, ret3.1), veorq_u8(ret4.1, ret5.1)));
            let ret_2 = veorq_u8(veorq_u8(ret0.2, ret1.2), veorq_u8(veorq_u8(ret2.2, ret3.2), veorq_u8(ret4.2, ret5.2)));

            self.tag = gf_mul_reduce_pre_k((ret_0, ret_1, ret_2));
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; 16] {
        unsafe {
            let mut tag = [0u8; Self::TAG_LEN];
            vst1q_u8(tag.as_mut_ptr(), vrbitq_u8(self.tag));
            tag
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ghash() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return;
        }
        ghash_test_case!();
    }

    #[test]
    fn test_neon_clmul() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return;
        }

        let a = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6];
        let b = [0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        unsafe {
            use std::mem::transmute;
            let a = vld1_u8(a.as_ptr());
            let b = vld1_u8(b.as_ptr());
            let result = super::super::arm::clmul!(a, b);
            let expected = vreinterpretq_u8_p128(vmull_p64(transmute(a), transmute(b)));
            let mut result_arr = [0u8; 16];
            vst1q_u8(result_arr.as_mut_ptr(), result);
            let mut expected_arr = [0u8; 16];
            vst1q_u8(expected_arr.as_mut_ptr(), expected);
            assert_eq!(result_arr, expected_arr);
        }
    }
}
