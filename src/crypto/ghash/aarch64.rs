#![allow(non_camel_case_types)]
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use core::mem::transmute;
use unsafe_target_feature::unsafe_target_feature;

#[inline(always)]
unsafe fn vmull_low(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let t1: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(a)));
    let t2: poly64x1_t = vget_low_p64(vreinterpretq_p64_u64(vreinterpretq_u64_u8(b)));

    let r = vmull_p64(transmute(t1), transmute(t2));

    return vreinterpretq_u8_p128(r);
}

#[inline(always)]
unsafe fn vmull_high(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let t1: poly64x2_t = vreinterpretq_p64_u64(vreinterpretq_u64_u8(a));
    let t2: poly64x2_t = vreinterpretq_p64_u64(vreinterpretq_u64_u8(b));

    let r = vmull_high_p64(t1, t2);

    return vreinterpretq_u8_p128(r);
}

#[unsafe_target_feature("aes")]
#[inline]
unsafe fn gf_mul_without_modular(a: uint8x16_t, b: uint8x16_t) -> (uint8x16_t, uint8x16_t, uint8x16_t) {
    let a_p = a;
    let b_p = b;

    let r0 = vmull_low(a_p, b_p);
    let r1 = vmull_high(a_p, b_p);
    let mut t0 = vextq_u8(b_p, b_p, 8);
    let t1 = vmull_low(a_p, t0);
    t0 = vmull_high(a_p, t0);
    t0 = veorq_u8(t0, t1);

    return (r0, t0, r1);
}

#[unsafe_target_feature("aes")]
#[inline]
unsafe fn gf_mul_modular(a: (uint8x16_t, uint8x16_t, uint8x16_t)) -> uint8x16_t {
    let mut r0 = a.0;
    let t0 = a.1;
    let mut r1 = a.2;
    let z = vdupq_n_u8(0);
    let mut t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);

    let p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087));
    let z = vdupq_n_u8(0);

    let mut t0 = vmull_high(r1, p);
    let t1 = vextq_u8(t0, z, 8);
    let r1 = veorq_u8(r1, t1);
    let t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);

    t0 = vmull_low(r1, p);
    veorq_u8(r0, t0)
}

#[unsafe_target_feature("aes")]
#[inline]
fn gf_mul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe {
        let r0 = gf_mul_without_modular(a, b);
        let r0 = gf_mul_modular(r0);
        return r0;
    }
}

// Perform the multiplication and reduction in GF(2^128)
#[unsafe_target_feature("aes")]
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
}

#[unsafe_target_feature::unsafe_target_feature("aes")]
impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;

    #[inline(always)]
    pub fn new(h: &[u8; 16]) -> Self {
        unsafe {
            let key: uint8x16_t = vrbitq_u8(vld1q_u8(h.as_ptr()));
            let key2 = gf_mul(key, key);
            let key3 = gf_mul(key2, key);
            let key4 = gf_mul(key2, key2);

            Self {
                key,
                tag: vdupq_n_u8(0),
                key2,
                key3,
                key4,
            }
        }
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        let mut mlen = m.len();

        let mut start = 0;
        while mlen >= Self::BLOCK_LEN {
            unsafe {
                let block = std::ptr::read_unaligned(&m[start] as *const u8 as *const uint8x16_t);
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
            std::hint::black_box(last_block.as_mut_ptr());
            last_block[..rlen].copy_from_slice(rem);

            unsafe {
                gf_mul_to_tag(self.key, vld1q_u8(last_block.as_ptr()), &mut self.tag);
            }
        }
    }
    
    #[inline(always)]
    pub(crate) fn update_4block_for_aes(&mut self, m0: &[u8; 16], m1: &[u8; 16], m2: &[u8; 16], m3: &[u8; 16]) {
        unsafe {
            let block0 = vld1q_u8(m0.as_ptr());
            let block1 = vld1q_u8(m1.as_ptr());
            let block2 = vld1q_u8(m2.as_ptr());
            let block3 = vld1q_u8(m3.as_ptr());

            let block0 = vrbitq_u8(block0);
            let block1 = vrbitq_u8(block1);
            let block2 = vrbitq_u8(block2);
            let block3 = vrbitq_u8(block3);
            
            let block0 = veorq_u8(block0, self.tag);
            let ret0 = gf_mul_without_modular(self.key4, block0);
            let ret1 = gf_mul_without_modular(self.key3, block1);
            let ret2 = gf_mul_without_modular(self.key2, block2);
            let ret3 = gf_mul_without_modular(self.key, block3);

            let ret_0 = veorq_u8(veorq_u8(veorq_u8(ret0.0, ret1.0), ret2.0), ret3.0);
            let ret_1 = veorq_u8(veorq_u8(veorq_u8(ret0.1, ret1.1), ret2.1), ret3.1);
            let ret_2 = veorq_u8(veorq_u8(veorq_u8(ret0.2, ret1.2), ret2.2), ret3.2);

            self.tag = gf_mul_modular((ret_0, ret_1, ret_2));
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
    
}