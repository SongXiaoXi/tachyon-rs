#[cfg(target_arch = "arm")]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use unsafe_target_feature::unsafe_target_feature;

#[macro_use]
mod macros {

macro_rules! clmul {
    ($a:expr, $b:expr) => {{
        {
            let a = $a;
            let b = $b;
            #[inline(always)]
            unsafe fn pmull_u8(a: uint8x8_t, b: uint8x8_t) -> uint8x16_t {
                vreinterpretq_u8_p16(vmull_p8(vreinterpret_p8_u8(a), vreinterpret_p8_u8(b)))
            }
            let mask48 = vreinterpret_u8_u64(vdup_n_u64(0x0000ffffffffffff));
            let mask32 = vreinterpret_u8_u64(vdup_n_u64(0x00000000ffffffff));
            let mask16 = vreinterpret_u8_u64(vdup_n_u64(0x000000000000ffff));
            let z = vdup_n_u64(0);

            let t0 = pmull_u8(b, vext_u8(a, a, 1));
            let t2 = pmull_u8(a, vext_u8(b, b, 1));
            let t1 = pmull_u8(b, vext_u8(a, a, 2));
            let t3 = pmull_u8(a, vext_u8(b, b, 2));

            let t0 = veorq_u8(t0, t2);
            let t2 = pmull_u8(b, vext_u8(a, a, 3));
            let t1 = veorq_u8(t1, t3);
            let t3 = pmull_u8(a, vext_u8(b, b, 3));
            let t2 = veorq_u8(t2, t3);
            let t3 = pmull_u8(a, vext_u8(b, b, 4));

            let t0_hi = vand_u8(vget_high_u8(t0), mask48);
            let t0_lo = veor_u8(veor_u8(vget_low_u8(t0), vget_high_u8(t0)), t0_hi);
            let t1_hi = vand_u8(vget_high_u8(t1), mask32);
            let t1_lo = veor_u8(veor_u8(vget_low_u8(t1), vget_high_u8(t1)), t1_hi);
            let t2_hi = vand_u8(vget_high_u8(t2), mask16);
            let t2_lo = veor_u8(veor_u8(vget_low_u8(t2), vget_high_u8(t2)), t2_hi);

            let t0 = vcombine_u8(t0_lo, t0_hi);
            let t0 = vextq_u8(t0, t0, 15);
            let t3_lo = veor_u8(vget_low_u8(t3), vget_high_u8(t3));
            // Magic: use vcombine_u64 to let the compiler know that we want to use 64-bit
            let t3 = vreinterpretq_u8_u64(vcombine_u64(vreinterpret_u64_u8(t3_lo), z));

            let t1 = vcombine_u8(t1_lo, t1_hi);
            let t1 = vextq_u8(t1, t1, 14);
            let r = pmull_u8(a, b);

            let t2 = vcombine_u8(t2_lo, t2_hi);
            let t3 = vextq_u8(t3, t3, 12);
            let t2 = vextq_u8(t2, t2, 13);
            let t0 = veorq_u8(t0, t1);
            let t2 = veorq_u8(t2, t3);
            let r = veorq_u8(r, t0);
            let r = veorq_u8(r, t2);
            r
        }
    }};
}

}

#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v7,neon"))]
#[inline]
unsafe fn gf_mul_prepare_k(key: uint8x16_t) -> uint8x16_t {
    let t0 = vdup_n_u8(0xe1);
    let t0_hi = vshl_n_u64(vreinterpret_u64_u8(t0), 57);
    let t0_lo = vshr_n_u64(vreinterpret_u64_u8(t0), 63);
    let t0 = vcombine_u8(vreinterpret_u8_u64(t0_lo), vreinterpret_u8_u64(t0_hi));
    let t1 = vdupq_laneq_u8(key, 15);
    let t2 = vshr_n_u64(vreinterpret_u64_u8(vget_low_u8(key)), 63);
    let t1 = vreinterpretq_u8_s8(vshrq_n_s8(vreinterpretq_s8_u8(t1), 7));
    let r = vreinterpretq_u8_u64(vshlq_n_u64(vreinterpretq_u64_u8(key), 1));
    let t0 = vandq_u8(t0, t1);
    let r = vorrq_u8(r, vreinterpretq_u8_u64(vcombine_u64(vdup_n_u64(0), t2)));
    let r = veorq_u8(r, t0);
    r
}

#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v7,neon"))]
#[inline]
unsafe fn gf_mul_no_reduce(a: uint8x16_t, b: uint8x16_t, a_k: uint8x8_t) -> (uint8x16_t, uint8x16_t, uint8x16_t) {
    let a_p = a;
    let b_p = b;

    let r0 = clmul!(vget_low_u8(a_p), vget_low_u8(b_p));
    let r1 = clmul!(vget_high_u8(a_p), vget_high_u8(b_p));
    let t1 = clmul!(a_k, veor_u8(vget_low_u8(b_p), vget_high_u8(b_p)));
    return (r0, t1, r1);
}

#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v7,neon"))]
#[inline]
unsafe fn gf_mul_reduce(a: (uint8x16_t, uint8x16_t, uint8x16_t)) -> uint8x16_t {
    // reduction like SSE version
    let mut r0 = a.0;
    let mut r1 = a.1;
    let mut r2 = a.2;

    r1 = veorq_u8(r0, r1);
    r1 = veorq_u8(r1, r2);

    let z = vdupq_n_u8(0);
    r0 = veorq_u8(r0, vext_qword(z, r1));

    let mut tmp: uint8x16_t = vshl64q_n_u8::<62>(r0);
    tmp = veorq_u8(tmp, vshl64q_n_u8::<57>(r0));
    tmp = veorq_u8(tmp, vshl64q_n_u8::<63>(r0));
    r0 = veorq_u8(r0, vext_qword(z, tmp));
    r2 = veorq_u8(r2, vext_qword(veorq_u8(tmp, r1), z));

    tmp = vshr64q_n_u8::<1>(r0);
    r2 = veorq_u8(r2, r0);
    r0 = veorq_u8(r0, tmp);
    tmp = vshr64q_n_u8::<6>(tmp);
    r0 = vshr64q_n_u8::<1>(r0);
    r0 = veorq_u8(r0, r2);
    r0 = veorq_u8(r0, tmp);

    r0
}


#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v7,neon"))]
#[inline]
unsafe fn gf_mul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    gf_mul_reduce(gf_mul_no_reduce(a, b, veor_u8(vget_low_u8(a), vget_high_u8(a))))
}

#[inline(always)]
unsafe fn vshr64q_n_u8<const N: i32>(a: uint8x16_t) -> uint8x16_t {
    vreinterpretq_u8_u64(vshrq_n_u64(vreinterpretq_u64_u8(a), N))
}

#[inline(always)]
unsafe fn vshl64q_n_u8<const N: i32>(a: uint8x16_t) -> uint8x16_t {
    vreinterpretq_u8_u64(vshlq_n_u64(vreinterpretq_u64_u8(a), N))
}

#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v7,neon"))]
#[inline]
unsafe fn vext_qword(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    cfg_if::cfg_if!{
        if #[cfg(target_arch = "arm")] {
            vreinterpretq_u8_u64(vcombine_u64(vreinterpret_u64_u8(vget_high_u8(a)), vreinterpret_u64_u8(vget_low_u8(b))))
        } else {
            vextq_u8(a, b, 8)
        }
    }
}


#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v7,neon"))]
#[inline]
unsafe fn bswap_128(a: uint8x16_t) -> uint8x16_t {
    cfg_if::cfg_if!{
        if #[cfg(target_arch = "arm")] {
            let a = vcombine_u8(vget_high_u8(a), vget_low_u8(a));
            // Magic: prevent the compiler from optimizing vrev64q_u8 and vextq_u8 to tbl
            // std::hint::black_box() may not be inlined on armv7
            crate::utils::black_box(vrev64q_u8(a))
        } else {
            vrev64q_u8(vextq_u8(a, a, 8))
        }
    }
}

pub(crate) use clmul;

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

#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v7,neon"))]
impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;

    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
        let key = vld1q_u8(key.as_ptr());

        let key = bswap_128(key);

        let key_orig = key;

        let key = gf_mul_prepare_k(key);

        let key2 = gf_mul(key, key_orig);
        let key3 = gf_mul(key, key2);
        let key4 = gf_mul(key, key3);
        #[cfg(ghash_block_x6)]
        let key5 = gf_mul(key, key4);
        #[cfg(ghash_block_x6)]
        let key6 = gf_mul(key, key5);

        let key2 = gf_mul_prepare_k(key2);
        let key3 = gf_mul_prepare_k(key3);
        let key4 = gf_mul_prepare_k(key4);
        #[cfg(ghash_block_x6)]
        let key5 = gf_mul_prepare_k(key5);
        #[cfg(ghash_block_x6)]
        let key6 = gf_mul_prepare_k(key6);

        let key_k = veor_u8(vget_low_u8(key), vget_high_u8(key));
        let key_k2 = veor_u8(vget_low_u8(key2), vget_high_u8(key2));
        let key_k3 = veor_u8(vget_low_u8(key3), vget_high_u8(key3));
        let key_k4 = veor_u8(vget_low_u8(key4), vget_high_u8(key4));
        #[cfg(ghash_block_x6)]
        let key_k5 = veor_u8(vget_low_u8(key5), vget_high_u8(key5));
        #[cfg(ghash_block_x6)]
        let key_k6 = veor_u8(vget_low_u8(key6), vget_high_u8(key6));

        Self {
            tag: vdupq_n_u8(0),
            key,
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

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        let mut mlen = m.len();

        let mut start = 0;
        while mlen >= Self::BLOCK_LEN {
            unsafe {
                let mut block = vld1q_u8(m.get_unchecked(start) as *const u8);
                block = bswap_128(block);
                block = veorq_u8(block, self.tag);
                self.tag = gf_mul(self.key, block);
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
            last_block[..rlen].copy_from_slice(rem);

            unsafe {
                let mut block = vld1q_u8(last_block.as_ptr());
                block = bswap_128(block);
                block = veorq_u8(block, self.tag);
                self.tag = gf_mul(self.key, block);
            }
        }
    }

    #[inline(always)]
    pub(crate) fn update_4block_for_aes(&mut self, m: [&[u8; 16]; 4]) {
        let m0 = bswap_128(vld1q_u8(m[0].as_ptr()));
        let m1 = bswap_128(vld1q_u8(m[1].as_ptr()));
        let m2 = bswap_128(vld1q_u8(m[2].as_ptr()));
        let m3 = bswap_128(vld1q_u8(m[3].as_ptr()));

        let m0 = veorq_u8(m0, self.tag);
        let ret0 = gf_mul_no_reduce(self.key4, m0, self.key_k4);
        let ret1 = gf_mul_no_reduce(self.key3, m1, self.key_k3);
        let ret2 = gf_mul_no_reduce(self.key2, m2, self.key_k2);
        let ret3 = gf_mul_no_reduce(self.key, m3, self.key_k);

        let ret_0 = veorq_u8(veorq_u8(veorq_u8(ret0.0, ret1.0), ret2.0), ret3.0);
        let ret_1 = veorq_u8(veorq_u8(veorq_u8(ret0.1, ret1.1), ret2.1), ret3.1);
        let ret_2 = veorq_u8(veorq_u8(veorq_u8(ret0.2, ret1.2), ret2.2), ret3.2);

        self.tag = gf_mul_reduce((ret_0, ret_1, ret_2));
    }

    #[cfg(ghash_block_x6)]
    #[inline(always)]
    pub(crate) fn update_6block_for_aes(&mut self, m: [&[u8; 16]; 6]) {
        let m0 = bswap_128(vld1q_u8(m[0].as_ptr()));
        let m1 = bswap_128(vld1q_u8(m[1].as_ptr()));
        let m2 = bswap_128(vld1q_u8(m[2].as_ptr()));
        let m3 = bswap_128(vld1q_u8(m[3].as_ptr()));
        let m4 = bswap_128(vld1q_u8(m[4].as_ptr()));
        let m5 = bswap_128(vld1q_u8(m[5].as_ptr()));

        let m0 = veorq_u8(m0, self.tag);
        let ret0 = gf_mul_no_reduce(self.key6, m0, self.key_k6);
        let ret1 = gf_mul_no_reduce(self.key5, m1, self.key_k5);
        let ret2 = gf_mul_no_reduce(self.key4, m2, self.key_k4);
        let ret3 = gf_mul_no_reduce(self.key3, m3, self.key_k3);
        let ret4 = gf_mul_no_reduce(self.key2, m4, self.key_k2);
        let ret5 = gf_mul_no_reduce(self.key,  m5, self.key_k);

        let ret_0 = veorq_u8(veorq_u8(veorq_u8(veorq_u8(veorq_u8(ret0.0, ret1.0), ret2.0), ret3.0), ret4.0), ret5.0);
        let ret_1 = veorq_u8(veorq_u8(veorq_u8(veorq_u8(veorq_u8(ret0.1, ret1.1), ret2.1), ret3.1), ret4.1), ret5.1);
        let ret_2 = veorq_u8(veorq_u8(veorq_u8(veorq_u8(veorq_u8(ret0.2, ret1.2), ret2.2), ret3.2), ret4.2), ret5.2);

        self.tag = gf_mul_reduce((ret_0, ret_1, ret_2));
    }

    #[inline]
    pub fn finalize(self) -> [u8; 16] {
        let mut ret = [0u8; 16];
        vst1q_u8(ret.as_mut_ptr(), bswap_128(self.tag));
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ghash() {
        if !crate::is_hw_feature_detected!("neon") {
            return;
        }
        ghash_test_case!();
    }
}