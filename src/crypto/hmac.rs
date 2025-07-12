// HMAC: Keyed-Hashing for Message Authentication
// https://tools.ietf.org/html/rfc2104

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

macro_rules! impl_hmac_with_hasher {
    ($name:tt, $hasher:ty, $tag_len:literal$(, $feature:literal)?) => {
        #[derive(Clone, Copy)]
        pub struct $name {
            okey: [u8; Self::BLOCK_LEN],
            hasher: $hasher,
        }

        $(#[unsafe_target_feature($feature)])?
        impl $name {
            pub const BLOCK_LEN: usize = <$hasher>::BLOCK_LEN;
            pub const TAG_LEN: usize = <$hasher>::DIGEST_LEN;

            pub fn new(key: &[u8]) -> Self {
                // H(K XOR opad, H(K XOR ipad, text))
                let mut ikey = [0u8; Self::BLOCK_LEN];
                let mut okey = [0u8; Self::BLOCK_LEN];

                if key.len() > Self::BLOCK_LEN {
                    let hkey = <$hasher>::oneshot(key);

                    ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                    okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                } else {
                    ikey[..key.len()].copy_from_slice(&key);
                    okey[..key.len()].copy_from_slice(&key);
                }

                for idx in 0..Self::BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }

                let mut hasher = <$hasher>::new();
                hasher.update(&ikey);

                Self { okey, hasher }
            }
            #[inline(always)]
            pub fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }
            #[inline(always)]
            pub fn finalize(self) -> [u8; $tag_len] {
                let h1 = self.hasher.finalize();

                let mut hasher = <$hasher>::new();
                hasher.update(&self.okey);
                hasher.update(&h1);

                let h2 = hasher.finalize();

                return h2;
            }
            #[inline(always)]
            pub fn oneshot(key: &[u8], m: &[u8]) -> [u8; $tag_len] {
                let mut mac = Self::new(key);
                mac.update(m);
                mac.finalize()
            }
        }
    };
}

use unsafe_target_feature::unsafe_target_feature;

impl_hmac_with_hasher!(HmacSha1Soft, super::hash::sha1::soft::Sha1, 20);
impl_hmac_with_hasher!(HmacMd5, super::hash::md5::soft::Md5, 16);

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        impl_hmac_with_hasher!(HmacSha1SSE, super::hash::sha1::x86_sse::Sha1, 20, "ssse3");
        impl_hmac_with_hasher!(HmacSha1AVX, super::hash::sha1::x86_avx::Sha1, 20, "avx");
        impl_hmac_with_hasher!(HmacSha1Bmi, super::hash::sha1::x86_bmi::Sha1, 20, "bmi1,bmi2");
        impl_hmac_with_hasher!(HmacSha1NI, super::hash::sha1::x86::Sha1, 20, "sse2,ssse3,sse4.1,sha");

        cfg_if::cfg_if! {
            if #[cfg(all(target_feature = "sha", target_feature = "sse2", target_feature = "ssse3", target_feature = "sse4.1"))] {
                pub type HmacSha1 = HmacSha1NI;
            } else {
                pub type HmacSha1 = HmacSha1Dynamic;
            }
        }
    } else if #[cfg(any(target_arch = "aarch64", target_arch = "arm"))] {
        impl_hmac_with_hasher!(HmacSha1NI, super::hash::sha1::arm_ni::Sha1, 20, "sha2");
        impl_hmac_with_hasher!(HmacSha1NEON, super::hash::sha1::arm::Sha1, 20, "neon");
        cfg_if::cfg_if! {
            if #[cfg(all(target_feature = "sha2", target_feature = "neon"))] {
                pub type HmacSha1 = HmacSha1NI;
            } else {
                pub type HmacSha1 = HmacSha1Dynamic;
            }
        }
    } else {
        pub type HmacSha1 = HmacSha1Soft;
    }
}

#[derive(Clone, Copy)]
pub union HmacSha1Dynamic {
    soft: HmacSha1Soft,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_sse: HmacSha1SSE,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_avx: HmacSha1AVX,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_bmi: HmacSha1Bmi,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_ni: HmacSha1NI,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    arm_ni: HmacSha1NI,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    arm_neon: HmacSha1NEON,
}

/// x86: 0 - soft, 1 - sha-ni, 2 - sse, 3 - avx, 4 - bmi2
/// arm/aarch64: 0 - soft, 1 - neon, 2 - sha2
use super::hash::sha1::dynamic::IDX as HMAC_SHA1_IDX;
use super::hash::sha1::dynamic::init_idx as init_hmac_sha1_idx;

impl HmacSha1Dynamic {
    pub const BLOCK_LEN: usize = 64;
    pub const TAG_LEN: usize = 20;

    #[inline(always)]
    pub fn new(key: &[u8]) -> Self {
        unsafe {
            match init_hmac_sha1_idx() {
                0 => Self {
                    soft: HmacSha1Soft::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Self {
                    x86_sse: HmacSha1SSE::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Self {
                    x86_avx: HmacSha1AVX::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => Self {
                    x86_bmi: HmacSha1Bmi::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Self {
                    x86_ni: HmacSha1NI::new(key),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => Self {
                    arm_neon: HmacSha1NEON::new(key),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => Self {
                    arm_ni: HmacSha1NI::new(key),
                },
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        unsafe {
            match HMAC_SHA1_IDX {
                0 => self.soft.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.x86_ni.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.x86_sse.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.x86_avx.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.x86_bmi.update(m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.arm_neon.update(m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.arm_ni.update(m),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            match HMAC_SHA1_IDX {
                0 => self.soft.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.x86_ni.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.x86_sse.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.x86_avx.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.x86_bmi.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.arm_neon.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.arm_ni.finalize(),
                _ => unreachable!(),
            }
        }
    }

    pub fn oneshot(key: &[u8], m: &[u8]) -> [u8; Self::TAG_LEN] {
        unsafe {
            match init_hmac_sha1_idx() {
                0 => HmacSha1Soft::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => HmacSha1NI::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => HmacSha1SSE::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => HmacSha1AVX::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => HmacSha1Bmi::oneshot(key, m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => HmacSha1NEON::oneshot(key, m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => HmacSha1NI::oneshot(key, m),
                _ => unreachable!(),
            }
        }
    }
}
