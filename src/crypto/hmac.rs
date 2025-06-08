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

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        impl_hmac_with_hasher!(HmacSha1SSE, super::hash::sha1::x86::Sha1, 20, "sha");
        type HmacSha1HW = HmacSha1SSE;
    } else if #[cfg(any(target_arch = "aarch64", target_arch = "arm"))] {
        impl_hmac_with_hasher!(HmacSha1ARM, super::hash::sha1::arm::Sha1, 20, "sha2");
        type HmacSha1HW = HmacSha1ARM;
    }
}

#[derive(Clone, Copy)]
pub union HmacSha1 {
    soft: HmacSha1Soft,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
    hw: HmacSha1HW,
}

// x86: 0 - soft, 1 - sha-ni
// aarch64/arm: 0 - soft, 1 - sha2
static mut HMAC_SHA1_IDX: u32 = u32::MAX;

impl HmacSha1 {
    pub const BLOCK_LEN: usize = 64;
    pub const TAG_LEN: usize = 20;

    #[inline(always)]
    pub fn new(key: &[u8]) -> Self {
        unsafe {
            if HMAC_SHA1_IDX == u32::MAX {
                if crate::is_hw_feature_detected!(
                    "x86" => ("sse2", "sha"),
                    "x86_64" => ("sse2", "sha"),
                    "aarch64" => ("sha2"),
                    "arm" => ("neon", "sha2")
                ) {
                    HMAC_SHA1_IDX = 1;
                } else {
                    HMAC_SHA1_IDX = 0;
                }
            }

            match HMAC_SHA1_IDX {
                0 => Self {
                    soft: HmacSha1Soft::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => Self {
                    hw: HmacSha1HW::new(key),
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
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.hw.update(m),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            match HMAC_SHA1_IDX {
                0 => self.soft.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.hw.finalize(),
                _ => unreachable!(),
            }
        }
    }

    pub fn oneshot(key: &[u8], m: &[u8]) -> [u8; Self::TAG_LEN] {
        let mut mac = Self::new(key);
        mac.update(m);
        mac.finalize()
    }
}