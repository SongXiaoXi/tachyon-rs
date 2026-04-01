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

impl_hmac_with_hasher!(HmacSha256Soft, super::hash::sha256::soft::Sha256, 32);

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        impl_hmac_with_hasher!(HmacSha256SSSE3, super::hash::sha256::x86_ssse3::Sha256, 32, "ssse3");
        impl_hmac_with_hasher!(HmacSha256AVX, super::hash::sha256::x86_avx::Sha256, 32, "avx");
        impl_hmac_with_hasher!(HmacSha256AVXBMI, super::hash::sha256::x86_avx_bmi::Sha256, 32, "bmi1,bmi2");
        impl_hmac_with_hasher!(HmacSha256NI, super::hash::sha256::x86_ni::Sha256, 32, "sse4.1,sha");
    } else if #[cfg(any(target_arch = "aarch64", target_arch = "arm"))] {
        impl_hmac_with_hasher!(HmacSha256NEON, super::hash::sha256::arm::Sha256, 32, "neon");
        impl_hmac_with_hasher!(HmacSha256NIArm, super::hash::sha256::arm_ni::Sha256, 32, "sha2");
    }
}

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        cfg_if::cfg_if! {
            if #[cfg(all(target_feature = "sse4.1", target_feature = "sha"))] {
                pub type HmacSha256 = HmacSha256NI;
            } else {
                pub type HmacSha256 = HmacSha256Dynamic;
            }
        }
    } else if #[cfg(any(target_arch = "aarch64", target_arch = "arm"))] {
        cfg_if::cfg_if! {
            if #[cfg(all(target_feature = "sha2", target_feature = "neon"))] {
                pub type HmacSha256 = HmacSha256NIArm;
            } else {
                pub type HmacSha256 = HmacSha256Dynamic;
            }
        }
    } else {
        pub type HmacSha256 = HmacSha256Soft;
    }
}

impl_hmac_with_hasher!(HmacSha512Soft, super::hash::sha512::soft::Sha512, 64);

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        impl_hmac_with_hasher!(HmacSha512SSSE3, super::hash::sha512::x86_ssse3::Sha512, 64, "ssse3");
        impl_hmac_with_hasher!(HmacSha512AVX, super::hash::sha512::x86_avx::Sha512, 64, "avx");
        impl_hmac_with_hasher!(HmacSha512AVXBMI, super::hash::sha512::x86_avx_bmi::Sha512, 64, "bmi1,bmi2");
    } else if #[cfg(target_arch = "aarch64")] {
        impl_hmac_with_hasher!(HmacSha512NEON, super::hash::sha512::aarch64::Sha512, 64, "neon");
        impl_hmac_with_hasher!(HmacSha512NIArm, super::hash::sha512::aarch64_ni::Sha512, 64, "neon,sha3");
    }
}

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        cfg_if::cfg_if! {
            if #[cfg(all(target_feature = "ssse3", target_feature = "avx", target_feature = "bmi1", target_feature = "bmi2"))] {
                pub type HmacSha512 = HmacSha512AVXBMI;
            } else {
                pub type HmacSha512 = HmacSha512Dynamic;
            }
        }
    } else if #[cfg(target_arch = "aarch64")] {
        cfg_if::cfg_if! {
            if #[cfg(all(target_feature = "neon", target_feature = "sha3"))] {
                pub type HmacSha512 = HmacSha512NIArm;
            } else {
                pub type HmacSha512 = HmacSha512Dynamic;
            }
        }
    } else {
        pub type HmacSha512 = HmacSha512Soft;
    }
}

#[derive(Clone, Copy)]
pub union HmacSha256Dynamic {
    soft: HmacSha256Soft,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ssse3: HmacSha256SSSE3,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx: HmacSha256AVX,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx_bmi: HmacSha256AVXBMI,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    hw_sha: HmacSha256NI,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    neon: HmacSha256NEON,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    ni_sha: HmacSha256NIArm,
}

// x86: 0 - soft, 1 - ssse3, 2 - avx, 3 - avx+bmi, 4 - hw_sha
// arm: 0 - soft, 1 - neon, 2 - ni_sha
static mut HMAC_SHA256_IDX: u32 = u32::MAX;

#[inline(always)]
unsafe fn init_hmac_sha256_idx() -> u32 {
    if HMAC_SHA256_IDX == u32::MAX {
        if crate::is_hw_feature_detected!(
            "x86" => ("ssse3"),
            "x86_64" => ("ssse3"),
            "aarch64" => ("neon"),
            "arm" => ("neon")
        ) {
            HMAC_SHA256_IDX = 1;
            if crate::is_hw_feature_detected!(
                "x86" => ("sse4.1", "sha"),
                "x86_64" => ("sse4.1", "sha"),
            ) {
                HMAC_SHA256_IDX = 4;
            } else if crate::is_hw_feature_detected!(
                "aarch64" => ("sha2"),
                "arm" => ("sha2"),
                "x86" => ("avx"),
                "x86_64" => ("avx"),
            ) {
                HMAC_SHA256_IDX = 2;
                if crate::is_hw_feature_detected!(
                    "x86" => ("bmi1", "bmi2"),
                    "x86_64" => ("bmi1", "bmi2"),
                ) {
                    HMAC_SHA256_IDX = 3;
                }
            }
        } else {
            HMAC_SHA256_IDX = 0;
        }
    }
    HMAC_SHA256_IDX
}

impl HmacSha256Dynamic {
    pub const BLOCK_LEN: usize = 64;
    pub const TAG_LEN: usize = 32;

    #[inline(always)]
    pub fn new(key: &[u8]) -> Self {
        unsafe {
            match init_hmac_sha256_idx() {
                0 => Self { soft: HmacSha256Soft::new(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Self { ssse3: HmacSha256SSSE3::new(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Self { avx: HmacSha256AVX::new(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Self { avx_bmi: HmacSha256AVXBMI::new(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => Self { hw_sha: HmacSha256NI::new(key) },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => Self { neon: HmacSha256NEON::new(key) },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => Self { ni_sha: HmacSha256NIArm::new(key) },
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        unsafe {
            match HMAC_SHA256_IDX {
                0 => self.soft.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx_bmi.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.hw_sha.update(m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon.update(m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.ni_sha.update(m),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            match HMAC_SHA256_IDX {
                0 => self.soft.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx_bmi.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.hw_sha.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.ni_sha.finalize(),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn oneshot(key: &[u8], m: &[u8]) -> [u8; Self::TAG_LEN] {
        unsafe {
            match init_hmac_sha256_idx() {
                0 => HmacSha256Soft::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => HmacSha256SSSE3::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => HmacSha256AVX::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => HmacSha256AVXBMI::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => HmacSha256NI::oneshot(key, m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => HmacSha256NEON::oneshot(key, m),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => HmacSha256NIArm::oneshot(key, m),
                _ => unreachable!(),
            }
        }
    }
}

#[derive(Clone, Copy)]
pub union HmacSha512Dynamic {
    soft: HmacSha512Soft,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ssse3: HmacSha512SSSE3,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx: HmacSha512AVX,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx_bmi: HmacSha512AVXBMI,
    #[cfg(target_arch = "aarch64")]
    neon: HmacSha512NEON,
    #[cfg(target_arch = "aarch64")]
    ni_sha: HmacSha512NIArm,
}

// x86: 0 - soft, 1 - ssse3, 2 - avx, 3 - avx+bmi
// aarch64: 0 - soft, 1 - neon, 2 - sha3
static mut HMAC_SHA512_IDX: u32 = u32::MAX;

#[inline(always)]
unsafe fn init_hmac_sha512_idx() -> u32 {
    if HMAC_SHA512_IDX == u32::MAX {
        if crate::is_hw_feature_detected!(
            "x86" => ("ssse3"),
            "x86_64" => ("ssse3"),
            "aarch64" => ("neon")
        ) {
            HMAC_SHA512_IDX = 1;
            if crate::is_hw_feature_detected!(
                "x86" => ("avx"),
                "x86_64" => ("avx"),
                "aarch64" => ("sha3"),
            ) {
                HMAC_SHA512_IDX = 2;
                if crate::is_hw_feature_detected!(
                    "x86" => ("bmi1", "bmi2"),
                    "x86_64" => ("bmi1", "bmi2"),
                ) {
                    HMAC_SHA512_IDX = 3;
                }
            }
        } else {
            HMAC_SHA512_IDX = 0;
        }
    }
    HMAC_SHA512_IDX
}

impl HmacSha512Dynamic {
    pub const BLOCK_LEN: usize = 128;
    pub const TAG_LEN: usize = 64;

    #[inline(always)]
    pub fn new(key: &[u8]) -> Self {
        unsafe {
            match init_hmac_sha512_idx() {
                0 => Self { soft: HmacSha512Soft::new(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Self { ssse3: HmacSha512SSSE3::new(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Self { avx: HmacSha512AVX::new(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Self { avx_bmi: HmacSha512AVXBMI::new(key) },
                #[cfg(target_arch = "aarch64")]
                1 => Self { neon: HmacSha512NEON::new(key) },
                #[cfg(target_arch = "aarch64")]
                2 => Self { ni_sha: HmacSha512NIArm::new(key) },
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        unsafe {
            match HMAC_SHA512_IDX {
                0 => self.soft.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx_bmi.update(m),
                #[cfg(target_arch = "aarch64")]
                1 => self.neon.update(m),
                #[cfg(target_arch = "aarch64")]
                2 => self.ni_sha.update(m),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            match HMAC_SHA512_IDX {
                0 => self.soft.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx_bmi.finalize(),
                #[cfg(target_arch = "aarch64")]
                1 => self.neon.finalize(),
                #[cfg(target_arch = "aarch64")]
                2 => self.ni_sha.finalize(),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn oneshot(key: &[u8], m: &[u8]) -> [u8; Self::TAG_LEN] {
        unsafe {
            match init_hmac_sha512_idx() {
                0 => HmacSha512Soft::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => HmacSha512SSSE3::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => HmacSha512AVX::oneshot(key, m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => HmacSha512AVXBMI::oneshot(key, m),
                #[cfg(target_arch = "aarch64")]
                1 => HmacSha512NEON::oneshot(key, m),
                #[cfg(target_arch = "aarch64")]
                2 => HmacSha512NIArm::oneshot(key, m),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = b"super secret key";
        let data = b"Hello, world!";

        let tag = HmacSha256::oneshot(key, data);

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let ring_tag = ring::hmac::sign(&ring_key, data);

        assert_eq!(tag.as_ref(), ring_tag.as_ref());
    }

    #[test]
    fn test_hmac_sha512() {
        let key = b"super secret key";
        let data = b"Hello, world!";

        let tag = HmacSha512::oneshot(key, data);

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key);
        let ring_tag = ring::hmac::sign(&ring_key, data);

        assert_eq!(tag.as_ref(), ring_tag.as_ref());
    }

    #[test]
    fn test_hmac_sha512_long_key() {
        let key = [0xaau8; 256];
        let data = b"test with a long key exceeding block size";

        let tag = HmacSha512::oneshot(&key, data);

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &key);
        let ring_tag = ring::hmac::sign(&ring_key, data);

        assert_eq!(tag.as_ref(), ring_tag.as_ref());
    }

    #[test]
    fn test_hmac_sha512_incremental() {
        let key = b"incremental hmac key";
        let data1 = b"first part ";
        let data2 = b"second part";

        let mut hmac = HmacSha512::new(key);
        hmac.update(data1);
        hmac.update(data2);
        let tag = hmac.finalize();

        let mut full = Vec::new();
        full.extend_from_slice(data1);
        full.extend_from_slice(data2);
        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key);
        let ring_tag = ring::hmac::sign(&ring_key, &full);

        assert_eq!(tag.as_ref(), ring_tag.as_ref());
    }

    #[test]
    fn test_hmac_sha512_empty() {
        let key = b"key";
        let data = b"";

        let tag = HmacSha512::oneshot(key, data);

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, key);
        let ring_tag = ring::hmac::sign(&ring_key, data);

        assert_eq!(tag.as_ref(), ring_tag.as_ref());
    }
}
