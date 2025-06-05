use super::soft;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_ssse3;
#[cfg(target_arch = "aarch64")]
use super::aarch64;
#[cfg(target_arch = "aarch64")]
use super::aarch64_ni;

#[derive(Clone, Copy)]
pub union Sha512 {
    soft: soft::Sha512,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    hw_sha: x86_avx::Sha512,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ssse3_sha: x86_ssse3::Sha512,
    #[cfg(target_arch = "aarch64")]
    ni_sha: aarch64_ni::Sha512,
    #[cfg(target_arch = "aarch64")]
    hw_sha: aarch64::Sha512,
}

static mut IDX: u32 = u32::MAX; // 0: soft, 1: x86 SSSE3/armv8 Sha512-NI, 2:x86 AVX/armv8 NEON

unsafe fn init_idx() {
    if IDX == u32::MAX {
        if crate::is_hw_feature_detected!(
            "x86" => ("sse2", "ssse3"),
            "x86_64" => ("sse2", "ssse3"),
            "aarch64" => ("neon")
        ) {
            IDX = 1;
            if crate::is_hw_feature_detected!(
                "x86" => ("avx"),
                "x86_64" => ("avx"),
                "aarch64" => ("sha3"),
            ) {
                IDX = 2;
            }
        } else {
            IDX = 0;
        }
    }
}

impl Sha512 {
    pub const BLOCK_LEN: usize = 128;
    pub const DIGEST_LEN: usize = 64;

    const BLOCK_LEN_BITS: u128 = Self::BLOCK_LEN as u128 * 8;
    const MLEN_SIZE: usize = core::mem::size_of::<u128>();
    const MLEN_SIZE_BITS: u128 = Self::MLEN_SIZE as u128 * 8;
    const MAX_PAD_LEN: usize = Self::BLOCK_LEN + Self::MLEN_SIZE as usize;

    #[inline(always)]
    pub fn new() -> Self {
        unsafe {
            init_idx();

            match IDX {
                0 => Sha512 {
                    soft: soft::Sha512::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Sha512 {
                    hw_sha: x86_avx::Sha512::new(),
                },
                #[cfg(target_arch = "aarch64")]
                1 => Sha512 {
                    hw_sha: aarch64::Sha512::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Sha512 {
                    ssse3_sha: x86_ssse3::Sha512::new(),
                },
                #[cfg(target_arch = "aarch64")]
                2 => Sha512 {
                    ni_sha: aarch64_ni::Sha512::new(),
                },
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn update(&mut self, m: &[u8]) {
        unsafe {
            match IDX {
                0 => self.soft.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.hw_sha.update(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3_sha.update(m),
                #[cfg(target_arch = "aarch64")]
                1 => self.hw_sha.update(m),
                #[cfg(target_arch = "aarch64")]
                2 => self.ni_sha.update(m),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        unsafe {
            match IDX {
                0 => self.soft.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.hw_sha.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3_sha.finalize(),
                #[cfg(target_arch = "aarch64")]
                1 => self.hw_sha.finalize(),
                #[cfg(target_arch = "aarch64")]
                2 => self.ni_sha.finalize(),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn oneshot(m: &[u8]) -> [u8; Self::DIGEST_LEN] {
        unsafe {
            init_idx();
            match IDX {
                0 => soft::Sha512::oneshot(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => x86_avx::Sha512::oneshot(m),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => x86_ssse3::Sha512::oneshot(m),
                #[cfg(target_arch = "aarch64")]
                1 => aarch64::Sha512::oneshot(m),
                #[cfg(target_arch = "aarch64")]
                2 => aarch64_ni::Sha512::oneshot(m),
                _ => unreachable!(),
            }
        }
    }
}