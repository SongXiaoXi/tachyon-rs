use crate::is_hw_feature_detected;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86 as hw;
#[cfg(target_arch = "aarch64")]
use super::aarch64 as hw;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx;

#[derive(Clone, Copy)]
pub union GHash {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    hw: hw::GHash,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx: x86_avx::GHash,
    soft: super::soft::GHash,
}

static mut IDX: u32 = u32::MAX; // 0: soft, 1: x86/arm, 2: avx

impl GHash {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize = 16;
    #[inline(always)]
    pub fn new(key: &[u8; 16]) -> Self {
        unsafe {
            if IDX == u32::MAX {
                if is_hw_feature_detected!(
                    "x86" => ("pclmulqdq", "sse2", "ssse3"),
                    "x86_64" => ("pclmulqdq", "sse2", "ssse3"),
                    "aarch64" => ("neon", "aes")
                ) {
                    IDX = 1;
                    if is_hw_feature_detected!(
                        "x86" => ("avx"),
                        "x86_64" => ("avx")
                    ) {
                        IDX = 2;
                    }
                } else {
                    IDX = 0;
                }
            }

            match IDX {
                0 => GHash {
                    soft: super::soft::GHash::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
                1 => GHash {
                    hw: hw::GHash::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => GHash {
                    avx: x86_avx::GHash::new(key),
                },
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            match IDX {
                0 => self.soft.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
                1 => self.hw.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.update(data),
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn finalize(self) -> [u8; 16] {
        unsafe {
            match IDX {
                0 => self.soft.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
                1 => self.hw.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.finalize(),
                _ => unreachable!(),
            }
        }
    }
}