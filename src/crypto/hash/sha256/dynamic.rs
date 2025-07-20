use super::soft;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_ni;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_ssse3;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx_bmi;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm_ni;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm;

#[derive(Clone, Copy)]
pub union Sha256 {
    soft: soft::Sha256,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ssse3_sha: x86_ssse3::Sha256,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx_sha: x86_avx::Sha256,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx_bmi_sha: x86_avx_bmi::Sha256,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    hw_sha: x86_ni::Sha256,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    neon_sha: arm::Sha256,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    ni_sha: arm_ni::Sha256,
}

// x86: 0 - soft, 1 - ssse3, 2 - avx, 3 - avx+bmi, 4 - hw_sha
// arm: 0 - soft, 1 - neon, 2 - ni_sha
static mut IDX: u32 = u32::MAX;

unsafe fn init_idx() {
    if IDX == u32::MAX {
        if crate::is_hw_feature_detected!(
            "x86" => ("ssse3"),
            "x86_64" => ("ssse3"),
            "aarch64" => ("neon"),
            "arm" => ("neon"),
        ) {
            IDX = 1;
            if crate::is_hw_feature_detected!(
                "x86" => ("sse4.1", "sha"),
                "x86_64" => ("sse4.1", "sha"),
            ) {
                IDX = 4;
            } else if crate::is_hw_feature_detected!(
                "aarch64" => ("sha2"),
                "arm" => ("sha2"),
                "x86" => ("avx"),
                "x86_64" => ("avx"),
            ) {
                IDX = 2;
                if crate::is_hw_feature_detected!(
                    "x86" => ("bmi1", "bmi2"),
                    "x86_64" => ("bmi1", "bmi2"),
                ) {
                    IDX = 3;
                }
            }
        } else {
            IDX = 0;
        }
    }
}

impl Sha256 {
    pub const BLOCK_LEN: usize = soft::Sha256::BLOCK_LEN;
    pub const DIGEST_LEN: usize = soft::Sha256::DIGEST_LEN;

    #[inline(always)]
    pub fn new() -> Self {
        unsafe {
            init_idx();
            match IDX {
                0 => Sha256 {
                    soft: soft::Sha256::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Sha256 {
                    ssse3_sha: x86_ssse3::Sha256::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Sha256 {
                    avx_sha: x86_avx::Sha256::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Sha256 {
                    avx_bmi_sha: x86_avx_bmi::Sha256::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => Sha256 {
                    hw_sha: x86_ni::Sha256::new(),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => Sha256 {
                    neon_sha: arm::Sha256::new(),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => Sha256 {
                    ni_sha: arm_ni::Sha256::new(),
                },
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            match IDX {
                0 => self.soft.update(data),

                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3_sha.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx_sha.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx_bmi_sha.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.hw_sha.update(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon_sha.update(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.ni_sha.update(data),
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        unsafe {
            match IDX {
                0 => self.soft.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3_sha.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx_sha.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx_bmi_sha.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.hw_sha.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon_sha.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.ni_sha.finalize(),
                _ => unreachable!(),
            }
        }
    }
    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        unsafe {
            init_idx();
            match IDX {
                0 => soft::Sha256::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => x86_ssse3::Sha256::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => x86_avx::Sha256::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => x86_avx_bmi::Sha256::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => x86_ni::Sha256::oneshot(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => arm::Sha256::oneshot(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => arm_ni::Sha256::oneshot(data),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha256() {
        sha256_test_case!();
    }
}