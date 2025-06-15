use super::soft;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_sse;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_bmi;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm_ni;

#[derive(Clone, Copy)]
pub union Sha1 {
    soft: soft::Sha1,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_sha: x86::Sha1,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_sse: x86_sse::Sha1,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_avx: x86_avx::Sha1,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_bmi: x86_bmi::Sha1,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    arm: arm::Sha1,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    arm_sha: arm_ni::Sha1,
}

// x86: 0 - soft, 1 - sha-ni, 2 - sse, 3 - avx, 4 - bmi2
// arm: 0 - soft, 1 - neon, 2 - sha2
static mut IDX: u32 = u32::MAX;

#[inline(always)]
unsafe fn init_idx() {
    if IDX == u32::MAX {
        if crate::is_hw_feature_detected!(
            "x86" => ("sse2", "ssse3", "sha"),
            "x86_64" => ("sse2", "ssse3", "sha"),
            "aarch64" => ("neon"),
            "arm" => ("neon")
        ) {
            IDX = 1;
            if crate::is_hw_feature_detected!(
                "aarch64" => ("sha2"),
                "arm" => ("sha2")
            ) {
                IDX = 2;
            }
        } else {
            IDX = 0;
            if crate::is_hw_feature_detected!(
                "x86" => ("ssse3"),
                "x86_64" => ("ssse3"),
            ) {
                IDX = 2;
                if crate::is_hw_feature_detected!(
                    "x86" => ("avx"),
                    "x86_64" => ("avx"),
                ) {
                    IDX = 3;
                    if crate::is_hw_feature_detected!(
                        "x86" => ("bmi1", "bmi2"),
                        "x86_64" => ("bmi1", "bmi2"),
                    ) {
                        IDX = 4;
                    }
                }
            }
        }
    }
}

impl Sha1 {
    sha1_define_const!();

    #[inline(always)]
    pub fn new() -> Self {
        unsafe {
            init_idx();

            match IDX {
                0 => Sha1 {
                    soft: soft::Sha1::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Sha1 {
                    x86_sha: x86::Sha1::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Sha1 {
                    x86_sse: x86_sse::Sha1::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Sha1 {
                    x86_avx: x86_avx::Sha1::new(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => Sha1 {
                    x86_bmi: x86_bmi::Sha1::new(),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => Sha1 {
                    arm: arm::Sha1::new(),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => Sha1 {
                    arm_sha: arm_ni::Sha1::new(),
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
                1 => self.x86_sha.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.x86_sse.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.x86_avx.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.x86_bmi.update(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.arm.update(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.arm_sha.update(data),
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
                1 => self.x86_sha.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.x86_sse.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.x86_avx.finalize(),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.x86_bmi.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.arm.finalize(),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => self.arm_sha.finalize(),
                _ => unreachable!(),
            }
        }
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 20] {
        unsafe {
            init_idx();
            match IDX {
                0 => soft::Sha1::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => x86::Sha1::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => x86_sse::Sha1::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => x86_avx::Sha1::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => x86_bmi::Sha1::oneshot(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => arm::Sha1::oneshot(data),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                2 => arm_ni::Sha1::oneshot(data),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha1() {
        sha1_test_case!();
    }
}