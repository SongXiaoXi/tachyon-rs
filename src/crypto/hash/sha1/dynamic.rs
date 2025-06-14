use super::soft;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm_ni;

#[derive(Clone, Copy)]
pub union Sha1 {
    soft: soft::Sha1,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    x86_sha: x86::Sha1,
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    arm_sha: arm_ni::Sha1,
}

static mut IDX: u32 = u32::MAX; // 0: soft, 1: x86/arm

#[inline(always)]
unsafe fn init_idx() {
    if IDX == u32::MAX {
        if crate::is_hw_feature_detected!(
            "x86" => ("sse2", "ssse3", "sha"),
            "x86_64" => ("sse2", "ssse3", "sha"),
            "aarch64" => ("sha2"),
            "arm" => ("neon", "sha2")
        ) {
            IDX = 1;
        } else {
            IDX = 0;
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
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => Sha1 {
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
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.arm_sha.update(data),
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
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.arm_sha.finalize(),
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
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => arm_ni::Sha1::oneshot(data),
                _ => unreachable!(),
            }
        }
    }
}