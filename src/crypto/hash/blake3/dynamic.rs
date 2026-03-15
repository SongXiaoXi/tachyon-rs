// BLAKE3 runtime dispatch – selects the best available SIMD back-end at
// first use, following the same union + static IDX pattern used by the
// SHA-256, SHA-1, and other hash implementations in this crate.

use super::soft;
#[cfg(target_arch = "aarch64")]
use super::aarch64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_ssse3;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx2;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
use super::x86_avx512;

#[derive(Clone, Copy)]
pub union Blake3 {
    soft: soft::Blake3,
    #[cfg(target_arch = "aarch64")]
    neon: aarch64::Blake3,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    ssse3: x86_ssse3::Blake3,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx: x86_avx::Blake3,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx2: x86_avx2::Blake3,
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
    avx512: x86_avx512::Blake3,
}

// x86 : 0 – soft, 1 – ssse3, 2 – avx, 3 – avx2, 4 – avx512
// arm : 0 – soft, 1 – neon
static mut IDX: u32 = u32::MAX;

#[inline(always)]
unsafe fn init_idx() {
    if IDX == u32::MAX {
        IDX = 0;
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "aarch64")] {
                if crate::is_hw_feature_detected!("aarch64" => ("neon")) {
                    IDX = 1;
                }
            } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                if crate::is_hw_feature_detected!(
                    "x86" => ("ssse3"),
                    "x86_64" => ("ssse3"),
                ) {
                    IDX = 1;
                    if crate::is_hw_feature_detected!(
                        "x86" => ("avx"),
                        "x86_64" => ("avx"),
                    ) {
                        IDX = 2;
                        if crate::is_hw_feature_detected!(
                            "x86" => ("avx2"),
                            "x86_64" => ("avx2"),
                        ) {
                            IDX = 3;
                            #[cfg(avx512_feature)]
                            if crate::is_hw_feature_detected!(
                                "x86" => ("avx512f", "avx512vl"),
                                "x86_64" => ("avx512f", "avx512vl"),
                            ) {
                                IDX = 4;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Blake3 {
    blake3_define_const!();

    #[inline(always)]
    pub fn new() -> Self {
        unsafe {
            init_idx();
            match IDX {
                0 => Blake3 { soft: soft::Blake3::new() },
                #[cfg(target_arch = "aarch64")]
                1 => Blake3 { neon: aarch64::Blake3::new() },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Blake3 { ssse3: x86_ssse3::Blake3::new() },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Blake3 { avx: x86_avx::Blake3::new() },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Blake3 { avx2: x86_avx2::Blake3::new() },
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
                4 => Blake3 { avx512: x86_avx512::Blake3::new() },
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn with_keyed(key: &[u8]) -> Self {
        unsafe {
            init_idx();
            match IDX {
                0 => Blake3 { soft: soft::Blake3::with_keyed(key) },
                #[cfg(target_arch = "aarch64")]
                1 => Blake3 { neon: aarch64::Blake3::with_keyed(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Blake3 { ssse3: x86_ssse3::Blake3::with_keyed(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Blake3 { avx: x86_avx::Blake3::with_keyed(key) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Blake3 { avx2: x86_avx2::Blake3::with_keyed(key) },
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
                4 => Blake3 { avx512: x86_avx512::Blake3::with_keyed(key) },
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub fn new_derive_key<S: AsRef<[u8]>>(context: S) -> Self {
        unsafe {
            init_idx();
            match IDX {
                0 => Blake3 { soft: soft::Blake3::new_derive_key(context) },
                #[cfg(target_arch = "aarch64")]
                1 => Blake3 { neon: aarch64::Blake3::new_derive_key(context) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => Blake3 { ssse3: x86_ssse3::Blake3::new_derive_key(context) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => Blake3 { avx: x86_avx::Blake3::new_derive_key(context) },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => Blake3 { avx2: x86_avx2::Blake3::new_derive_key(context) },
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
                4 => Blake3 { avx512: x86_avx512::Blake3::new_derive_key(context) },
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            match IDX {
                0 => self.soft.update(data),
                #[cfg(target_arch = "aarch64")]
                1 => self.neon.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.update(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx2.update(data),
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
                4 => self.avx512.update(data),
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    pub fn finalize(self, digest: &mut [u8]) {
        unsafe {
            match IDX {
                0 => self.soft.finalize(digest),
                #[cfg(target_arch = "aarch64")]
                1 => self.neon.finalize(digest),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.ssse3.finalize(digest),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.finalize(digest),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx2.finalize(digest),
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
                4 => self.avx512.finalize(digest),
                _ => unreachable!(),
            }
        }
    }

    #[inline(never)]
    pub fn oneshot<S: AsRef<[u8]>>(data: S) -> [u8; Self::DIGEST_LEN] {
        unsafe {
            init_idx();
            match IDX {
                0 => soft::Blake3::oneshot(data),
                #[cfg(target_arch = "aarch64")]
                1 => aarch64::Blake3::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => x86_ssse3::Blake3::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => x86_avx::Blake3::oneshot(data),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => x86_avx2::Blake3::oneshot(data),
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
                4 => x86_avx512::Blake3::oneshot(data),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    blake3_test_case!();
}
