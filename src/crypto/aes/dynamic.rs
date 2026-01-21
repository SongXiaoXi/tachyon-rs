use std::mem::ManuallyDrop;

use crate::is_hw_feature_detected;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx as hw;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm as hw;

use super::soft;

pub union AES128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
    ni: hw::AES128,
    soft: ManuallyDrop<soft::AES128>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    sse: x86::AES128,
}

static mut IDX: u32 = u32::MAX; // 0: soft, 1: x86/arm aes-ni, 2: sse

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    #[inline(always)]
    pub fn new(key: [u8; 16]) -> Self {
        unsafe {
            if IDX == u32::MAX {
                if is_hw_feature_detected!(
                    "x86" => ("aes"),
                    "x86_64" => ("aes"),
                    "aarch64" => ("aes")
                ) {
                    IDX = 1;
                    if is_hw_feature_detected!(
                        "x86" => ("avx"),
                        "x86_64" => ("avx")
                    ) {
                        IDX = 1;
                    } else {
                        if is_hw_feature_detected!(
                            "x86" => ("sse2"),
                            "x86_64" => ("sse2")
                        ) {
                            IDX = 2;
                        } else {
                            IDX = 0;
                        }
                    }
                } else {
                    IDX = 0;
                }
            }

            match IDX {
                0 => AES128 {
                    soft: ManuallyDrop::new(soft::AES128::new(key)),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => AES128 {
                    ni: hw::AES128::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => AES128 {
                    sse: x86::AES128::new(key),
                },
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        Self::new(unsafe { *(key.as_ptr() as *const [u8; 16]) })
    }
    #[inline(always)]
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        unsafe {
            match IDX {
                0 => self.soft.encrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.encrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.encrypt(block),
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn decrypt(&self, block: &mut [u8; 16]) {
        unsafe {
            match IDX {
                0 => self.soft.decrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.decrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.decrypt(block),
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn encrypt_copy(&self, block: &[u8; 16], output: &mut [u8; 16]) {
        unsafe {
            match IDX {
                0 => self.soft.encrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.encrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.encrypt_copy(block, output),
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn decrypt_copy(&self, block: &[u8; 16], output: &mut [u8; 16]) {
        unsafe {
            match IDX {
                0 => self.soft.decrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.decrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.decrypt_copy(block, output),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub(crate) fn encrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        unsafe {
            match IDX {
                0 => self.soft.encrypt_4_blocks(data0, data1, data2, data3),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.encrypt_4_blocks(data0, data1, data2, data3),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.encrypt_4_blocks(data0, data1, data2, data3),
                _ => unreachable!(),
            }
        }
    }

    #[inline(always)]
    pub(crate) fn decrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        unsafe {
            match IDX {
                0 => self.soft.decrypt_4_blocks(data0, data1, data2, data3),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.decrypt_4_blocks(data0, data1, data2, data3),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.decrypt_4_blocks(data0, data1, data2, data3),
                _ => unreachable!(),
            }
        }
    }
}

impl Clone for AES128 {
    #[inline]
    fn clone(&self) -> Self {
        unsafe {
            match IDX {
                0 => AES128 {
                    soft: self.soft.clone(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => AES128 {
                    ni: self.ni,
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => AES128 {
                    sse: self.sse,
                },
                _ => unreachable!(),
            }
        }
    }
}

impl Drop for AES128 {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            match IDX {
                0 => ManuallyDrop::drop(&mut self.soft),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => (),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => (),
                _ => unreachable!(),
            }
        }
    }
}

pub union AES256 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
    ni: hw::AES256,
    soft: ManuallyDrop<soft::AES256>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    sse: x86::AES256,
}

static mut IDX256: u32 = u32::MAX; // 0: soft, 1: x86/arm aes-ni, 2: sse

impl AES256 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 32;
    #[inline(always)]
    pub fn new(key: [u8; 32]) -> Self {
        unsafe {
            if IDX256 == u32::MAX {
                if is_hw_feature_detected!(
                    "x86" => ("aes"),
                    "x86_64" => ("aes"),
                    "aarch64" => ("aes")
                ) {
                    IDX256 = 1;
                    if is_hw_feature_detected!(
                        "x86" => ("avx"),
                        "x86_64" => ("avx")
                    ) {
                        IDX256 = 1;
                    } else {
                        if is_hw_feature_detected!(
                            "x86" => ("sse2"),
                            "x86_64" => ("sse2")
                        ) {
                            IDX256 = 2;
                        } else {
                            IDX256 = 0;
                        }
                    }
                } else {
                    IDX256 = 0;
                }
            }

            match IDX256 {
                0 => AES256 {
                    soft: ManuallyDrop::new(soft::AES256::new(key)),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => AES256 {
                    ni: hw::AES256::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => AES256 {
                    sse: x86::AES256::new(key),
                },
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        Self::new(unsafe { *(key.as_ptr() as *const [u8; 32]) })
    }
    #[inline(always)]
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        unsafe {
            match IDX256 {
                0 => self.soft.encrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.encrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.encrypt(block),
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn decrypt(&self, block: &mut [u8; 16]) {
        unsafe {
            match IDX256 {
                0 => self.soft.decrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.decrypt(block),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.decrypt(block),
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn encrypt_copy(&self, block: &[u8; 16], output: &mut [u8; 16]) {
        unsafe {
            match IDX256 {
                0 => self.soft.encrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.encrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.encrypt_copy(block, output),
                _ => unreachable!(),
            }
        }
    }
    #[inline(always)]
    pub fn decrypt_copy(&self, block: &[u8; 16], output: &mut [u8; 16]) {
        unsafe {
            match IDX256 {
                0 => self.soft.decrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => self.ni.decrypt_copy(block, output),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.sse.decrypt_copy(block, output),
                _ => unreachable!(),
            }
        }
    }
}

impl Clone for AES256 {
    #[inline]
    fn clone(&self) -> Self {
        unsafe {
            match IDX256 {
                0 => AES256 {
                    soft: self.soft.clone(),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => AES256 {
                    ni: self.ni,
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => AES256 {
                    sse: self.sse,
                },
                _ => unreachable!(),
            }
        }
    }
}

impl Drop for AES256 {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            match IDX256 {
                0 => ManuallyDrop::drop(&mut self.soft),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
                1 => (),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => (),
                _ => unreachable!(),
            }
        }
    }
}