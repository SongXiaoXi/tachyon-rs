use crate::is_hw_feature_detected;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86_avx as hw;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm as hw;

use super::soft;

#[derive(Clone, Copy)]
pub union AES128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
    ni: hw::AES128,
    soft: soft::AES128,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    sse: x86::AES128,
}

static mut IDX: u32 = u32::MAX; // 0: soft, 1: x86/arm aes-ni, 2: sse

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = true;
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
                    soft: soft::AES128::new(key),
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