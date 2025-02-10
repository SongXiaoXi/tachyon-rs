use crate::is_hw_feature_available;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::x86 as hw;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
use super::arm as hw;

#[derive(Clone)]
pub enum AES128 {
    HW(hw::AES128),
    SW(super::soft::AES128),
}

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    #[inline(always)]
    pub fn new(key: [u8; 16]) -> Self {
        if is_hw_feature_available!(
            "x86" => ("aes", "sse2"),
            "x86_64" => ("aes", "sse2"),
            "aarch64" => ("aes")
        ) {
            AES128::HW(hw::AES128::new(key))
        } else {
            AES128::SW(super::soft::AES128::new(key))
        }
    }
    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        if is_hw_feature_available!(
            "x86" => ("aes", "sse2"),
            "x86_64" => ("aes", "sse2"),
            "aarch64" => ("aes")
        ) {
            AES128::HW(hw::AES128::from_slice(key))
        } else {
            AES128::SW(super::soft::AES128::from_slice(key))
        }
    }
    #[inline(always)]
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        match self {
            AES128::HW(hw) => hw.encrypt(block),
            AES128::SW(sw) => sw.encrypt(block),
        }
    }
    #[inline(always)]
    pub fn decrypt(&self, block: &mut [u8; 16]) {
        match self {
            AES128::HW(hw) => hw.decrypt(block),
            AES128::SW(sw) => sw.decrypt(block),
        }
    }
    #[inline(always)]
    pub fn encrypt_copy(&self, block: &[u8; 16], output: &mut [u8; 16]) {
        match self {
            AES128::HW(hw) => hw.encrypt_copy(block, output),
            AES128::SW(sw) => sw.encrypt_copy(block, output),
        }
    }
    #[inline(always)]
    pub fn decrypt_copy(&self, block: &[u8; 16], output: &mut [u8; 16]) {
        match self {
            AES128::HW(hw) => hw.decrypt_copy(block, output),
            AES128::SW(sw) => sw.decrypt_copy(block, output),
        }
    }

    #[inline(always)]
    pub fn encrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        match self {
            AES128::HW(hw) => hw.encrypt_4_blocks(data0, data1, data2, data3),
            AES128::SW(sw) => sw.encrypt_4_blocks(data0, data1, data2, data3),
        }
    }

    #[inline(always)]
    pub fn decrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        match self {
            AES128::HW(hw) => hw.decrypt_4_blocks(data0, data1, data2, data3),
            AES128::SW(sw) => sw.decrypt_4_blocks(data0, data1, data2, data3),
        }
    }
}