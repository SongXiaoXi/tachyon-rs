#![cfg_attr(feature = "nightly", feature(cfg_version))]
#![cfg_attr(feature = "nightly", cfg_attr(not(version("1.75.0")), feature(stdsimd)))]

pub mod crypto;
pub mod string;

#[allow(non_snake_case)]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub const fn _MM_SHUFFLE(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}