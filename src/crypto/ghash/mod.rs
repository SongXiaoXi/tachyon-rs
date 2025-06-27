#[macro_use]
pub mod soft;
pub mod dynamic;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_avx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_avx2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(avx512_feature)]
pub mod x86_avx512;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub mod arm;

cfg_if::cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx", target_feature = "pclmulqdq"))] {
        pub use x86_avx::*;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "aes"))] {
        pub use aarch64::*;
    } else {
        pub use dynamic::*;
    }
}