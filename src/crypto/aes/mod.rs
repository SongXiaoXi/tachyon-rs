#[macro_use]
pub mod soft;
pub mod dynamic;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_avx;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub mod arm;

cfg_if::cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx", target_feature = "aes"))] {
        pub use x86_avx::*;
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "aes"))] {
        pub use arm::*;
    } else {
        pub use dynamic::*;
    }
}