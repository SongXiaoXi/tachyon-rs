pub mod soft;
pub mod dynamic;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub mod arm;

cfg_if::cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", target_feature = "aes"))] {
        pub use x86::*;
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "aes"))] {
        pub use arm::*;
    } else {
        #[cfg(not(feature = "disable_soft"))]
        pub use dynamic::*;
        #[allow(unused_imports)]
        #[cfg(feature = "disable_soft")]
        pub(crate) use dynamic::*;
    }
}