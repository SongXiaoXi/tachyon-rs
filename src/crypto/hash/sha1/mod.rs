#[macro_use]
pub mod soft;
pub mod dynamic;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub mod arm_ni;

cfg_if::cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", target_feature = "sha"))] {
        pub use x86::*;
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "neon", target_feature = "sha2"))] {
        pub use arm_ni::*;
    } else {
        #[cfg(not(feature = "disable_dynamic_export"))]
        pub use dynamic::*;
        #[allow(unused_imports)]
        #[cfg(feature = "disable_dynamic_export")]
        pub(crate) use dynamic::*;
    }
}

const INITIAL_STATE: [u32; 5] = [
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
];