pub mod soft;

cfg_if::cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))] {
        mod x86;
        pub use x86::*;
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "aes"))] {
        mod arm;
        pub use arm::*;
    } else {
        pub use soft::*;
    }
}