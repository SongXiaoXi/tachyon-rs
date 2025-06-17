#[macro_use]
pub mod soft;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;

pub(crate) const PARALLEL_BLOCKS: usize = 4;

pub(crate) use soft::Chacha20Soft;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) use x86::Chacha20SSE;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) use x86::Chacha20AVX;
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub(crate) use soft::Chacha20Neon;

cfg_if::cfg_if!{
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx"))] {
        pub type Chacha20 = Chacha20AVX;
    } else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2"))] {
        pub type Chacha20 = Chacha20SSE;
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "neon"))] {
        pub type Chacha20 = Chacha20Neon;
    } else {
        pub type Chacha20 = Chacha20Soft;
    }
}