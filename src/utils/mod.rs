pub(crate) mod portable;
pub(crate) mod alloc;
mod cpu_name;

pub use cpu_name::cpu_name;
pub(crate) use alloc::Alloc;

mod disjoint_bitor;
pub(crate) mod num_traits;
mod bench;

pub use disjoint_bitor::disjoint_or;
pub(crate) use num_traits::IntTraits;

pub mod black_box;
pub use black_box::black_box;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(feature = "variable_time_eq")]
#[inline(always)]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a == b
}
#[cfg(not(feature = "variable_time_eq"))]
#[inline(always)]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut x = 0u8;

    for i in 0..a.len() {
        x |= a[i] ^ b[i];
    }

    x == 0
}

#[cfg(feature = "variable_time_eq")]
#[inline(always)]
pub(crate) fn constant_time_is_zero(a: &[u8]) -> bool {
    a.iter().all(|&x| x == 0)
}

#[cfg(not(feature = "variable_time_eq"))]
#[inline(always)]
pub(crate) fn constant_time_is_zero(a: &[u8]) -> bool {
    let mut x = 0u8;

    for i in 0..a.len() {
        x |= a[i];
    }

    x == 0
}

/// detect hardware features every time
#[macro_export]
macro_rules! is_hw_feature_detected {
    ($($arch:tt => ($($arch_feat:tt),+)),+$(,)?) => {
        {
            let mut available = false;
            $(
                if cfg!(target_arch = $arch) {
                    if cfg!(all($(target_feature = $arch_feat),+)) {
                        available = true;
                    }
                }
            )+
            if !available {
                #[allow(unused_mut)]
                #[allow(unused_assignments)]
                let mut available = false;
                $(
                    #[cfg(target_arch = $arch)]
                    {
                        available = true;
                        $(
                            #[cfg(any(target_arch = "x86"))]
                            if !is_x86_feature_detected!($arch_feat) {
                                available = false;
                            }
                            #[cfg(any(target_arch = "x86_64"))]
                            if !is_x86_feature_detected!($arch_feat) {
                                available = false;
                            }
                            #[cfg(all(target_arch = "aarch64"))]
                            {
                                use std::arch::is_aarch64_feature_detected;
                                if !is_aarch64_feature_detected!($arch_feat) {
                                    available = false;
                                }
                            }
                            #[cfg(all(target_arch = "arm"))]
                            {
                                use std::arch::is_arm_feature_detected;
                                if !is_arm_feature_detected!($arch_feat) {
                                    available = false;
                                }
                            }
                        )+
                    }
                )+
                available
            } else {
                true
            }
        }
    };
    ($($feat:tt),+$(,)?) => {
        {
            let mut available = false;
            if cfg!(all($(target_feature = $feat),+)) {
                available = true;
            }
            if !available {
                #[allow(unused_mut)]
                #[allow(unused_assignments)]
                let mut available = cfg!(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"));
                {
                    $(
                        #[cfg(any(target_arch = "x86"))]
                        if !is_x86_feature_detected!($feat) {
                            available = false;
                        }
                        #[cfg(any(target_arch = "x86_64"))]
                        if !is_x86_feature_detected!($feat) {
                            available = false;
                        }
                        #[cfg(all(target_arch = "aarch64"))]
                        {
                            use std::arch::is_aarch64_feature_detected;
                            if !is_aarch64_feature_detected!($feat) {
                                available = false;
                            }
                        }
                        #[cfg(all(target_arch = "arm"))]
                        {
                            use std::arch::is_arm_feature_detected;
                            if !is_arm_feature_detected!($feat) {
                                available = false;
                            }
                        }
                    )+
                }
                available
            } else {
                true
            }
        }
    };
}

/// detect hardware features and cache the result
#[macro_export]
macro_rules! is_hw_feature_available {
    ($($arch:tt => ($($arch_feat:tt),+)),+) => {
        {
            let mut available = false;
            $(
                if cfg!(target_arch = $arch) {
                    if cfg!(all($(target_feature = $arch_feat),+)) {
                        available = true;
                    }
                }
            )+
            if !available {
                use core::sync::atomic::{AtomicBool, Ordering};
                static FEATURE_AVAILABLE: AtomicBool = AtomicBool::new(false);
                static INIT: AtomicBool = AtomicBool::new(false);

                if FEATURE_AVAILABLE.load(Ordering::Relaxed) {
                    true
                } else if INIT.load(Ordering::Relaxed) {
                    false
                } else {
                    #[allow(unused_mut)]
                    let mut available = false;
                    $(
                        #[cfg(target_arch = $arch)]
                        {
                            available = true;
                            $(
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                                if !is_x86_feature_detected!($arch_feat) {
                                    available = false;
                                }
                                #[cfg(all(target_arch = "aarch64"))]
                                {
                                    use std::arch::is_aarch64_feature_detected;
                                    if !is_aarch64_feature_detected!($arch_feat) {
                                        available = false;
                                    }
                                }
                                #[cfg(all(target_arch = "arm"))]
                                {
                                    use std::arch::is_arm_feature_detected;
                                    if !is_arm_feature_detected!($arch_feat) {
                                        available = false;
                                    }
                                }
                            )+
                        }
                    )+
                    INIT.store(true, Ordering::Relaxed);
                    FEATURE_AVAILABLE.store(available, Ordering::Relaxed);
                    available
                }
            } else {
                true
            }
        }
    };
    ($($feat:tt),+) => {
        {
            let mut available = false;
            if cfg!(all($(target_feature = $feat),+)) {
                available = true;
            }
            if !available {
                use core::sync::atomic::{AtomicBool, Ordering};
                static FEATURE_AVAILABLE: AtomicBool = AtomicBool::new(false);
                static INIT: AtomicBool = AtomicBool::new(false);

                if FEATURE_AVAILABLE.load(Ordering::Relaxed) {
                    true
                } else if INIT.load(Ordering::Relaxed) {
                    false
                } else {
                    let mut available = false;
                    $(
                        #[cfg(any(target_arch = "x86"))]
                        if !is_x86_feature_detected!($feat) {
                            available = false;
                        }
                        #[cfg(any(target_arch = "x86_64"))]
                        if !is_x86_feature_detected!($feat) {
                            available = false;
                        }
                        #[cfg(all(target_arch = "aarch64"))]
                        {
                            use std::arch::is_aarch64_feature_detected;
                            if !is_aarch64_feature_detected!($feat) {
                                available = false;
                            }
                        }
                        #[cfg(all(target_arch = "arm"))]
                        {
                            use std::arch::is_arm_feature_detected;
                            if !is_arm_feature_detected!($feat) {
                                available = false;
                            }
                        }
                    )*
                    INIT.store(true, Ordering::Relaxed);
                    FEATURE_AVAILABLE.store(available, Ordering::Relaxed);
                    available
                }
            } else {
                true
            }
        }
    };
}
#[inline(always)]
pub(crate) const unsafe fn slice_to_array<T, const N: usize>(slice: &[T]) -> &[T; N] {
    &*(slice.as_ptr() as *const [T; N])
}
#[inline(always)]
pub(crate) const unsafe fn slice_to_array_mut<T, const N: usize>(slice: &mut [T]) -> &mut [T; N] {
    &mut *(slice.as_mut_ptr() as *mut [T; N])
}
#[inline(always)]
pub(crate) const unsafe fn slice_to_array_at<T, const N: usize>(slice: &[T], index: usize) -> &[T; N] {
    &*(slice.as_ptr().add(index) as *const [T; N])
}
#[inline(always)]
pub(crate) const unsafe fn slice_to_array_at_mut<T, const N: usize>(slice: &mut [T], index: usize) -> &mut [T; N] {
    &mut *(slice.as_mut_ptr().add(index) as *mut [T; N])
}

/// Converts a size in bytes to a human-readable string. For benchmarking
pub fn human_readable_size(size: usize) -> String {
    let mut cal_size = size;
    let mut unit = 0;
    while cal_size >= 1024 {
        cal_size >>= 10;
        unit += 1;
    }
    let unit = match unit {
        0 => "B",
        1 => "KiB",
        2 => "MiB",
        3 => "GiB",
        4 => "TiB",
        5 => "PiB",
        6 => "EiB",
        7 => "ZiB",
        8 => "YiB",
        _ => {
            cal_size = size;
            "B"
        },
    };
    format!("{} {}", cal_size, unit)
}

#[cfg(debug_assertions)]
#[inline(always)]
pub const unsafe fn unreachable() -> ! {
    unreachable!()
}

#[cfg(not(debug_assertions))]
pub const unsafe fn unreachable() -> ! {
    core::hint::unreachable_unchecked()
}

/// Informs the optimizer that a condition is always true.
/// If the condition is false, the behavior is undefined.
#[inline(always)]
pub const unsafe fn assume(b: bool) {
    if !b {
        // SAFETY: the caller must guarantee the argument is never `false`
        unreachable()
    }
}

/// Bitwise merge two values using a mask. If the mask bit is set, the
/// corresponding bit in 'b' is used, otherwise the corresponding bit in 'a'
/// is used.
#[inline(always)]
pub fn merge_bits<T>(a: T, b: T, mask: T) -> T
where
    T: IntTraits,
{
    // (a & !mask) | (b & mask)
    // SAFETY: `mask` is disjoint with `!mask`
    unsafe {
        (a & !mask).disjoint_bitor(b & mask)
    }
}

/// Copies `len` bytes from `src` to `dst`. This is useful for small copies
/// where the compiler might optimize to a memcpy, which can be slower than
/// a simple loop. This is also useful for copying data that is not aligned
/// to the destination pointer. This function is unsafe because it does not
/// check for alignment or out-of-bounds access.
#[inline(always)]
#[allow(asm_sub_register)]
pub unsafe fn copy_chunks_u8(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) {
    for i in 0..len {
        let byte = crate::utils::black_box(*src.add(i));
        *dst.add(i) = byte;
    }
}

pub use crate::memory::*;