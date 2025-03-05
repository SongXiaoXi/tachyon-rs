pub(crate) mod xor;

#[cfg(feature = "variable_time_eq")]
#[inline(always)]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a == b
}
#[cfg(not(feature = "variable_time_eq"))]
#[inline(always)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut x = 0u8;

    for i in 0..a.len() {
        x |= a[i] ^ b[i];
    }

    x == 0
}
// detect hardware features everytimes
#[macro_export]
macro_rules! is_hw_feature_detected {
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
    ($($feat:tt),+) => {
        {
            let mut available = false;
            if cfg!(all($(target_feature = $feat),+)) {
                available = true;
            }
            if !available {
                #[allow(unused_mut)]
                #[allow(unused_assignments)]
                let mut available = false;
                $(
                    #[cfg(target_arch = $arch)]
                    {
                        available = true;
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
                    }
                )*
                available
            } else {
                true
            }
        }
    };
}

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
pub(crate) unsafe fn slice_to_array<T, const N: usize>(slice: &[T]) -> &[T; N] {
    &*(slice.as_ptr() as *const [T; N])
}
#[inline(always)]
pub(crate) unsafe fn slice_to_array_mut<T, const N: usize>(slice: &mut [T]) -> &mut [T; N] {
    &mut *(slice.as_mut_ptr() as *mut [T; N])
}
#[inline(always)]
pub(crate) unsafe fn slice_to_array_at<T, const N: usize>(slice: &[T], index: usize) -> &[T; N] {
    &*(slice.as_ptr().add(index) as *const [T; N])
}
#[inline(always)]
pub(crate) unsafe fn slice_to_array_at_mut<T, const N: usize>(slice: &mut [T], index: usize) -> &mut [T; N] {
    &mut *(slice.as_mut_ptr().add(index) as *mut [T; N])
}

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

#[inline(always)]
pub const unsafe fn unreachable() -> ! {
    unreachable!()
}

#[inline(always)]
pub const unsafe fn assume(b: bool) {
    if !b {
        // SAFETY: the caller must guarantee the argument is never `false`
        unreachable()
    }
}