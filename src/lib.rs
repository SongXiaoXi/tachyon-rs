#![cfg_attr(feature = "nightly", feature(cfg_version))]
#![cfg_attr(feature = "nightly", cfg_attr(not(version("1.75.0")), feature(stdsimd)))]
#![cfg_attr(target_arch = "arm", cfg_attr(version("1.75.0"), feature(stdarch_arm_neon_intrinsics)))]
#![cfg_attr(feature = "nightly", cfg_attr(not(version("1.75.0")), feature(const_mut_refs)))]
#![allow(dead_code)]
#![cfg_attr(feature = "nightly", feature(arm_target_feature))]
#![cfg_attr(feature = "nightly", cfg_attr(target_arch = "aarch64", feature(stdarch_aarch64_feature_detection)))]
#![cfg_attr(feature = "nightly", cfg_attr(target_arch = "aarch64", feature(aarch64_unstable_target_feature)))]
#![cfg_attr(feature = "nightly", cfg_attr(version("1.75.0"), cfg_attr(target_arch = "arm", feature(stdarch_arm_feature_detection))))]

pub mod crypto;
pub mod string;
pub mod utils;

pub use tachyon_macros::*;

/// A utility function for creating masks to use with Intel shuffle and
/// permute intrinsics.
#[inline(always)]
#[allow(non_snake_case)]
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub const fn _MM_SHUFFLE(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

#[macro_export]
macro_rules! const_loop4 {
    ($i:ident, $e:expr) => {{
        crate::const_loop!($i, 0, 4, {$e});
    }};
    ($i:ident, $start:expr, $e:expr) => {{
        crate::const_loop!($i, $start, 4, {$e});
    }};
}

#[macro_export]
macro_rules! const_loop8 {
    ($i:ident, $e:expr) => {{
        crate::const_loop!($i, 0, 8, {$e});
    }};
    ($i:ident, $start:expr, $e:expr) => {{
        crate::const_loop!($i, $start, 8, {$e});
    }};
}

#[macro_export]
macro_rules! unroll_by {
    ($by:tt => $ntimes:expr, $i:ident, $e:expr) => {{
        let mut _k = $ntimes;
        while _k >= $by {
            crate::const_loop!($i, 0, $by, {$e});
            _k -= $by;
        }
        while _k > 0 {
            #[allow(unused)]
            let $i = 0;
            $e;
            _k -= 1;
        }
    }};
    ($by:tt => $ntimes:expr, $e:expr) => {{
        let mut _k = $ntimes;
        while _k >= $by {
            crate::const_loop!(_, 0, $by, {$e});
            _k -= $by;
        }
        while _k > 0 {
            $e;
            _k -= 1;
        }
    }};
    (1 => $ntimes:expr, $e:expr) => {{
        let mut _k = $ntimes;
        while _k > 0 {
            $e;
            _k -= 1;
        }
    }};
}