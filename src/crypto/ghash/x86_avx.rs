#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::x86::*;

x86_ghash_128_impl!("avx,pclmulqdq");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ghash() {
        if !crate::is_hw_feature_detected!("avx", "pclmulqdq") {
            return;
        }
        ghash_test_case!();
    }
}