pub trait IntTraits: Copy + core::ops::BitAnd<Output = Self> + core::ops::BitOr<Output = Self> + core::ops::Not<Output = Self> + super::disjoint_bitor::DisjointBitOr {
    fn sign_bit(self) -> bool;
    #[inline(always)]
    fn merge_bits(self, b: Self, mask: Self) -> Self {
        super::merge_bits(self, b, mask)
    }
}

macro_rules! implement_int_traits_for {
    ($t:ty, $sign_type: ty, true) => {
        impl IntTraits for $t {
            /// Returns the sign bit of the integer.
            #[inline(always)]
            fn sign_bit(self) -> bool {
                (self as $sign_type).is_negative()
            }
        }
    };
}

implement_int_traits_for!(u8, i8, true);
implement_int_traits_for!(u16, i16, true);
implement_int_traits_for!(u32, i32, true);
implement_int_traits_for!(u64, i64, true);


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_bit() {
        assert_eq!(0u8.sign_bit(), false);
        assert_eq!(1u8.sign_bit(), false);
        assert_eq!(127u8.sign_bit(), false);
        assert_eq!(128u8.sign_bit(), true);
        assert_eq!(255u8.sign_bit(), true);

        assert_eq!(0u16.sign_bit(), false);
        assert_eq!(1u16.sign_bit(), false);
        assert_eq!(32767u16.sign_bit(), false);
        assert_eq!(32768u16.sign_bit(), true);
        assert_eq!(65535u16.sign_bit(), true);

        assert_eq!(0u32.sign_bit(), false);
        assert_eq!(1u32.sign_bit(), false);
        assert_eq!(2147483647u32.sign_bit(), false);
        assert_eq!(2147483648u32.sign_bit(), true);
        assert_eq!(4294967295u32.sign_bit(), true);

        assert_eq!(0u64.sign_bit(), false);
        assert_eq!(1u64.sign_bit(), false);
        assert_eq!(9223372036854775807u64.sign_bit(), false);
        assert_eq!(9223372036854775808u64.sign_bit(), true);
        assert_eq!(18446744073709551615u64.sign_bit(), true);
    }
}