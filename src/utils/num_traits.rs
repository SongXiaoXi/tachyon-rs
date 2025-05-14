use core::cmp::Ord;

pub(crate) trait ConstNum<T = usize> {
    const VALUE: T;
}

pub(crate) struct ConstUsize<const N: usize>;

impl<const N: usize> ConstNum for ConstUsize<N> {
    const VALUE: usize = N;
}

pub trait IntTraits: NumTraits + core::ops::BitAnd<Output = Self> + core::ops::BitOr<Output = Self> + core::ops::Not<Output = Self> + super::disjoint_bitor::DisjointBitOr {
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

        implement_min_max_for_int!($t);
    };
}

pub trait MinMax {
    fn min(self, rhs: Self) -> Self;
    fn max(self, rhs: Self) -> Self;
}

macro_rules! implement_min_max_for_int {
    ($t:ty) => {
        impl MinMax for $t {
            #[inline(always)]
            fn min(self, rhs: Self) -> Self { Ord::min(self, rhs) }
            #[inline(always)]
            fn max(self, rhs: Self) -> Self { Ord::max(self, rhs) }
        }
    };
}

macro_rules! implement_min_max_for_float {
    ($t:ty) => {
        impl MinMax for $t {
            #[inline(always)]
            fn min(self, rhs: Self) -> Self { self.min(rhs) }
            #[inline(always)]
            fn max(self, rhs: Self) -> Self { self.max(rhs) }
        }
    };
}

pub trait NumTraits: Copy + Send + Sync + MinMax {
    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;
    fn add(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;
    fn add_assign(&mut self, rhs: Self) { *self = self.add(rhs); }
    fn mul_assign(&mut self, rhs: Self) { *self = self.mul(rhs); }
}

macro_rules! implement_num_traits_for {
    ($t:ty) => {
        impl NumTraits for $t {
            #[inline(always)]
            fn zero() -> Self { 0 as $t }
            #[inline(always)]
            fn one() -> Self { 1 as $t }
            #[inline(always)]
            fn is_zero(&self) -> bool { *self == Self::zero() }
            #[inline(always)]
            fn add(self, rhs: Self) -> Self { self + rhs }
            #[inline(always)]
            fn sub(self, rhs: Self) -> Self { self - rhs }
            #[inline(always)]
            fn mul(self, rhs: Self) -> Self { self * rhs }
            #[inline(always)]
            fn add_assign(&mut self, rhs: Self) { *self += rhs; }
            #[inline(always)]
            fn mul_assign(&mut self, rhs: Self) { *self *= rhs; }
        }
    };
}

pub trait FmaTraits: Sized + Copy + Send + Sync {
    const IS_FUSED: bool = false;
    fn mul_add(self, a: Self, b: Self) -> Self;
    #[inline(always)]
    fn mul_add_assign(&mut self, a: Self, b: Self) {
        *self = self.mul_add(a, b);
    }
}

pub trait FloatTraits: NumTraits + FmaTraits {}

macro_rules! implement_float_traits_for {
    ($t:ty) => {
        impl FmaTraits for $t {
            const IS_FUSED: bool = true;
            #[inline(always)]
            fn mul_add(self, a: Self, b: Self) -> Self {
                self.mul_add(a, b)
            }
        }
        impl FloatTraits for $t {}
        implement_min_max_for_float!($t);
    };
}

implement_int_traits_for!(u8, i8, true);
implement_int_traits_for!(u16, i16, true);
implement_int_traits_for!(u32, i32, true);
implement_int_traits_for!(u64, i64, true);

implement_int_traits_for!(i8, i8, true);
implement_int_traits_for!(i16, i16, true);
implement_int_traits_for!(i32, i32, true);
implement_int_traits_for!(i64, i64, true);

implement_num_traits_for!(u8);
implement_num_traits_for!(u16);
implement_num_traits_for!(u32);
implement_num_traits_for!(u64);
implement_num_traits_for!(i8);
implement_num_traits_for!(i16);
implement_num_traits_for!(i32);
implement_num_traits_for!(i64);
implement_num_traits_for!(f32);
implement_num_traits_for!(f64);

implement_float_traits_for!(f32);
implement_float_traits_for!(f64);

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