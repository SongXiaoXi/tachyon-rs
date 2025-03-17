
/// Combine two values which have no bits in common.
/// 
/// # Safety
/// Requires that `(a & b) == 0`, or equivalently that `(a | b) == (a + b)`.
/// 
/// Otherwise it's immediate UB.
#[inline(always)]
pub unsafe fn disjoint_or<T: DisjointBitOr>(a: T, b: T) -> T {
    a.disjoint_bitor(b)
}

/// we just need the trait indirection to handle
/// different types since calling intrinsics with generics doesn't work.
pub trait DisjointBitOr: Copy + 'static {
    unsafe fn disjoint_bitor(self, other: Self) -> Self;
}

macro_rules! zero {
    (bool) => {
        false
    };
    ($t:ident) => {
        0
    };
}

macro_rules! impl_disjoint_bitor {
    ($($t:ident,)+) => {$(
        impl DisjointBitOr for $t {
            #[inline]
            unsafe fn disjoint_bitor(self, other: Self) -> Self {
                // Note that the assume here is required for UB detection in Miri!

                // SAFETY: our precondition is that there are no bits in common,
                // so this is just telling that to the backend.
                unsafe { crate::utils::assume((self & other) == zero!($t)) };
                self | other
            }
        }
    )+};
}

impl_disjoint_bitor! {
    bool,
    u8, u16, u32, u64, u128, usize,
    i8, i16, i32, i64, i128, isize,
}
