pub trait BlackBox {
    /// Prevents the compiler from optimizing away the value of `x`.
    fn black_box(x: Self) -> Self;
}

macro_rules! black_box_impl {
    ($ty:ty, $reg:ident$(, $feature:literal)?) => {
        $(#[unsafe_target_feature::unsafe_target_feature($feature)])?
        impl BlackBox for $ty {
            #[inline(always)]
            #[allow(asm_sub_register)]
            fn black_box(mut x: $ty) -> $ty {
                unsafe {
                    core::arch::asm!(concat!("/* {x} */"), x = inout($reg) x, options(nomem, nostack, preserves_flags, pure));
                }
                x
            }
        }
    };
}
cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        black_box_impl!(u8, reg_byte);
        black_box_impl!(i8, reg_byte);
    } else {
        black_box_impl!(u8, reg);
        black_box_impl!(i8, reg);
    }
}

black_box_impl!(u16, reg);
black_box_impl!(u32, reg);
#[cfg(target_pointer_width = "64")]
black_box_impl!(u64, reg);
black_box_impl!(usize, reg);
black_box_impl!(i16, reg);
black_box_impl!(i32, reg);
#[cfg(target_pointer_width = "64")]
black_box_impl!(i64, reg);
black_box_impl!(isize, reg);

impl<T> BlackBox for *const T {
    #[inline(always)]
    fn black_box(mut x: *const T) -> *const T {
        unsafe {
            core::arch::asm!("/* {x} */", x = inout(reg) x, options(nomem, nostack, preserves_flags, pure));
        }
        x
    }
}

impl<T> BlackBox for *mut T {
    #[inline(always)]
    fn black_box(mut x: *mut T) -> *mut T {
        unsafe {
            core::arch::asm!("/* {x} */", x = inout(reg) x, options(nomem, nostack, preserves_flags, pure));
        }
        x
    }
}

impl<T> BlackBox for &T {
    #[inline(always)]
    fn black_box(x: &T) -> &T {
        core::hint::black_box(x)
    }
}

impl<T> BlackBox for &mut T {
    #[inline(always)]
    fn black_box(x: &mut T) -> &mut T {
        core::hint::black_box(x)
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        use core::arch::aarch64::*;
        black_box_impl!(uint8x16_t, vreg);
        black_box_impl!(uint16x8_t, vreg);
        black_box_impl!(uint32x4_t, vreg);
        black_box_impl!(uint64x2_t, vreg);

        black_box_impl!(uint8x8_t, vreg);
        black_box_impl!(uint16x4_t, vreg);
        black_box_impl!(uint32x2_t, vreg);
        black_box_impl!(uint64x1_t, vreg);

        black_box_impl!(int8x16_t, vreg);
        black_box_impl!(int16x8_t, vreg);
        black_box_impl!(int32x4_t, vreg);
        black_box_impl!(int64x2_t, vreg);

        black_box_impl!(int8x8_t, vreg);
        black_box_impl!(int16x4_t, vreg);
        black_box_impl!(int32x2_t, vreg);
        black_box_impl!(int64x1_t, vreg);

        black_box_impl!(float32x4_t, vreg);
        black_box_impl!(float64x2_t, vreg);
        black_box_impl!(float32x2_t, vreg);
        black_box_impl!(float64x1_t, vreg);
    } else if #[cfg(target_arch = "arm")] {
        use core::arch::arm::*;
        black_box_impl!(uint8x16_t, qreg, "neon");
        black_box_impl!(uint16x8_t, qreg, "neon");
        black_box_impl!(uint32x4_t, qreg, "neon");
        black_box_impl!(uint64x2_t, qreg, "neon");

        black_box_impl!(uint8x8_t, dreg, "neon");
        black_box_impl!(uint16x4_t, dreg, "neon");
        black_box_impl!(uint32x2_t, dreg, "neon");
        black_box_impl!(uint64x1_t, dreg, "neon");

        black_box_impl!(int8x16_t, qreg, "neon");
        black_box_impl!(int16x8_t, qreg, "neon");
        black_box_impl!(int32x4_t, qreg, "neon");
        black_box_impl!(int64x2_t, qreg, "neon");

        black_box_impl!(int8x8_t, dreg, "neon");
        black_box_impl!(int16x4_t, dreg, "neon");
        black_box_impl!(int32x2_t, dreg, "neon");
        black_box_impl!(int64x1_t, dreg, "neon");

        black_box_impl!(float32x4_t, qreg, "neon");
        black_box_impl!(float32x2_t, dreg, "neon");
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;
        black_box_impl!(__m128i, xmm_reg, "sse");
        black_box_impl!(__m256i, ymm_reg, "avx");
        black_box_impl!(__m128, xmm_reg, "sse");
        black_box_impl!(__m256, ymm_reg, "avx");
        black_box_impl!(__m128d, xmm_reg, "sse");
        black_box_impl!(__m256d, ymm_reg, "avx");

    }
}

#[inline(always)]
pub fn black_box<T>(x: T) -> T
where
    T: BlackBox,
{
    T::black_box(x)
}