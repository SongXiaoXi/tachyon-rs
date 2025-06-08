

use core::{cmp, mem};
use std::alloc::{self, handle_alloc_error, Layout};

pub(crate) struct Alloc<T> {
    ptr: *mut T,
    nelem: usize,
    align: usize,
}

impl<T> Alloc<T> {
    #[inline]
    pub unsafe fn new(nelem: usize, align: usize) -> Result<Self, std::alloc::LayoutError> {
        let align = cmp::max(align, mem::align_of::<T>());
        let layout = Layout::from_size_align(
            mem::size_of::<T>() * nelem,
            align
        )?;
        let ptr = alloc::alloc(layout);
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        Ok(Alloc {
            ptr: ptr as *mut T,
            nelem,
            align,
        })
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut T { self.ptr }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const T { self.ptr }

    #[inline(always)]
    pub fn align(&self) -> usize { self.align }

    #[inline(always)]
    pub fn is_null(&self) -> bool { self.ptr.is_null() }
}

impl<T> Drop for Alloc<T> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            let layout =
                Layout::from_size_align_unchecked(
                    mem::size_of::<T>() * self.nelem,
                    self.align
                );
            std::alloc::dealloc(self.ptr as _, layout);
        }
    }
}

impl<T> std::ops::Deref for Alloc<T> {
    type Target = [T];
    #[inline(always)]
    fn deref(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.nelem) }
    }
}

impl<T> std::ops::DerefMut for Alloc<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.nelem) }
    }
}