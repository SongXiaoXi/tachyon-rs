

#[inline(always)]
#[allow(asm_sub_register)]
pub unsafe fn copy_chunks_u32(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) {
    for i in (0..len).step_by(core::mem::size_of::<u32>()) {
        let mut value = core::ptr::read_unaligned(src.add(i) as *const u32);
        core::arch::asm!(
            "/* {value} */",
            value = inout(reg) value,
            options(pure, nomem, preserves_flags, nostack)
        );

        core::ptr::write_unaligned(dst.add(i) as *mut u32, value);
    }
}

#[inline(always)]
#[allow(asm_sub_register)]
pub unsafe fn copy_chunks_usize(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) {
    for i in (0..len).step_by(core::mem::size_of::<usize>()) {
        let mut value = core::ptr::read_unaligned(src.add(i) as *const usize);
        core::arch::asm!(
            "/* {value} */",
            value = inout(reg) value,
            options(pure, nomem, preserves_flags, nostack)
        );

        core::ptr::write_unaligned(dst.add(i) as *mut usize, value);
    }
}

#[inline(always)]
#[allow(asm_sub_register)]
pub unsafe fn fill_chunks_u8(
    dst: *mut u8,
    byte: u8,
    len: usize,
) {
    for i in 0..len {
        let mut value = byte;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        core::arch::asm!(
            "/* {value} */",
            value = inout(reg_byte) value,
            options(pure, nomem, preserves_flags, nostack)
        );
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        core::arch::asm!(
            "/* {value} */",
            value = inout(reg) value,
            options(pure, nomem, preserves_flags, nostack)
        );

        *dst.add(i) = value;
    }
}

#[inline(always)]
#[allow(asm_sub_register)]
pub(crate) unsafe fn fill_chunks_u32(
    dst: *mut u8,
    v: u32,
    len: usize,
) {
    for i in (0..len).step_by(core::mem::size_of::<u32>()) {
        let mut value = v;
        core::arch::asm!(
            "/* {value} */",
            value = inout(reg) value,
            options(pure, nomem, preserves_flags, nostack)
        );

        core::ptr::write_unaligned(dst.add(i) as *mut u32, value);
    }
}

#[inline(always)]
unsafe fn estimate_bandwidth_impl() -> f64 {
    let data_size: usize = 256 * 1024 * 1024;
    #[cfg(unix)]
    let page_size = (libc::sysconf(libc::_SC_PAGESIZE) as usize).max(4096);
    #[cfg(windows)]
    let page_size = 4096; // assuming a default page size of 4096 bytes on Windows

    let mut data_storage = crate::utils::Alloc::<u8>::new(data_size, page_size).unwrap();

    let mut data = data_storage.as_mut_ptr();
    // access data to make sure it is allocated
    for i in (0..data_size).step_by(page_size) {
        core::ptr::write(data.add(i), 1);
    }

    let mut sum: usize = 0;

    const SKIP: usize = 64;

    let start = std::time::Instant::now();
    for _ in 0..4 {
        for i in (0..data_size).step_by(16 * SKIP) {
            crate::const_loop!(j, 0, 16, {
                let v = std::ptr::read_unaligned(data.add(i + SKIP * j) as *const _);
                sum = sum.wrapping_add(v);
            });
        }
        data = std::hint::black_box(data);
    }
    let elapsed = start.elapsed();
    let elapsed_us = elapsed.as_micros() as f64;
    let bandwidth = (data_size as f64 * 1_000_000.0) / elapsed_us * 4.0;
    std::hint::black_box(sum);
    bandwidth
}

pub fn estimate_bandwidth() -> f64 {
    unsafe { estimate_bandwidth_impl() }
}