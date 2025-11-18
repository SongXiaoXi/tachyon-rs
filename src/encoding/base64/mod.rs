#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod x86;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod arm;
mod soft;

static LUT_DATA: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode input bytes into base64 and write to output slice.
/// Returns the number of bytes written to output slice, or Err(()) if output slice is too small.
/// The output slice is never read in this function, so it is safe to pass uninitialized memory.
#[allow(unreachable_code)]
pub fn encode_slice(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {

    #[cfg(target_arch = "aarch64")]
    unsafe {
        return arm::encode_neon(input, output);
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        static mut METHOD_IDX: u32 = u32::MAX; // 0: soft, 1: neon
        if METHOD_IDX == u32::MAX {
            if std::arch::is_arm_feature_detected!("neon") {
                METHOD_IDX = 1;
            } else {
                METHOD_IDX = 0;
            }
        }
        if METHOD_IDX == 1 {
            return arm::encode_neon(input, output);
        }
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    unsafe {
        static mut METHOD_IDX: u32 = u32::MAX; // 0: soft, 1: sse, 2: avx, 3: avx2

        if METHOD_IDX == u32::MAX {
            if std::arch::is_x86_feature_detected!("sse2") && std::arch::is_x86_feature_detected!("ssse3") {
                METHOD_IDX = 1;
                if std::arch::is_x86_feature_detected!("avx") {
                    METHOD_IDX = 2;
                    if std::arch::is_x86_feature_detected!("avx2") {
                        METHOD_IDX = 3;
                    }
                }
            } else {
                METHOD_IDX = 0;
            }
        }
        match METHOD_IDX {
            3 => return x86::encode_avx2(input, output),
            2 => return x86::encode_avx(input, output),
            1 => return x86::encode_sse(input, output),
            _ => {}
        }
    }
    return soft::encode(input, output);
}

pub fn encode(input: &[u8]) -> String {
    let output_len = (input.len() + 2) / 3 * 4;
    let mut output = Vec::with_capacity(output_len);
    unsafe {
        output.set_len(output_len);
    }
    let _ = encode_slice(input, &mut output).unwrap();
    unsafe { String::from_utf8_unchecked(output) }
}