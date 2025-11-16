mod soft;

static LUT_DATA: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode input bytes into base64 and write to output slice.
/// Returns the number of bytes written to output slice, or Err(()) if output slice is too small.
/// The output slice is never read in this function, so it is safe to pass uninitialized memory.
pub fn encode_slice(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
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