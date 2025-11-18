use super::soft;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "arm")]
use core::arch::arm::*;

#[inline(always)]
pub(crate) unsafe fn encode_block_neon(input: *const u8) -> uint8x16x4_t {
    let in_vec = vld3q_u8(input);
    let a = vshrq_n_u8(in_vec.0, 2);
    let b = vandq_u8(vsliq_n_u8(vshrq_n_u8(in_vec.1, 4), in_vec.0, 4), vdupq_n_u8(0x3F));
    let c = vandq_u8(vsliq_n_u8(vshrq_n_u8(in_vec.2, 6), in_vec.1, 2), vdupq_n_u8(0x3F));
    let d = vandq_u8(in_vec.2, vdupq_n_u8(0x3F));

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn lut(v: uint8x16_t) -> uint8x16_t {
        use super::LUT_DATA;
        let lut = vld1q_u8_x4(LUT_DATA.as_ptr());
        vqtbl4q_u8(lut, v)
    }
    #[cfg(target_arch = "arm")]
    #[inline(always)]
    unsafe fn lut(input: uint8x16_t) -> uint8x16_t {
        let mut result = vqsubq_u8(input, vdupq_n_u8(51));
        let less = vcgtq_u8(vdupq_n_u8(26), input);
        result = vorrq_u8(result, vandq_u8(less, vdupq_n_u8(13)));

        let lut_array: [u8; 16] = [
            71, 252, 252, 252,
            252, 252, 252, 252,
            252, 252, 252, 237,
            240, 65, 0, 0,
        ];

        let lut_lo = vld1_u8(lut_array.as_ptr());
        let lut_hi = vld1_u8(lut_array.as_ptr().add(8));
        let shift_lut = uint8x8x2_t(lut_lo, lut_hi);
        result = vcombine_u8(
            vtbl2_u8(shift_lut, vget_low_u8(result)),
            vtbl2_u8(shift_lut, vget_high_u8(result)),
        );

        vaddq_u8(result, input)
    }

    let out_a = lut(a);
    let out_b = lut(b);
    let out_c = lut(c);
    let out_d = lut(d);

    uint8x16x4_t(out_a, out_b, out_c, out_d)
}

#[target_feature(enable = "neon")]
pub unsafe fn encode_neon(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    let input_len = input.len();
    let output_len = output.len();
    let full_blocks = input_len / 3;
    let remaining_bytes = input_len % 3;
    let required_output_len = full_blocks * 4 + if remaining_bytes > 0 { 4 } else { 0 };

    if output_len < required_output_len {
        return Err(());
    }

    let neon_blocks = full_blocks / 16;

    let mut i = 0;
    // Apple CPUs have strong out-of-order execution capabilities that can get no benefit
    // from unrolling the loop twice. So we use a simpler loop for Apple targets.
    #[cfg(not(target_vendor = "apple"))]
    while i < (neon_blocks / 2) * 2 {
        let in_offset = i * 3 * 16;
        let out_offset = i * 4 * 16;
        let in_block0 = input.as_ptr().add(in_offset);
        let out_block0 = output.as_mut_ptr().add(out_offset);
        i += 1;

        let in_offset = i * 3 * 16;
        let out_offset = i * 4 * 16;
        let in_block1 = input.as_ptr().add(in_offset);
        let out_block1 = output.as_mut_ptr().add(out_offset);
        let out0 = encode_block_neon(in_block0);
        let out1 = encode_block_neon(in_block1);
        vst4q_u8(out_block0, out0);
        vst4q_u8(out_block1, out1);
        i += 1;
    }

    while i < neon_blocks {
        let in_offset = i * 3 * 16;
        let out_offset = i * 4 * 16;
        let in_block = input.as_ptr().add(in_offset);
        let out_block = output.as_mut_ptr().add(out_offset);
        let out = encode_block_neon(in_block);
        vst4q_u8(out_block, out);
        i += 1;
    }

    let processed_bytes = neon_blocks * 3 * 16;
    let remaining_input = &input[processed_bytes..];
    let remaining_output = &mut output[neon_blocks * 4 * 16..];
    // Process remaining full blocks with soft implementation
    let remaining_full_blocks = remaining_input.len() / 3;
    for i in 0..remaining_full_blocks {
        let in_offset = i * 3;
        let out_offset = i * 4;
        let in_block = unsafe { &*(remaining_input.as_ptr().add(in_offset) as *const [u8; 3]) };
        let out_block = unsafe { &mut *(remaining_output.as_mut_ptr().add(out_offset) as *mut [u8; 4]) };
        soft::encode_block(in_block, out_block);
    }
    let processed_remaining_bytes = remaining_full_blocks * 3;
    let final_input = &remaining_input[processed_remaining_bytes..];
    let final_output = &mut remaining_output[remaining_full_blocks * 4..];
    // Handle remaining bytes
    if !final_input.is_empty() {
        let mut in_block = [0u8; 3];
        for i in 0..final_input.len() {
            in_block[i] = final_input[i];
        }
        let mut out_block = [0u8; 4];
        soft::encode_block(&in_block, &mut out_block);
        // TODO: optimize final write
        for i in 0..(final_input.len() + 1) {
            final_output[i] = out_block[i];
        }
        for i in final_input.len()+1 .. 4 {
            final_output[i] = b'=';
        }
    }
    return Ok(required_output_len);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encode() {
        // Generate random input data with random lengths
        const TIMES: usize = 1000;
        for _ in 0..TIMES {
            let input_len = (rand::random::<u32>() % 1024) as usize;
            let mut input = vec![0u8; input_len];
            for byte in input.iter_mut() {
                *byte = rand::random::<u8>();
            }
            let mut output0 = vec![0u8; ((input_len + 2) / 3) * 4];
            let mut output1 = vec![0u8; ((input_len + 2) / 3) * 4];

            data_encoding::BASE64.encode_mut(&input, &mut output0);
            let expected_len = output0.len();
            let encoded_len = unsafe { encode_neon(&input, &mut output1).unwrap() };
            assert_eq!(expected_len, encoded_len);
            assert_eq!(&output0[0..expected_len], &output1[0..encoded_len]);
        }
    }
}