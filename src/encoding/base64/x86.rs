use super::soft;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

/// Encode a block of 48 bytes (16 * 3) into 64 bytes (16 * 4) using SSE intrinsics.
/// target_feature: sse2, ssse3
#[inline(always)]
pub(crate) unsafe fn encode_block_sse(input: *const u8, output: *mut u8) {
    let input0 = _mm_loadu_si128(input as *const __m128i);
    let input1 = _mm_loadu_si128(input.add(16) as *const __m128i);
    let input2 = _mm_loadu_si128(input.add(32) as *const __m128i);

    let out0 = encode_kernel_sse(input0);
    let out1 = encode_kernel_sse(_mm_alignr_epi8(input1, input0, 12));
    let out2 = encode_kernel_sse(_mm_alignr_epi8(input2, input1, 8));
    let out3 = encode_kernel_sse(_mm_srli_si128(input2, 4));
    _mm_storeu_si128(output as *mut __m128i, out0);
    _mm_storeu_si128(output.add(16) as *mut __m128i, out1);
    _mm_storeu_si128(output.add(32) as *mut __m128i, out2);
    _mm_storeu_si128(output.add(48) as *mut __m128i, out3);
}

/// Encode a 12-byte input vector into a 16-byte output vector using SSE intrinsics.
/// target_feature: sse2, ssse3
#[inline(always)]
pub(crate) unsafe fn encode_kernel_sse(input: __m128i) -> __m128i {
    let shuf = _mm_set_epi8(10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1);
    let in_shuf = _mm_shuffle_epi8(input, shuf);
    let t0 = _mm_and_si128(in_shuf, _mm_set1_epi32(0x0fc0fc00));
    let t1 = _mm_mulhi_epu16(t0, _mm_set1_epi32(0x04000040));

    let t2 = _mm_and_si128(in_shuf, _mm_set1_epi32(0x003f03f0));
    let t3 = _mm_mullo_epi16(t2, _mm_set1_epi32(0x01000010));

    let indices = _mm_or_si128(t1, t3);

    #[inline(always)]
    unsafe fn lut(input: __m128i) -> __m128i {
        let mut result = _mm_subs_epu8(input, _mm_set1_epi8(51));
        let less = _mm_cmpgt_epi8(_mm_set1_epi8(26), input);
        result = _mm_or_si128(result, _mm_and_si128(less, _mm_set1_epi8(13)));
        let lut = _mm_setr_epi8(
            71, -4, -4, -4,
            -4, -4, -4, -4,
            -4, -4, -4, -19,
            -16, 65, 0, 0,
        );

        result = _mm_shuffle_epi8(lut, result);
        _mm_add_epi8(result, input)
    }

    lut(indices)
}

#[target_feature(enable = "sse2", enable = "ssse3")]
#[inline]
pub unsafe fn encode_sse(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    let input_len = input.len();
    let output_len = output.len();
    let full_blocks = input_len / 3;
    let remaining_bytes = input_len % 3;
    let required_output_len = full_blocks * 4 + if remaining_bytes > 0 { 4 } else { 0 };

    if output_len < required_output_len {
        return Err(());
    }

    let sse_blocks = full_blocks / 16;
    for i in 0..sse_blocks {
        let in_offset = i * 3 * 16;
        let out_offset = i * 4 * 16;
        let in_block = input.as_ptr().add(in_offset);
        let out_block = output.as_mut_ptr().add(out_offset);
        unsafe { encode_block_sse(in_block, out_block); }
    }

    let processed_bytes = sse_blocks * 3 * 16;
    let remaining_input = &input[processed_bytes..];
    let remaining_output = &mut output[sse_blocks * 4 * 16..];

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

    if !final_input.is_empty() {
        let mut in_block = [0u8; 3];
        for i in 0..final_input.len() {
            in_block[i] = final_input[i];
        }
        let mut out_block = [0u8; 4];
        soft::encode_block(&in_block, &mut out_block);
        for i in 0..(final_input.len() + 1) {
            final_output[i] = out_block[i];
        }
        for i in final_input.len()+1 .. 4 {
            final_output[i] = b'=';
        }
    }
    return Ok(required_output_len);
}

#[target_feature(enable = "avx", enable = "sse2", enable = "ssse3")]
pub unsafe fn encode_avx(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    // Fallback to SSE implementation for simplicity
    encode_sse(input, output)
}

/// Encode a 32-byte input vector into a  Forty-byte output vector using AVX2 intrinsics.
/// target_feature: avx2
#[inline(always)]
pub(crate) unsafe fn encode_kernel_avx2(input: __m256i) -> __m256i {
let shuf = _mm256_broadcastsi128_si256(_mm_set_epi8(10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1));
    let in_shuf = _mm256_shuffle_epi8(input, shuf);
    let t0 = _mm256_and_si256(in_shuf, _mm256_set1_epi32(0x0fc0fc00));
    let t1 = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x04000040));

    let t2 = _mm256_and_si256(in_shuf, _mm256_set1_epi32(0x003f03f0));
    let t3 = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x01000010));

    let indices = _mm256_or_si256(t1, t3);

    #[inline(always)]
    unsafe fn lut(input: __m256i) -> __m256i {
        let mut result = _mm256_subs_epu8(input, _mm256_set1_epi8(51));
        let less = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), input);
        result = _mm256_or_si256(result, _mm256_and_si256(less, _mm256_set1_epi8(13)));
        let lut = _mm256_broadcastsi128_si256(_mm_setr_epi8(
            71, -4, -4, -4,
            -4, -4, -4, -4,
            -4, -4, -4, -19,
            -16, 65, 0, 0,
        ));

        result = _mm256_shuffle_epi8(lut, result);
        _mm256_add_epi8(result, input)
    }

    lut(indices)
}

/// Encode a block of 96 bytes (32 * 3) into 128 bytes (32 * 4) using AVX2 intrinsics.
/// target_feature: avx2
#[inline(always)]
pub(crate) unsafe fn encode_block_avx2(input: *const u8, output: *mut u8) {
    let input0 = _mm256_loadu_si256(input as *const __m256i);
    let input1 = _mm256_loadu_si256(input.add(24) as *const __m256i);
    let input2 = _mm256_loadu_si256(input.add(48) as *const __m256i);
    let input3 = _mm256_loadu_si256(input.add(72) as *const __m256i);

    let input_shuf = _mm256_setr_epi32(0, 1, 2,0, 3, 4, 5, 6);

    let out0 = encode_kernel_avx2(_mm256_permutevar8x32_epi32(input0, input_shuf));
    let out1 = encode_kernel_avx2(_mm256_permutevar8x32_epi32(
        input1,
        input_shuf,
    ));
    let out2 = encode_kernel_avx2(_mm256_permutevar8x32_epi32(
        input2,
        input_shuf,
    ));
    let out3 = encode_kernel_avx2(_mm256_permutevar8x32_epi32(
        input3,
        input_shuf,
    ));
    _mm256_storeu_si256(output as *mut __m256i, out0);
    _mm256_storeu_si256(output.add(32) as *mut __m256i, out1);
    _mm256_storeu_si256(output.add(64) as *mut __m256i, out2);
    _mm256_storeu_si256(output.add(96) as *mut __m256i, out3);
}

#[target_feature(enable = "avx2")]
pub unsafe fn encode_avx2(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    let input_len = input.len();
    let output_len = output.len();
    let full_blocks = input_len / 3;
    let remaining_bytes = input_len % 3;
    let required_output_len = full_blocks * 4 + if remaining_bytes > 0 { 4 } else { 0 };

    if output_len < required_output_len {
        return Err(());
    }

    let avx_blocks = full_blocks / 32;
    for i in 0..avx_blocks {
        let in_offset = i * 3 * 32;
        let out_offset = i * 4 * 32;
        let in_block = input.as_ptr().add(in_offset);
        let out_block = output.as_mut_ptr().add(out_offset);
        unsafe { encode_block_avx2(in_block, out_block); }
    }

    let processed_bytes = avx_blocks * 3 * 32;
    let remaining_input = &input[processed_bytes..];
    let remaining_output = &mut output[avx_blocks * 4 * 32..];

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

    if !final_input.is_empty() {
        let mut in_block = [0u8; 3];
        for i in 0..final_input.len() {
            in_block[i] = final_input[i];
        }
        let mut out_block = [0u8; 4];
        soft::encode_block(&in_block, &mut out_block);
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
    fn test_sse() {
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
        
            let encoded_len = unsafe { encode_sse(&input, &mut output1).unwrap() };
            assert_eq!(expected_len, encoded_len);
            assert_eq!(&output0[0..expected_len], &output1[0..encoded_len]);
        }
    }
    fn test_avx2() {
        const TIMES: usize = 1000;
        for _ in 0..TIMES {
            let input_len = (rand::random::<u32>() % 2048) as usize;
            let mut input = vec![0u8; input_len];
            for byte in input.iter_mut() {
                *byte = rand::random::<u8>();
            }
            let mut output0 = vec![0u8; ((input_len + 2) / 3) * 4];
            let mut output1 = vec![0u8; ((input_len + 2) / 3) * 4];

            data_encoding::BASE64.encode_mut(&input, &mut output0);
            let expected_len = output0.len();
        
            let encoded_len = unsafe { encode_avx2(&input, &mut output1).unwrap() };
            assert_eq!(expected_len, encoded_len);
            assert_eq!(&output0[0..expected_len], &output1[0..encoded_len]);
        }
    }
    #[test]
    fn test_encode() {
        if is_x86_feature_detected!("avx2") {
            test_avx2();
        } else if is_x86_feature_detected!("sse2") && is_x86_feature_detected!("ssse3") {
            test_sse();
        } else {
            panic!("No suitable CPU features detected for testing x86 base64 encoding");
        }
    }
}