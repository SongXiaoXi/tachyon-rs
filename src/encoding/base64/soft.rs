use super::LUT_DATA;


#[inline(always)]
pub(crate) fn encode_block(input: &[u8; 3], output: &mut [u8; 4]) {
    let b0 = input[0];
    let b1 = input[1];
    let b2 = input[2];

    let i0 = (b0 >> 2) & 0x3F;
    let i1 = ((b0 << 4) | (b1 >> 4)) & 0x3F;
    let i2 = ((b1 << 2) | (b2 >> 6)) & 0x3F;
    let i3 = b2 & 0x3F;

    output[0] = LUT_DATA[i0 as usize];
    output[1] = LUT_DATA[i1 as usize];
    output[2] = LUT_DATA[i2 as usize];
    output[3] = LUT_DATA[i3 as usize];
}

pub fn encode(input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    let input_len = input.len();
    let output_len = output.len();
    let full_blocks = input_len / 3;
    let remaining_bytes = input_len % 3;
    let required_output_len = full_blocks * 4 + if remaining_bytes > 0 { 4 } else { 0 };

    if output_len < required_output_len {
        return Err(());
    }

    for i in 0..full_blocks {
        let in_offset = i * 3;
        let out_offset = i * 4;
        let in_block = unsafe { &*(input.as_ptr().add(in_offset) as *const [u8; 3]) };
        let out_block = unsafe { &mut *(output.as_mut_ptr().add(out_offset) as *mut [u8; 4]) };
        encode_block(in_block, out_block);
    }

    let processed_bytes = full_blocks * 3;
    let remaining_input = &input[processed_bytes..];
    let remaining_output = &mut output[full_blocks * 4..];

    if !remaining_input.is_empty() {
        let mut in_block = [0u8; 3];
        for i in 0..remaining_input.len() {
            in_block[i] = remaining_input[i];
        }
        let mut out_block = [0u8; 4];
        encode_block(&in_block, &mut out_block);
        // TODO: optimize final write
        for i in 0..(remaining_input.len() + 1) {
            remaining_output[i] = out_block[i];
        }
        for i in remaining_input.len()+1 .. 4 {
            remaining_output[i] = b'=';
        }
    }

    Ok(required_output_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_encode() {
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
            
            let encoded_len = encode(&input, &mut output1).unwrap();
            assert_eq!(expected_len, encoded_len);
            assert_eq!(&output0[0..encoded_len], &output1[0..encoded_len]);
        }
    }
}