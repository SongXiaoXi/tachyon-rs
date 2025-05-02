#[cfg(target_arch = "arm")]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
use unsafe_target_feature::unsafe_target_feature;

// The round constant word array.
const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// Forward S-Box
const FORWARD_S_BOX: [u8; 256] = [
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[inline(always)]
fn sub_word(x: u32) -> u32 {
    // SubWord([b0, b1, b2, b3]) = [ SubByte(b0), SubByte(b1), SubByte(b2), SubByte(b3) ]
    let mut bytes = x.to_le_bytes();
    bytes[0] = FORWARD_S_BOX[bytes[0] as usize];
    bytes[1] = FORWARD_S_BOX[bytes[1] as usize];
    bytes[2] = FORWARD_S_BOX[bytes[2] as usize];
    bytes[3] = FORWARD_S_BOX[bytes[3] as usize];
    u32::from_le_bytes(bytes)
}

#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon,aes"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v8,neon,aes"))]
#[inline(always)]
fn load_key_128(k: &mut [uint8x16_t; 20], key: &[u8; 16]) {
    use std::mem::transmute;
    unsafe {
        let mut ek: [u32; 44] = [0u32; 44];

            let k1: [u32; 4] = transmute(vld1q_u32(key.as_ptr() as *const u32));
            ek[0] = k1[0];
            ek[1] = k1[1];
            ek[2] = k1[2];
            ek[3] = k1[3];

            ek[4] = ek[0] ^ (sub_word(ek[3]).rotate_left(24) ^ RCON[0]);
            ek[5] = ek[1] ^ ek[4];
            ek[6] = ek[2] ^ ek[5];
            ek[7] = ek[3] ^ ek[6];

            ek[8] = ek[4] ^ (sub_word(ek[7]).rotate_left(24) ^ RCON[1]);
            ek[9] = ek[5] ^ ek[8];
            ek[10] = ek[6] ^ ek[9];
            ek[11] = ek[7] ^ ek[10];

            ek[12] = ek[8] ^ (sub_word(ek[11]).rotate_left(24) ^ RCON[2]);
            ek[13] = ek[9] ^ ek[12];
            ek[14] = ek[10] ^ ek[13];
            ek[15] = ek[11] ^ ek[14];

            ek[16] = ek[12] ^ (sub_word(ek[15]).rotate_left(24) ^ RCON[3]);
            ek[17] = ek[13] ^ ek[16];
            ek[18] = ek[14] ^ ek[17];
            ek[19] = ek[15] ^ ek[18];

            ek[20] = ek[16] ^ (sub_word(ek[19]).rotate_left(24) ^ RCON[4]);
            ek[21] = ek[17] ^ ek[20];
            ek[22] = ek[18] ^ ek[21];
            ek[23] = ek[19] ^ ek[22];

            ek[24] = ek[20] ^ (sub_word(ek[23]).rotate_left(24) ^ RCON[5]);
            ek[25] = ek[21] ^ ek[24];
            ek[26] = ek[22] ^ ek[25];
            ek[27] = ek[23] ^ ek[26];

            ek[28] = ek[24] ^ (sub_word(ek[27]).rotate_left(24) ^ RCON[6]);
            ek[29] = ek[25] ^ ek[28];
            ek[30] = ek[26] ^ ek[29];
            ek[31] = ek[27] ^ ek[30];

            ek[32] = ek[28] ^ (sub_word(ek[31]).rotate_left(24) ^ RCON[7]);
            ek[33] = ek[29] ^ ek[32];
            ek[34] = ek[30] ^ ek[33];
            ek[35] = ek[31] ^ ek[34];

            ek[36] = ek[32] ^ (sub_word(ek[35]).rotate_left(24) ^ RCON[8]);
            ek[37] = ek[33] ^ ek[36];
            ek[38] = ek[34] ^ ek[37];
            ek[39] = ek[35] ^ ek[38];

            ek[40] = ek[36] ^ (sub_word(ek[39]).rotate_left(24) ^ RCON[9]);
            ek[41] = ek[37] ^ ek[40];
            ek[42] = ek[38] ^ ek[41];
            ek[43] = ek[39] ^ ek[42];

            let ptr = ek.as_ptr();

        crate::const_loop!(i, 0, 11, {
            k[i] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(i * 4)));
        });

        crate::const_loop!(i, 11, 9, {
            k[i] = vaesimcq_u8(k[20 - i]);
        });
    }
}

macro_rules! DO_ENC_BLOCK {
    ($block:expr, $key:expr) => {
        #[allow(unused_unsafe)]
        unsafe {
            $block = vaeseq_u8($block, $key[0]);
            crate::const_loop!(i, 1, 9, {
                $block = vaeseq_u8(vaesmcq_u8($block), $key[i]);
            });
            $block = veorq_u8($block, $key[10]);
        }
    };
}

macro_rules! DO_DEC_BLOCK {
    ($block:expr, $key:expr) => {
        #[allow(unused_unsafe)]
        unsafe {
            crate::const_loop!(i, 10, 9, {
                $block = vaesdq_u8($block, $key[i]);
                $block = vaesimcq_u8($block);
            });
            $block = vaesdq_u8($block, $key[19]);
            $block = veorq_u8($block, $key[0]);
        }
    };
}

#[derive(Clone, Copy)]
pub struct AES128 {
    key_schedule: [uint8x16_t; 20],
}

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    pub(crate) const IS_SOFT: bool = false;
}

#[cfg_attr(target_arch = "aarch64", unsafe_target_feature("neon,aes"))]
#[cfg_attr(target_arch = "arm", unsafe_target_feature("v8,neon,aes"))]
impl AES128 {
    #[inline(always)]
    pub fn new(key: [u8; 16]) -> Self {
        let mut key_schedule = [unsafe { core::mem::zeroed() }; 20];
        load_key_128(&mut key_schedule, &key);
        Self { key_schedule }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        Self::new(unsafe { *(key.as_ptr() as *const [u8; 16]) })
    }

    #[inline(always)]
    pub fn encrypt(&self, data: &mut [u8; 16]) {
        let mut block = unsafe { vld1q_u8(data.as_ptr()) };
        DO_ENC_BLOCK!(block, self.key_schedule);
        unsafe { vst1q_u8(data.as_mut_ptr(), block) };
    }

    #[inline(always)]
    pub fn encrypt_simd(&self, mut block: uint8x16_t) -> uint8x16_t {
        DO_ENC_BLOCK!(block, self.key_schedule);
        block
    }

    #[inline(always)]
    pub fn encrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        let mut block = unsafe { vld1q_u8(data.as_ptr()) };
        DO_ENC_BLOCK!(block, self.key_schedule);
        unsafe { vst1q_u8(output.as_mut_ptr(), block) };
    }

    #[inline(always)]
    pub fn decrypt(&self, data: &mut [u8; 16]) {
        let mut block = unsafe { vld1q_u8(data.as_ptr()) };
        DO_DEC_BLOCK!(block, self.key_schedule);
        unsafe { vst1q_u8(data.as_mut_ptr(), block) };
    }
    /*
    #[inline(always)]
    pub fn encrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        let mut block0 = unsafe { vld1q_u8(data0.as_ptr()) };
        let mut block1 = unsafe { vld1q_u8(data1.as_ptr()) };
        let mut block2 = unsafe { vld1q_u8(data2.as_ptr()) };
        let mut block3 = unsafe { vld1q_u8(data3.as_ptr()) };

        DO_ENC_BLOCK!(block0, self.key_schedule);
        DO_ENC_BLOCK!(block1, self.key_schedule);
        DO_ENC_BLOCK!(block2, self.key_schedule);
        DO_ENC_BLOCK!(block3, self.key_schedule);

        unsafe {
            vst1q_u8(data0.as_mut_ptr(), block0);
            vst1q_u8(data1.as_mut_ptr(), block1);
            vst1q_u8(data2.as_mut_ptr(), block2);
            vst1q_u8(data3.as_mut_ptr(), block3);
        }
    }*/
    
    #[inline(always)]
    pub(crate) fn encrypt_4_blocks_xor(&self, data0: &[u8; 16], data1: &[u8; 16], data2: &[u8; 16], data3: &[u8; 16], text0: &mut [u8; 16], text1: &mut [u8; 16], text2: &mut [u8; 16], text3: &mut [u8; 16]) {
        let mut block0 = unsafe { vld1q_u8(data0.as_ptr()) };
        let mut block1 = unsafe { vld1q_u8(data1.as_ptr()) };
        let mut block2 = unsafe { vld1q_u8(data2.as_ptr()) };
        let mut block3 = unsafe { vld1q_u8(data3.as_ptr()) };

        unsafe {
            crate::const_loop!(i, 0, 9, {
                block0 = vaesmcq_u8(vaeseq_u8(block0, self.key_schedule[i]));
                block1 = vaesmcq_u8(vaeseq_u8(block1, self.key_schedule[i]));
                block2 = vaesmcq_u8(vaeseq_u8(block2, self.key_schedule[i]));
                block3 = vaesmcq_u8(vaeseq_u8(block3, self.key_schedule[i]));
            });

            block0 = vaeseq_u8(block0, self.key_schedule[9]);
            block1 = vaeseq_u8(block1, self.key_schedule[9]);
            block2 = vaeseq_u8(block2, self.key_schedule[9]);
            block3 = vaeseq_u8(block3, self.key_schedule[9]);

            block0 = veorq_u8(block0, veorq_u8(self.key_schedule[10], vld1q_u8(text0.as_ptr())));
            block1 = veorq_u8(block1, veorq_u8(self.key_schedule[10], vld1q_u8(text1.as_ptr())));
            block2 = veorq_u8(block2, veorq_u8(self.key_schedule[10], vld1q_u8(text2.as_ptr())));
            block3 = veorq_u8(block3, veorq_u8(self.key_schedule[10], vld1q_u8(text3.as_ptr())));

            vst1q_u8(text0.as_mut_ptr(), block0);
            vst1q_u8(text1.as_mut_ptr(), block1);
            vst1q_u8(text2.as_mut_ptr(), block2);
            vst1q_u8(text3.as_mut_ptr(), block3);
        }
    }

    #[inline(always)]
    pub(crate) fn encrypt_6_blocks_xor(&self, data0: &[u8; 16], data1: &[u8; 16], data2: &[u8; 16], data3: &[u8; 16], data4: &[u8; 16], data5: &[u8; 16], text0: &mut [u8; 16], text1: &mut [u8; 16], text2: &mut [u8; 16], text3: &mut [u8; 16], text4: &mut [u8; 16], text5: &mut [u8; 16]) {
        let mut block0 = unsafe { vld1q_u8(data0.as_ptr()) };
        let mut block1 = unsafe { vld1q_u8(data1.as_ptr()) };
        let mut block2 = unsafe { vld1q_u8(data2.as_ptr()) };
        let mut block3 = unsafe { vld1q_u8(data3.as_ptr()) };
        let mut block4 = unsafe { vld1q_u8(data4.as_ptr()) };
        let mut block5 = unsafe { vld1q_u8(data5.as_ptr()) };

        unsafe {
            crate::const_loop!(i, 0, 9, {
                block0 = vaesmcq_u8(vaeseq_u8(block0, self.key_schedule[i]));
                block1 = vaesmcq_u8(vaeseq_u8(block1, self.key_schedule[i]));
                block2 = vaesmcq_u8(vaeseq_u8(block2, self.key_schedule[i]));
                block3 = vaesmcq_u8(vaeseq_u8(block3, self.key_schedule[i]));
                block4 = vaesmcq_u8(vaeseq_u8(block4, self.key_schedule[i]));
                block5 = vaesmcq_u8(vaeseq_u8(block5, self.key_schedule[i]));
            });

            block0 = vaeseq_u8(block0, self.key_schedule[9]);
            block1 = vaeseq_u8(block1, self.key_schedule[9]);
            block2 = vaeseq_u8(block2, self.key_schedule[9]);
            block3 = vaeseq_u8(block3, self.key_schedule[9]);
            block4 = vaeseq_u8(block4, self.key_schedule[9]);
            block5 = vaeseq_u8(block5, self.key_schedule[9]);

            block0 = veorq_u8(block0, veorq_u8(self.key_schedule[10], vld1q_u8(text0.as_ptr())));
            block1 = veorq_u8(block1, veorq_u8(self.key_schedule[10], vld1q_u8(text1.as_ptr())));
            block2 = veorq_u8(block2, veorq_u8(self.key_schedule[10], vld1q_u8(text2.as_ptr())));
            block3 = veorq_u8(block3, veorq_u8(self.key_schedule[10], vld1q_u8(text3.as_ptr())));
            block4 = veorq_u8(block4, veorq_u8(self.key_schedule[10], vld1q_u8(text4.as_ptr())));
            block5 = veorq_u8(block5, veorq_u8(self.key_schedule[10], vld1q_u8(text5.as_ptr())));

            vst1q_u8(text0.as_mut_ptr(), block0);
            vst1q_u8(text1.as_mut_ptr(), block1);
            vst1q_u8(text2.as_mut_ptr(), block2);
            vst1q_u8(text3.as_mut_ptr(), block3);
            vst1q_u8(text4.as_mut_ptr(), block4);
            vst1q_u8(text5.as_mut_ptr(), block5);
        }
    }

    #[inline(always)]
    pub(crate) fn encrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        let mut block0 = unsafe { vld1q_u8(data0.as_ptr()) };
        let mut block1 = unsafe { vld1q_u8(data1.as_ptr()) };
        let mut block2 = unsafe { vld1q_u8(data2.as_ptr()) };
        let mut block3 = unsafe { vld1q_u8(data3.as_ptr()) };

        unsafe {
            crate::const_loop!(i, 0, 9, {
                block0 = vaesmcq_u8(vaeseq_u8(block0, self.key_schedule[i]));
                block1 = vaesmcq_u8(vaeseq_u8(block1, self.key_schedule[i]));
                block2 = vaesmcq_u8(vaeseq_u8(block2, self.key_schedule[i]));
                block3 = vaesmcq_u8(vaeseq_u8(block3, self.key_schedule[i]));
            });

            block0 = vaeseq_u8(block0, self.key_schedule[9]);
            block1 = vaeseq_u8(block1, self.key_schedule[9]);
            block2 = vaeseq_u8(block2, self.key_schedule[9]);
            block3 = vaeseq_u8(block3, self.key_schedule[9]);

            block0 = veorq_u8(block0, self.key_schedule[10]);
            block1 = veorq_u8(block1, self.key_schedule[10]);
            block2 = veorq_u8(block2, self.key_schedule[10]);
            block3 = veorq_u8(block3, self.key_schedule[10]);

            vst1q_u8(data0.as_mut_ptr(), block0);
            vst1q_u8(data1.as_mut_ptr(), block1);
            vst1q_u8(data2.as_mut_ptr(), block2);
            vst1q_u8(data3.as_mut_ptr(), block3);
        }
    }

    #[inline(always)]
    pub fn decrypt_4_blocks(&self, data0: &mut [u8; 16], data1: &mut [u8; 16], data2: &mut [u8; 16], data3: &mut [u8; 16]) {
        let mut block0 = unsafe { vld1q_u8(data0.as_ptr()) };
        let mut block1 = unsafe { vld1q_u8(data1.as_ptr()) };
        let mut block2 = unsafe { vld1q_u8(data2.as_ptr()) };
        let mut block3 = unsafe { vld1q_u8(data3.as_ptr()) };

        unsafe {
            crate::const_loop!(i, 10, 9, {
                block0 = vaesimcq_u8(vaesdq_u8(block0, self.key_schedule[i]));
                block1 = vaesimcq_u8(vaesdq_u8(block1, self.key_schedule[i]));
                block2 = vaesimcq_u8(vaesdq_u8(block2, self.key_schedule[i]));
                block3 = vaesimcq_u8(vaesdq_u8(block3, self.key_schedule[i]));
            });

            block0 = vaesdq_u8(block0, self.key_schedule[19]);
            block1 = vaesdq_u8(block1, self.key_schedule[19]);
            block2 = vaesdq_u8(block2, self.key_schedule[19]);
            block3 = vaesdq_u8(block3, self.key_schedule[19]);
            block0 = veorq_u8(block0, self.key_schedule[0]);
            block1 = veorq_u8(block1, self.key_schedule[0]);
            block2 = veorq_u8(block2, self.key_schedule[0]);
            block3 = veorq_u8(block3, self.key_schedule[0]);

            vst1q_u8(data0.as_mut_ptr(), block0);
            vst1q_u8(data1.as_mut_ptr(), block1);
            vst1q_u8(data2.as_mut_ptr(), block2);
            vst1q_u8(data3.as_mut_ptr(), block3);
        }
    }

    #[inline(always)]
    pub fn decrypt_copy(&self, data: &[u8; 16], output: &mut [u8; 16]) {
        let mut block = unsafe { vld1q_u8(data.as_ptr()) };
        DO_DEC_BLOCK!(block, self.key_schedule);
        unsafe { vst1q_u8(output.as_mut_ptr(), block) };
    }

    #[inline(always)]
    pub fn decrypt_simd(&self, mut block: uint8x16_t) -> uint8x16_t {
        DO_DEC_BLOCK!(block, self.key_schedule);
        block
    }
    // data must be a slice of 16 bytes
    #[inline(always)]
    pub fn decrypt_slice(&self, data: &mut [u8]) {
        assert_eq!(data.len() % 16, 0);
        let mut chunks = data.chunks_exact_mut(16 * 4);
        for chunk in &mut chunks {
            let block0 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 0) };
            let block0 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block0) };
            let block1 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 1) };
            let block1 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block1) };
            let block2 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 2) };
            let block2 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block2) };
            let block3 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 3) };
            let block3 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block3) };

            self.decrypt_4_blocks(block0, block1, block2, block3);
        }

        for chunk in chunks.into_remainder().chunks_exact_mut(16) {
            let mut block = unsafe { crate::utils::slice_to_array_mut(chunk) };
            self.decrypt(&mut block);
        }
    }
    // data must be a slice of 16 bytes
    #[inline(always)]
    pub fn encrypt_slice(&self, data: &mut [u8]) {
        assert_eq!(data.len() % 16, 0);
        let mut chunks = data.chunks_exact_mut(16 * 4);
        for chunk in &mut chunks {
            let block0 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 0) };
            let block0 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block0) };
            let block1 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 1) };
            let block1 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block1) };
            let block2 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 2) };
            let block2 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block2) };
            let block3 = unsafe { crate::utils::slice_to_array_at_mut(chunk, 3) };
            let block3 = unsafe { std::mem::transmute::<&mut [u8; 16], _>(block3) };

            self.encrypt_4_blocks(block0, block1, block2, block3);
        }

        for chunk in chunks.into_remainder().chunks_exact_mut(16) {
            let mut block = unsafe { crate::utils::slice_to_array_mut(chunk) };
            self.encrypt(&mut block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "arm")]
    use std::arch::is_arm_feature_detected as is_target_feature_detected;
    #[cfg(target_arch = "aarch64")]
    use std::arch::is_aarch64_feature_detected as is_target_feature_detected;

    #[test]
    fn test_aes128() {
        if !is_target_feature_detected!("aes") {
            return;
        }
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let cipher = AES128::new(key);

        let mut data = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        cipher.encrypt(&mut data);
        assert_eq!(data, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);

        let mut data = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        cipher.decrypt(&mut data);
        assert_eq!(data, [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]);
    }
}