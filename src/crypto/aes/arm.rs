#[cfg(target_arch = "arm")]
use core::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

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

#[inline]
fn sub_word(x: u32) -> u32 {
    // SubWord([b0, b1, b2, b3]) = [ SubByte(b0), SubByte(b1), SubByte(b2), SubByte(b3) ]
    let mut bytes = x.to_le_bytes();
    bytes[0] = FORWARD_S_BOX[bytes[0] as usize];
    bytes[1] = FORWARD_S_BOX[bytes[1] as usize];
    bytes[2] = FORWARD_S_BOX[bytes[2] as usize];
    bytes[3] = FORWARD_S_BOX[bytes[3] as usize];
    u32::from_le_bytes(bytes)
}

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

            k[0] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(0)));
            k[1] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(4)));
            k[2] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(8)));
            k[3] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(12)));
            k[4] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(16)));
            k[5] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(20)));
            k[6] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(24)));
            k[7] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(28)));
            k[8] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(32)));
            k[9] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(36)));
            k[10] = vreinterpretq_u8_u32(vld1q_u32(ptr.add(40)));

            k[11] = vaesimcq_u8(k[9]);
            k[12] = vaesimcq_u8(k[8]);
            k[13] = vaesimcq_u8(k[7]);
            k[14] = vaesimcq_u8(k[6]);
            k[15] = vaesimcq_u8(k[5]);
            k[16] = vaesimcq_u8(k[4]);
            k[17] = vaesimcq_u8(k[3]);
            k[18] = vaesimcq_u8(k[2]);
            k[19] = vaesimcq_u8(k[1]);
    }
}

macro_rules! DO_ENC_BLOCK {
    ($block:expr, $key:expr) => {
        unsafe {
            $block = vaeseq_u8($block, $key[0]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[1]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[2]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[3]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[4]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[5]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[6]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[7]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[8]);
            $block = vaeseq_u8(vaesmcq_u8($block), $key[9]);
            $block = veorq_u8($block, $key[10]);
        }
    };
}

macro_rules! DO_DEC_BLOCK {
    ($block:expr, $key:expr) => {
        unsafe {
            $block = vaesdq_u8($block, $key[10]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[11]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[12]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[13]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[14]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[15]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[16]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[17]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[18]);
            $block = vaesimcq_u8($block);
            $block = vaesdq_u8($block, $key[19]);
            $block = veorq_u8($block, $key[0]);
        }
    };
}

#[derive(Clone)]
pub struct AES128 {
    key_schedule: [uint8x16_t; 20],
}

impl AES128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize = 16;
    #[inline(always)]
    pub fn new(key: &[u8; 16]) -> Self {
        let mut key_schedule = [unsafe { core::mem::zeroed() }; 20];
        load_key_128(&mut key_schedule, key);
        Self { key_schedule }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 16);
        Self::new(unsafe { &*(key.as_ptr() as *const [u8; 16]) })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let cipher = AES128::new(&key);

        let mut data = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        cipher.encrypt(&mut data);
        assert_eq!(data, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);

        let mut data = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        cipher.decrypt(&mut data);
        assert_eq!(data, [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]);
    }
}