#[macro_use]
pub mod soft;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[macro_use]
pub mod x86_ssse3;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_avx;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_avx2;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
pub mod x86_avx512;

#[cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))]
pub mod dynamic;

cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "aarch64", target_feature = "neon"))] {
        pub use aarch64::*;
    } else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx512f", avx512_feature))] {
        pub use x86_avx512::*;
    } else if #[cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))] {
        pub use dynamic::*;
    } else {
        pub use soft::*;
    }
}

// BLAKE3 IV
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;

#[inline(always)]
fn u32x8_from_le_bytes(bytes: &[u8; 32]) -> [u32; 8] {
    let mut m = [0u32; 8];
    m[0] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    m[1] = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    m[2] = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    m[3] = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    m[4] = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    m[5] = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    m[6] = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    m[7] = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    m
}

#[inline(always)]
fn u32x16_from_le_bytes(bytes: &[u8; 64]) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[0] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    m[1] = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    m[2] = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    m[3] = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    m[4] = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    m[5] = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    m[6] = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    m[7] = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    m[8] = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
    m[9] = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
    m[10] = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
    m[11] = u32::from_le_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]);
    m[12] = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]);
    m[13] = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]);
    m[14] = u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]);
    m[15] = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]);
    m
}

#[inline(always)]
fn u32x16_to_le_bytes(words: &[u32; 16]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
    bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
    bytes[8..12].copy_from_slice(&words[2].to_le_bytes());
    bytes[12..16].copy_from_slice(&words[3].to_le_bytes());
    bytes[16..20].copy_from_slice(&words[4].to_le_bytes());
    bytes[20..24].copy_from_slice(&words[5].to_le_bytes());
    bytes[24..28].copy_from_slice(&words[6].to_le_bytes());
    bytes[28..32].copy_from_slice(&words[7].to_le_bytes());
    bytes[32..36].copy_from_slice(&words[8].to_le_bytes());
    bytes[36..40].copy_from_slice(&words[9].to_le_bytes());
    bytes[40..44].copy_from_slice(&words[10].to_le_bytes());
    bytes[44..48].copy_from_slice(&words[11].to_le_bytes());
    bytes[48..52].copy_from_slice(&words[12].to_le_bytes());
    bytes[52..56].copy_from_slice(&words[13].to_le_bytes());
    bytes[56..60].copy_from_slice(&words[14].to_le_bytes());
    bytes[60..64].copy_from_slice(&words[15].to_le_bytes());
    bytes
}

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];