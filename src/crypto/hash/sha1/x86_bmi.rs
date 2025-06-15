#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::x86_sse::*;

#[derive(Clone, Copy)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha1 {
    sha1_define_const!();

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }
}

#[unsafe_target_feature::unsafe_target_feature("ssse3,avx,bmi1,bmi2")]
impl Sha1 {
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;

        if self.offset > 0 {
            while i < data.len() {
                if self.offset < Self::BLOCK_LEN {
                    unsafe { crate::utils::assume(i < data.len()) };
                    self.buffer[self.offset] = data[i];
                    self.offset += 1;
                    i += 1;
                }
                if self.offset == Self::BLOCK_LEN {
                    self.process_block();
                    self.offset = 0;
                    self.len += Self::BLOCK_LEN as u64;
                    break;
                }
            }
        }

        while i + Self::BLOCK_LEN <= data.len() {
            let block = unsafe { crate::utils::slice_to_array_at::<u8, 64>(data, i) };
            process_block_with!(self.state, block);
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            self.offset = remain;
            // SAFETY: remain is less than BLOCK_LEN
            unsafe {
                self.buffer.get_unchecked_mut(..remain).copy_from_slice(&data[i..]);
            }
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; 20] {
        let mlen = self.len + self.offset as u64; // in bytes
        let mlen_bits = mlen * 8; // in bits

        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert_eq!(
            (mlen + plen + Self::MLEN_SIZE as u64) % Self::BLOCK_LEN as u64,
            0
        );

        let plen = plen as usize;

        let mut padding: [u8; Self::MAX_PAD_LEN] = [0u8; Self::MAX_PAD_LEN];
        // Magic: black_box is used to prevent the compiler from using bzero
        std::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha1 = self;
        sha1.update(data);

        debug_assert_eq!(sha1.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&sha1.state[0].to_be_bytes());
        output[4..8].copy_from_slice(&sha1.state[1].to_be_bytes());
        output[8..12].copy_from_slice(&sha1.state[2].to_be_bytes());
        output[12..16].copy_from_slice(&sha1.state[3].to_be_bytes());
        output[16..20].copy_from_slice(&sha1.state[4].to_be_bytes());
        output
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 20] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline(always)]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; 64], &[u8; 64]>(&self.buffer) };
        process_block_with!(self.state, block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        if !(std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("ssse3") && std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("bmi1")) {
            return;
        }
        sha1_test_case!();
    }
}