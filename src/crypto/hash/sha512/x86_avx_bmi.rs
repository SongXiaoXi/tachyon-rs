#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use super::x86_ssse3::process_block_with;

use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha512 {
    state: [u64; 8],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha512 {
    sha512_define_const!();

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 128],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("ssse3,avx,bmi1,bmi2")]
impl Sha512 {
    #[inline(always)]
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
                    self.offset = 0;
                    self.process_block();
                    self.len += Self::BLOCK_LEN as u64;
                    break;
                }
            }
        }
        while i + Self::BLOCK_LEN <= data.len() {
            let block = unsafe { crate::utils::slice_to_array_at::<_, { Self::BLOCK_LEN }>(data, i) };
            _mm_prefetch(block.as_ptr().add(128) as *const _, _MM_HINT_T0);
            _mm_prefetch(block.as_ptr().add(196) as *const _, _MM_HINT_T0);
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

    #[inline(always)]
    pub fn finalize(self) -> [u8; 64] {
        let mlen = self.len as u128 + self.offset as u128; // in bytes
        let mlen_bits = mlen * 8; // in bits

        // pad len, in bits
        let plen_bits = Self::BLOCK_LEN_BITS
            - (mlen_bits + Self::MLEN_SIZE_BITS + 1) % Self::BLOCK_LEN_BITS
            + 1;
        // pad len, in bytes
        let plen = plen_bits / 8;
        debug_assert_eq!(plen_bits % 8, 0);
        debug_assert_eq!(
            (mlen + plen + Self::MLEN_SIZE as u128) % Self::BLOCK_LEN as u128,
            0
        );

        let plen = plen as usize;

        let mut padding: [u8; Self::MAX_PAD_LEN] = [0u8; Self::MAX_PAD_LEN];
        // Magic: black_box is used to prevent the compiler from using bzero
        core::hint::black_box(padding.as_mut_ptr());
        padding[0] = 0x80;

        let mlen_octets: [u8; Self::MLEN_SIZE] = mlen_bits.to_be_bytes();
        padding[plen..plen + Self::MLEN_SIZE].copy_from_slice(&mlen_octets);

        let data = &padding[..plen + Self::MLEN_SIZE];
        let mut sha512 = self;
        sha512.update(data);

        debug_assert_eq!(sha512.offset, 0);

        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..8].copy_from_slice(&sha512.state[0].to_be_bytes());
        output[8..16].copy_from_slice(&sha512.state[1].to_be_bytes());
        output[16..24].copy_from_slice(&sha512.state[2].to_be_bytes());
        output[24..32].copy_from_slice(&sha512.state[3].to_be_bytes());
        output[32..40].copy_from_slice(&sha512.state[4].to_be_bytes());
        output[40..48].copy_from_slice(&sha512.state[5].to_be_bytes());
        output[48..56].copy_from_slice(&sha512.state[6].to_be_bytes());
        output[56..64].copy_from_slice(&sha512.state[7].to_be_bytes());
        output
    }

    #[inline]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 64] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; Self::BLOCK_LEN], &[u8; Self::BLOCK_LEN]>(&self.buffer) };
        process_block_with!(self.state, block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sha512() {
        if std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("avx")
            && std::arch::is_x86_feature_detected!("bmi1")
            && std::arch::is_x86_feature_detected!("bmi2") {
            sha512_test_case!();
        }
    }
}