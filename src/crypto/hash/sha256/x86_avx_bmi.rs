#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[allow(unused_imports)]
use super::x86_ssse3::process_block_with;
use unsafe_target_feature::unsafe_target_feature;

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    len: u64,
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
}

impl Sha256 {
    sha256_define_const!();
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            state: super::INITIAL_STATE,
            len: 0,
            buffer: [0; 64],
            offset: 0,
        }
    }
}

#[unsafe_target_feature("ssse3,avx,bmi1,bmi2")]
impl Sha256 {
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
                    self.offset = 0;
                    self.process_block();
                    self.len += Self::BLOCK_LEN as u64;
                    break;
                }
            }
        }
        while i + Self::BLOCK_LEN <= data.len() {
            let block = unsafe { crate::utils::slice_to_array_at::<_, { Self::BLOCK_LEN }>(data, i) };
            _mm_prefetch(block.as_ptr().add(64) as *const _, _MM_HINT_T0);
            _mm_prefetch(block.as_ptr().add(128) as *const _, _MM_HINT_T0);
            _mm_prefetch(block.as_ptr().add(256) as *const _, _MM_HINT_T0);
            process_block_with!(self.state, block);
            self.len += Self::BLOCK_LEN as u64;
            i += Self::BLOCK_LEN;
        }

        if i < data.len() {
            let remain = data.len() - i;
            self.offset = remain;
            self.buffer[..remain].copy_from_slice(&data[i..]);
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; 32] {
        
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
        let mut sha256 = self;
        sha256.update(data);

        debug_assert_eq!(sha256.offset, 0);

        let state = sha256.state;
        let mut output = [0u8; Self::DIGEST_LEN];
        output[0..4].copy_from_slice(&state[0].to_be_bytes());
        output[4..8].copy_from_slice(&state[1].to_be_bytes());
        output[8..12].copy_from_slice(&state[2].to_be_bytes());
        output[12..16].copy_from_slice(&state[3].to_be_bytes());
        output[16..20].copy_from_slice(&state[4].to_be_bytes());
        output[20..24].copy_from_slice(&state[5].to_be_bytes());
        output[24..28].copy_from_slice(&state[6].to_be_bytes());
        output[28..32].copy_from_slice(&state[7].to_be_bytes());
        output
    }

    #[inline(always)]
    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize()
    }

    #[inline(always)]
    fn process_block(&mut self) {
        let block = unsafe { core::mem::transmute::<&[u8; Self::BLOCK_LEN], &[u8; Self::BLOCK_LEN]>(&self.buffer) };
        process_block_with!(self.state, block);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        if std::arch::is_x86_feature_detected!("ssse3") && std::arch::is_x86_feature_detected!("avx") && std::arch::is_x86_feature_detected!("bmi1") && std::arch::is_x86_feature_detected!("bmi2") {
            sha256_test_case!();
        }
    }
}