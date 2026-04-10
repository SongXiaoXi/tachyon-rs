use std::mem::ManuallyDrop;

#[allow(unused_imports)]
use unsafe_target_feature::unsafe_target_feature;

use crate::utils::portable::xor_si128_inplace;

const CBC_BLOCK_LEN: usize = 16;

macro_rules! impl_block_cipher_with_cbc_mode {
	// With 4-block decrypt support
	($name:tt, $cipher:ty, $klen:expr, $feature:literal; @decrypt4) => {
		impl_block_cipher_with_cbc_mode!(@body $name, $cipher, $klen, true, $feature);
	};
	($name:tt, $cipher:ty, $klen:expr; @decrypt4) => {
		impl_block_cipher_with_cbc_mode!(@body $name, $cipher, $klen, true);
	};
	// Without 4-block decrypt (e.g. AES256 soft/arm)
	($name:tt, $cipher:ty, $klen:expr, $feature:literal) => {
		impl_block_cipher_with_cbc_mode!(@body $name, $cipher, $klen, false, $feature);
	};
	($name:tt, $cipher:ty, $klen:expr) => {
		impl_block_cipher_with_cbc_mode!(@body $name, $cipher, $klen, false);
	};

	(@body $name:tt, $cipher:ty, $klen:expr, $has_decrypt4:tt $(, $feature:literal)?) => {
		#[derive(Clone)]
		pub struct $name {
			cipher: $cipher,
		}

		impl $name {
			pub const KEY_LEN: usize = $klen;
			pub const BLOCK_LEN: usize = <$cipher>::BLOCK_LEN;
			pub const IV_LEN: usize = 16;
		}

		$(#[unsafe_target_feature($feature)])?
		impl $name {
			#[inline(always)]
			pub fn new(key: [u8; $klen]) -> Self {
				assert_eq!(Self::BLOCK_LEN, CBC_BLOCK_LEN);
				let cipher = <$cipher>::new(key);
				Self { cipher }
			}

			#[inline(always)]
			pub fn from_slice(key: &[u8]) -> Self {
				assert_eq!(key.len(), $klen);
				let key = unsafe { *crate::utils::slice_to_array(key) };
				Self::new(key)
			}

			/// Encrypt `data` in-place using AES-CBC mode.
			///
			/// `data.len()` must be a multiple of 16.
			/// CBC encrypt is inherently serial: each block depends on the previous ciphertext.
			#[inline(always)]
			pub fn encrypt_slice(&self, iv: &[u8; 16], data: &mut [u8]) {
				assert_eq!(data.len() % CBC_BLOCK_LEN, 0);

				let mut prev = *iv;
				let mut pos = 0usize;

				while pos + CBC_BLOCK_LEN <= data.len() {
					let block = unsafe { &mut *(data.as_mut_ptr().add(pos) as *mut [u8; 16]) };
					xor_si128_inplace(block, &prev);
					self.cipher.encrypt(block);
					prev = *block;
					pos += CBC_BLOCK_LEN;
				}
			}

			/// Decrypt `data` in-place using AES-CBC mode.
			///
			/// `data.len()` must be a multiple of 16.
			/// CBC decrypt is parallelizable: each block only needs the previous ciphertext.
			#[inline(always)]
			pub fn decrypt_slice(&self, iv: &[u8; 16], data: &mut [u8]) {
				assert_eq!(data.len() % CBC_BLOCK_LEN, 0);

				let mut pos = 0usize;
				let mut prev = *iv;

				impl_block_cipher_with_cbc_mode!(@decrypt_bulk, self, data, pos, prev, $has_decrypt4);

				// Remainder: one block at a time
				while pos + CBC_BLOCK_LEN <= data.len() {
					let block = unsafe { &mut *(data.as_mut_ptr().add(pos) as *mut [u8; 16]) };
					let saved_ct = *block;
					self.cipher.decrypt(block);
					xor_si128_inplace(block, &prev);
					prev = saved_ct;
					pos += CBC_BLOCK_LEN;
				}
			}
		}
	};

	// 4-block decrypt bulk loop when decrypt_4_blocks is available.
	// CBC decrypt: save ciphertext copies, batch-decrypt, then XOR with previous ciphertext.
	(@decrypt_bulk, $self:expr, $data:expr, $pos:expr, $prev:expr, true) => {
		while $pos + CBC_BLOCK_LEN * 4 <= $data.len() {
			// Save ciphertext of these 4 blocks (needed for XOR after decrypt).
			let ct0 = unsafe { *(($data.as_ptr().add($pos)) as *const [u8; 16]) };
			let ct1 = unsafe { *(($data.as_ptr().add($pos + 16)) as *const [u8; 16]) };
			let ct2 = unsafe { *(($data.as_ptr().add($pos + 32)) as *const [u8; 16]) };
			let ct3 = unsafe { *(($data.as_ptr().add($pos + 48)) as *const [u8; 16]) };

			let b0 = unsafe { &mut *($data.as_mut_ptr().add($pos) as *mut [u8; 16]) };
			let b1 = unsafe { &mut *($data.as_mut_ptr().add($pos + 16) as *mut [u8; 16]) };
			let b2 = unsafe { &mut *($data.as_mut_ptr().add($pos + 32) as *mut [u8; 16]) };
			let b3 = unsafe { &mut *($data.as_mut_ptr().add($pos + 48) as *mut [u8; 16]) };

			$self.cipher.decrypt_4_blocks(b0, b1, b2, b3);

			xor_si128_inplace(b0, &$prev);
			xor_si128_inplace(b1, &ct0);
			xor_si128_inplace(b2, &ct1);
			xor_si128_inplace(b3, &ct2);

			$prev = ct3;
			$pos += CBC_BLOCK_LEN * 4;
		}
	};

	// Fallback: no bulk decrypt when decrypt_4_blocks is not available.
	(@decrypt_bulk, $self:expr, $data:expr, $pos:expr, $prev:expr, false) => {
		// No 4-block decrypt available; handled by remainder loop below.
	};
}

use crate::crypto::aes::soft::AES128 as AES128Soft;
use crate::crypto::aes::soft::AES256 as AES256Soft;

impl_block_cipher_with_cbc_mode!(AES128CbcSoft, AES128Soft, 16; @decrypt4);
impl_block_cipher_with_cbc_mode!(AES256CbcSoft, AES256Soft, 32);

cfg_if::cfg_if! {
	if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
		use crate::crypto::aes::x86::AES128 as AES128SSE;
		use crate::crypto::aes::x86::AES256 as AES256SSE;
		impl_block_cipher_with_cbc_mode!(AES128CbcSSE, AES128SSE, 16, "sse2,aes"; @decrypt4);
		impl_block_cipher_with_cbc_mode!(AES256CbcSSE, AES256SSE, 32, "sse2,aes");
		type AES128CbcHW = AES128CbcSSE;
		type AES256CbcHW = AES256CbcSSE;

		use crate::crypto::aes::x86_avx::AES128 as AES128AVX;
		use crate::crypto::aes::x86_avx::AES256 as AES256AVX;
		impl_block_cipher_with_cbc_mode!(AES128CbcAVX, AES128AVX, 16, "avx,aes"; @decrypt4);
		impl_block_cipher_with_cbc_mode!(AES256CbcAVX, AES256AVX, 32, "avx,aes");

		#[cfg(avx512_feature)]
		use crate::crypto::aes::x86_avx512::AES128 as AES128AVX512;
		#[cfg(avx512_feature)]
		use crate::crypto::aes::x86_avx512::AES256 as AES256AVX512;
		#[cfg(avx512_feature)]
		impl_block_cipher_with_cbc_mode!(AES128CbcAVX512, AES128AVX512, 16, "avx512f,avx512bw,avx512vl,vaes"; @decrypt4);
		#[cfg(avx512_feature)]
		impl_block_cipher_with_cbc_mode!(AES256CbcAVX512, AES256AVX512, 32, "avx512f,avx512bw,avx512vl,vaes");
	} else if #[cfg(any(target_arch = "aarch64", target_arch = "arm"))] {
		use crate::crypto::aes::arm::AES128 as AES128Arm;
		use crate::crypto::aes::arm::AES256 as AES256Arm;
		impl_block_cipher_with_cbc_mode!(AES128CbcHW, AES128Arm, 16; @decrypt4);
		impl_block_cipher_with_cbc_mode!(AES256CbcHW, AES256Arm, 32);
	}
}

cfg_if::cfg_if! {
	if #[cfg(all(avx512_feature, any(target_arch = "x86", target_arch = "x86_64"), target_feature = "vaes", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx512bw"))] {
		pub type AES128Cbc = AES128CbcAVX512;
		pub type AES256Cbc = AES256CbcAVX512;
	} else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx", target_feature = "aes"))] {
		pub type AES128Cbc = AES128CbcAVX;
		pub type AES256Cbc = AES256CbcAVX;
	} else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", target_feature = "aes"))] {
		pub type AES128Cbc = AES128CbcSSE;
		pub type AES256Cbc = AES256CbcSSE;
	} else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "aes"))] {
		pub type AES128Cbc = AES128CbcHW;
		pub type AES256Cbc = AES256CbcHW;
	} else if #[cfg(all(target_arch = "arm", target_feature = "neon", target_feature = "aes"))] {
		pub type AES128Cbc = AES128CbcHW;
		pub type AES256Cbc = AES256CbcHW;
	} else {
		pub type AES128Cbc = AES128CbcDynamic;
		pub type AES256Cbc = AES256CbcDynamic;
	}
}

// x86: 0 - avx aes-ni, 1 - sse aes-ni, 2 - soft, 3 - avx512 (vaes)
// arm/aarch64: 0 - aes, 2 - soft
static mut AES_CBC_IDX: u32 = u32::MAX;

pub union AES128CbcDynamic {
	#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
	hw: ManuallyDrop<AES128CbcHW>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	avx: ManuallyDrop<AES128CbcAVX>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	#[cfg(avx512_feature)]
	avx512: ManuallyDrop<AES128CbcAVX512>,
	sw: ManuallyDrop<AES128CbcSoft>,
}

pub union AES256CbcDynamic {
	#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
	hw: ManuallyDrop<AES256CbcHW>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	avx: ManuallyDrop<AES256CbcAVX>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	#[cfg(avx512_feature)]
	avx512: ManuallyDrop<AES256CbcAVX512>,
	sw: ManuallyDrop<AES256CbcSoft>,
}

impl AES128CbcDynamic {
	pub const KEY_LEN: usize = 16;
	pub const BLOCK_LEN: usize = 16;
	pub const IV_LEN: usize = 16;

	pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
		unsafe {
			if AES_CBC_IDX == u32::MAX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				{
					if cfg!(avx512_feature)
						&& crate::is_hw_feature_detected!(
							"x86" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
							"x86_64" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
						)
					{
						AES_CBC_IDX = 3;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("avx", "aes"),
						"x86_64" => ("avx", "aes"),
					) {
						AES_CBC_IDX = 0;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("sse2", "aes"),
						"x86_64" => ("sse2", "aes"),
					) {
						AES_CBC_IDX = 1;
					} else {
						AES_CBC_IDX = 2;
					}
				}
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				{
					if crate::is_hw_feature_detected!(
						"aarch64" => ("aes", "neon"),
						"arm" => ("neon", "aes"),
					) {
						AES_CBC_IDX = 0;
					} else {
						AES_CBC_IDX = 2;
					}
				}
				#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
				{
					AES_CBC_IDX = 2;
				}
			}

			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => AES128CbcDynamic { avx: ManuallyDrop::new(AES128CbcAVX::new(key)) },
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => AES128CbcDynamic { hw: ManuallyDrop::new(AES128CbcHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => AES128CbcDynamic { hw: ManuallyDrop::new(AES128CbcHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => AES128CbcDynamic { avx512: ManuallyDrop::new(AES128CbcAVX512::new(key)) },
				2 => AES128CbcDynamic { sw: ManuallyDrop::new(AES128CbcSoft::new(key)) },
				_ => unreachable!(),
			}
		}
	}

	#[inline(always)]
	pub fn from_slice(key: &[u8]) -> Self {
		assert_eq!(key.len(), Self::KEY_LEN);
		let key = unsafe { crate::utils::slice_to_array(key).clone() };
		Self::new(key)
	}

	#[inline(never)]
	pub fn encrypt_slice(&self, iv: &[u8; 16], data: &mut [u8]) {
		unsafe {
			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.encrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.encrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.encrypt_slice(iv, data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.encrypt_slice(iv, data),
				2 => self.sw.encrypt_slice(iv, data),
				_ => unreachable!(),
			}
		}
	}

	#[inline(never)]
	pub fn decrypt_slice(&self, iv: &[u8; 16], data: &mut [u8]) {
		unsafe {
			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.decrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.decrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.decrypt_slice(iv, data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.decrypt_slice(iv, data),
				2 => self.sw.decrypt_slice(iv, data),
				_ => unreachable!(),
			}
		}
	}
}

impl Drop for AES128CbcDynamic {
	#[inline]
	fn drop(&mut self) {
		unsafe {
			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => ManuallyDrop::drop(&mut self.avx),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => ManuallyDrop::drop(&mut self.hw),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => ManuallyDrop::drop(&mut self.avx512),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => ManuallyDrop::drop(&mut self.hw),
				2 => ManuallyDrop::drop(&mut self.sw),
				_ => {}
			}
		}
	}
}

impl AES256CbcDynamic {
	pub const KEY_LEN: usize = 32;
	pub const BLOCK_LEN: usize = 16;
	pub const IV_LEN: usize = 16;

	pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
		unsafe {
			if AES_CBC_IDX == u32::MAX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				{
					if cfg!(avx512_feature)
						&& crate::is_hw_feature_detected!(
							"x86" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
							"x86_64" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
						)
					{
						AES_CBC_IDX = 3;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("avx", "aes"),
						"x86_64" => ("avx", "aes"),
					) {
						AES_CBC_IDX = 0;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("sse2", "aes"),
						"x86_64" => ("sse2", "aes"),
					) {
						AES_CBC_IDX = 1;
					} else {
						AES_CBC_IDX = 2;
					}
				}
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				{
					if crate::is_hw_feature_detected!(
						"aarch64" => ("aes", "neon"),
						"arm" => ("neon", "aes"),
					) {
						AES_CBC_IDX = 0;
					} else {
						AES_CBC_IDX = 2;
					}
				}
				#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
				{
					AES_CBC_IDX = 2;
				}
			}

			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => AES256CbcDynamic { avx: ManuallyDrop::new(AES256CbcAVX::new(key)) },
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => AES256CbcDynamic { hw: ManuallyDrop::new(AES256CbcHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => AES256CbcDynamic { hw: ManuallyDrop::new(AES256CbcHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => AES256CbcDynamic { avx512: ManuallyDrop::new(AES256CbcAVX512::new(key)) },
				2 => AES256CbcDynamic { sw: ManuallyDrop::new(AES256CbcSoft::new(key)) },
				_ => unreachable!(),
			}
		}
	}

	#[inline(always)]
	pub fn from_slice(key: &[u8]) -> Self {
		assert_eq!(key.len(), Self::KEY_LEN);
		let key = unsafe { crate::utils::slice_to_array(key).clone() };
		Self::new(key)
	}

	#[inline(never)]
	pub fn encrypt_slice(&self, iv: &[u8; 16], data: &mut [u8]) {
		unsafe {
			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.encrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.encrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.encrypt_slice(iv, data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.encrypt_slice(iv, data),
				2 => self.sw.encrypt_slice(iv, data),
				_ => unreachable!(),
			}
		}
	}

	#[inline(never)]
	pub fn decrypt_slice(&self, iv: &[u8; 16], data: &mut [u8]) {
		unsafe {
			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.decrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.decrypt_slice(iv, data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.decrypt_slice(iv, data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.decrypt_slice(iv, data),
				2 => self.sw.decrypt_slice(iv, data),
				_ => unreachable!(),
			}
		}
	}
}

impl Drop for AES256CbcDynamic {
	#[inline]
	fn drop(&mut self) {
		unsafe {
			match AES_CBC_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => ManuallyDrop::drop(&mut self.avx),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => ManuallyDrop::drop(&mut self.hw),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => ManuallyDrop::drop(&mut self.avx512),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => ManuallyDrop::drop(&mut self.hw),
				2 => ManuallyDrop::drop(&mut self.sw),
				_ => {}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	macro_rules! test_aes128_cbc_nist_impl {
		($cipher_type:ty) => {{
			// NIST SP 800-38A, F.2.1 CBC-AES128.Encrypt
			let key: [u8; 16] = [
				0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
				0x4f, 0x3c,
			];
			let iv: [u8; 16] = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				0x0e, 0x0f,
			];
			let plaintext: [u8; 64] = [
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
				0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
				0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
				0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
				0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
			];
			let expected_ciphertext: [u8; 64] = [
				0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12,
				0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb,
				0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74,
				0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1,
				0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
			];

			let cipher = <$cipher_type>::new(key);

			// Encrypt
			let mut buf = plaintext;
			cipher.encrypt_slice(&iv, &mut buf);
			assert_eq!(
				buf, expected_ciphertext,
				"cipher_type: {} encrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);

			// Decrypt
			cipher.decrypt_slice(&iv, &mut buf);
			assert_eq!(
				buf, plaintext,
				"cipher_type: {} decrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);
		}};
	}

	macro_rules! test_aes256_cbc_nist_impl {
		($cipher_type:ty) => {{
			// NIST SP 800-38A, F.2.5 CBC-AES256.Encrypt
			let key: [u8; 32] = [
				0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
				0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
				0x09, 0x14, 0xdf, 0xf4,
			];
			let iv: [u8; 16] = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				0x0e, 0x0f,
			];
			let plaintext: [u8; 64] = [
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
				0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
				0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
				0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
				0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
			];
			let expected_ciphertext: [u8; 64] = [
				0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
				0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f,
				0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba,
				0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb, 0x05, 0xe2,
				0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
			];

			let cipher = <$cipher_type>::new(key);

			// Encrypt
			let mut buf = plaintext;
			cipher.encrypt_slice(&iv, &mut buf);
			assert_eq!(
				buf, expected_ciphertext,
				"cipher_type: {} encrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);

			// Decrypt
			cipher.decrypt_slice(&iv, &mut buf);
			assert_eq!(
				buf, plaintext,
				"cipher_type: {} decrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);
		}};
	}

	macro_rules! test_cbc_roundtrip_impl {
		($cipher_type:ty, $key_len:expr) => {{
			let key = [0x42u8; $key_len];
			let iv = [0x13u8; 16];
			let cipher = <$cipher_type>::new(key);

			// Test various lengths that are multiples of 16
			for num_blocks in [1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 64, 100] {
				let len = num_blocks * 16;
				let mut data = vec![0u8; len];
				for (i, b) in data.iter_mut().enumerate() {
					*b = (i as u8).wrapping_mul(31).wrapping_add(7);
				}
				let original = data.clone();

				cipher.encrypt_slice(&iv, &mut data);
				assert_ne!(
					data, original,
					"cipher_type: {} encrypt produced identical output for {} blocks",
					core::any::type_name::<$cipher_type>(), num_blocks
				);

				cipher.decrypt_slice(&iv, &mut data);
				assert_eq!(
					data, original,
					"cipher_type: {} roundtrip failed for {} blocks",
					core::any::type_name::<$cipher_type>(), num_blocks
				);
			}
		}};
	}

	#[test]
	fn test_aes_cbc_all_backends() {
		// Always test soft backends.
		test_aes128_cbc_nist_impl!(AES128CbcSoft);
		test_aes256_cbc_nist_impl!(AES256CbcSoft);
		test_cbc_roundtrip_impl!(AES128CbcSoft, 16);
		test_cbc_roundtrip_impl!(AES256CbcSoft, 32);

		// x86 / x86_64 feature-gated backends.
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		if crate::is_hw_feature_detected!("sse2", "aes") {
			test_aes128_cbc_nist_impl!(AES128CbcSSE);
			test_aes256_cbc_nist_impl!(AES256CbcSSE);
			test_cbc_roundtrip_impl!(AES128CbcSSE, 16);
			test_cbc_roundtrip_impl!(AES256CbcSSE, 32);
		}
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		if crate::is_hw_feature_detected!("avx", "aes") {
			test_aes128_cbc_nist_impl!(AES128CbcAVX);
			test_aes256_cbc_nist_impl!(AES256CbcAVX);
			test_cbc_roundtrip_impl!(AES128CbcAVX, 16);
			test_cbc_roundtrip_impl!(AES256CbcAVX, 32);
		}
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		#[cfg(avx512_feature)]
		if crate::is_hw_feature_detected!("avx512f", "avx512bw", "avx512vl", "vaes") {
			test_aes128_cbc_nist_impl!(AES128CbcAVX512);
			test_aes256_cbc_nist_impl!(AES256CbcAVX512);
			test_cbc_roundtrip_impl!(AES128CbcAVX512, 16);
			test_cbc_roundtrip_impl!(AES256CbcAVX512, 32);
		}

		// ARM/AArch64 hardware AES backend.
		#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
		if crate::is_hw_feature_detected!(
			"aarch64" => ("aes", "neon"),
			"arm" => ("aes", "neon"),
		) {
			test_aes128_cbc_nist_impl!(AES128CbcHW);
			test_aes256_cbc_nist_impl!(AES256CbcHW);
			test_cbc_roundtrip_impl!(AES128CbcHW, 16);
			test_cbc_roundtrip_impl!(AES256CbcHW, 32);
		}

		// Finally, always test dynamic dispatch.
		test_aes128_cbc_nist_impl!(AES128CbcDynamic);
		test_aes256_cbc_nist_impl!(AES256CbcDynamic);
		test_cbc_roundtrip_impl!(AES128CbcDynamic, 16);
		test_cbc_roundtrip_impl!(AES256CbcDynamic, 32);
	}
}
