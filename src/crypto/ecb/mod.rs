use std::mem::ManuallyDrop;

#[allow(unused_imports)]
use unsafe_target_feature::unsafe_target_feature;

const ECB_BLOCK_LEN: usize = 16;

macro_rules! impl_block_cipher_with_ecb_mode {
	// With 4-block decrypt support
	($name:tt, $cipher:ty, $klen:expr, $feature:literal; @decrypt4) => {
		impl_block_cipher_with_ecb_mode!(@body $name, $cipher, $klen, true, $feature);
	};
	($name:tt, $cipher:ty, $klen:expr; @decrypt4) => {
		impl_block_cipher_with_ecb_mode!(@body $name, $cipher, $klen, true);
	};
	// Without 4-block decrypt (e.g. AES256 soft/arm)
	($name:tt, $cipher:ty, $klen:expr, $feature:literal) => {
		impl_block_cipher_with_ecb_mode!(@body $name, $cipher, $klen, false, $feature);
	};
	($name:tt, $cipher:ty, $klen:expr) => {
		impl_block_cipher_with_ecb_mode!(@body $name, $cipher, $klen, false);
	};

	(@body $name:tt, $cipher:ty, $klen:expr, $has_decrypt4:tt $(, $feature:literal)?) => {
		#[derive(Clone)]
		pub struct $name {
			cipher: $cipher,
		}

		impl $name {
			pub const KEY_LEN: usize = $klen;
			pub const BLOCK_LEN: usize = <$cipher>::BLOCK_LEN;
		}

		$(#[unsafe_target_feature($feature)])?
		impl $name {
			#[inline(always)]
			pub fn new(key: [u8; $klen]) -> Self {
				assert_eq!(Self::BLOCK_LEN, ECB_BLOCK_LEN);
				let cipher = <$cipher>::new(key);
				Self { cipher }
			}

			#[inline(always)]
			pub fn from_slice(key: &[u8]) -> Self {
				assert_eq!(key.len(), $klen);
				let key = unsafe { *crate::utils::slice_to_array(key) };
				Self::new(key)
			}

			/// `data.len()` must be a multiple of 16.
			#[inline(always)]
			pub fn encrypt_slice(&self, data: &mut [u8]) {
				assert_eq!(data.len() % ECB_BLOCK_LEN, 0);

				let mut pos = 0usize;

				// 4-block bulk loop
				while pos + ECB_BLOCK_LEN * 4 <= data.len() {
					let b0 = unsafe { &mut *(data.as_mut_ptr().add(pos) as *mut [u8; 16]) };
					let b1 = unsafe { &mut *(data.as_mut_ptr().add(pos + 16) as *mut [u8; 16]) };
					let b2 = unsafe { &mut *(data.as_mut_ptr().add(pos + 32) as *mut [u8; 16]) };
					let b3 = unsafe { &mut *(data.as_mut_ptr().add(pos + 48) as *mut [u8; 16]) };

					self.cipher.encrypt_4_blocks(b0, b1, b2, b3);
					pos += ECB_BLOCK_LEN * 4;
				}

				// Remainder: one block at a time
				while pos + ECB_BLOCK_LEN <= data.len() {
					let block = unsafe { &mut *(data.as_mut_ptr().add(pos) as *mut [u8; 16]) };
					self.cipher.encrypt(block);
					pos += ECB_BLOCK_LEN;
				}
			}

			/// `data.len()` must be a multiple of 16.
			#[inline(always)]
			pub fn decrypt_slice(&self, data: &mut [u8]) {
				assert_eq!(data.len() % ECB_BLOCK_LEN, 0);

				let mut pos = 0usize;

				impl_block_cipher_with_ecb_mode!(@decrypt_bulk, self, data, pos, $has_decrypt4);

				// Remainder: one block at a time
				while pos + ECB_BLOCK_LEN <= data.len() {
					let block = unsafe { &mut *(data.as_mut_ptr().add(pos) as *mut [u8; 16]) };
					self.cipher.decrypt(block);
					pos += ECB_BLOCK_LEN;
				}
			}
		}
	};

	// 4-block decrypt bulk loop when decrypt_4_blocks is available
	(@decrypt_bulk, $self:expr, $data:expr, $pos:expr, true) => {
		while $pos + ECB_BLOCK_LEN * 4 <= $data.len() {
			let b0 = unsafe { &mut *($data.as_mut_ptr().add($pos) as *mut [u8; 16]) };
			let b1 = unsafe { &mut *($data.as_mut_ptr().add($pos + 16) as *mut [u8; 16]) };
			let b2 = unsafe { &mut *($data.as_mut_ptr().add($pos + 32) as *mut [u8; 16]) };
			let b3 = unsafe { &mut *($data.as_mut_ptr().add($pos + 48) as *mut [u8; 16]) };

			$self.cipher.decrypt_4_blocks(b0, b1, b2, b3);
			$pos += ECB_BLOCK_LEN * 4;
		}
	};

	// Fallback: single-block decrypt loop when decrypt_4_blocks is not available
	(@decrypt_bulk, $self:expr, $data:expr, $pos:expr, false) => {
		// No 4-block decrypt available; handled by remainder loop below.
	};
}

use crate::crypto::aes::soft::AES128 as AES128Soft;
use crate::crypto::aes::soft::AES256 as AES256Soft;

impl_block_cipher_with_ecb_mode!(AES128EcbSoft, AES128Soft, 16; @decrypt4);
impl_block_cipher_with_ecb_mode!(AES256EcbSoft, AES256Soft, 32);

cfg_if::cfg_if! {
	if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
		use crate::crypto::aes::x86::AES128 as AES128SSE;
		use crate::crypto::aes::x86::AES256 as AES256SSE;
		impl_block_cipher_with_ecb_mode!(AES128EcbSSE, AES128SSE, 16, "sse2,aes"; @decrypt4);
		impl_block_cipher_with_ecb_mode!(AES256EcbSSE, AES256SSE, 32, "sse2,aes");
		type AES128EcbHW = AES128EcbSSE;
		type AES256EcbHW = AES256EcbSSE;

		use crate::crypto::aes::x86_avx::AES128 as AES128AVX;
		use crate::crypto::aes::x86_avx::AES256 as AES256AVX;
		impl_block_cipher_with_ecb_mode!(AES128EcbAVX, AES128AVX, 16, "avx,aes"; @decrypt4);
		impl_block_cipher_with_ecb_mode!(AES256EcbAVX, AES256AVX, 32, "avx,aes");

		#[cfg(avx512_feature)]
		use crate::crypto::aes::x86_avx512::AES128 as AES128AVX512;
		#[cfg(avx512_feature)]
		use crate::crypto::aes::x86_avx512::AES256 as AES256AVX512;
		#[cfg(avx512_feature)]
		impl_block_cipher_with_ecb_mode!(AES128EcbAVX512, AES128AVX512, 16, "avx512f,avx512bw,avx512vl,vaes"; @decrypt4);
		#[cfg(avx512_feature)]
		impl_block_cipher_with_ecb_mode!(AES256EcbAVX512, AES256AVX512, 32, "avx512f,avx512bw,avx512vl,vaes");
	} else if #[cfg(any(target_arch = "aarch64", target_arch = "arm"))] {
		use crate::crypto::aes::arm::AES128 as AES128Arm;
		use crate::crypto::aes::arm::AES256 as AES256Arm;
		impl_block_cipher_with_ecb_mode!(AES128EcbHW, AES128Arm, 16; @decrypt4);
		impl_block_cipher_with_ecb_mode!(AES256EcbHW, AES256Arm, 32);
	}
}

cfg_if::cfg_if! {
	if #[cfg(all(avx512_feature, any(target_arch = "x86", target_arch = "x86_64"), target_feature = "vaes", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx512bw"))] {
		pub type AES128Ecb = AES128EcbAVX512;
		pub type AES256Ecb = AES256EcbAVX512;
	} else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx", target_feature = "aes"))] {
		pub type AES128Ecb = AES128EcbAVX;
		pub type AES256Ecb = AES256EcbAVX;
	} else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", target_feature = "aes"))] {
		pub type AES128Ecb = AES128EcbSSE;
		pub type AES256Ecb = AES256EcbSSE;
	} else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "aes"))] {
		pub type AES128Ecb = AES128EcbHW;
		pub type AES256Ecb = AES256EcbHW;
	} else if #[cfg(all(target_arch = "arm", target_feature = "neon", target_feature = "aes"))] {
		pub type AES128Ecb = AES128EcbHW;
		pub type AES256Ecb = AES256EcbHW;
	} else {
		pub type AES128Ecb = AES128EcbDynamic;
		pub type AES256Ecb = AES256EcbDynamic;
	}
}

// x86: 0 - avx aes-ni, 1 - sse aes-ni, 2 - soft, 3 - avx512 (vaes)
// arm/aarch64: 0 - aes, 2 - soft
static mut AES_ECB_IDX: u32 = u32::MAX;

pub union AES128EcbDynamic {
	#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
	hw: ManuallyDrop<AES128EcbHW>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	avx: ManuallyDrop<AES128EcbAVX>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	#[cfg(avx512_feature)]
	avx512: ManuallyDrop<AES128EcbAVX512>,
	sw: ManuallyDrop<AES128EcbSoft>,
}

pub union AES256EcbDynamic {
	#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
	hw: ManuallyDrop<AES256EcbHW>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	avx: ManuallyDrop<AES256EcbAVX>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	#[cfg(avx512_feature)]
	avx512: ManuallyDrop<AES256EcbAVX512>,
	sw: ManuallyDrop<AES256EcbSoft>,
}

impl AES128EcbDynamic {
	pub const KEY_LEN: usize = 16;
	pub const BLOCK_LEN: usize = 16;

	pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
		unsafe {
			if AES_ECB_IDX == u32::MAX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				{
					if cfg!(avx512_feature)
						&& crate::is_hw_feature_detected!(
							"x86" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
							"x86_64" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
						)
					{
						AES_ECB_IDX = 3;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("avx", "aes"),
						"x86_64" => ("avx", "aes"),
					) {
						AES_ECB_IDX = 0;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("sse2", "aes"),
						"x86_64" => ("sse2", "aes"),
					) {
						AES_ECB_IDX = 1;
					} else {
						AES_ECB_IDX = 2;
					}
				}
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				{
					if crate::is_hw_feature_detected!(
						"aarch64" => ("aes", "neon"),
						"arm" => ("neon", "aes"),
					) {
						AES_ECB_IDX = 0;
					} else {
						AES_ECB_IDX = 2;
					}
				}
				#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
				{
					AES_ECB_IDX = 2;
				}
			}

			match AES_ECB_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => AES128EcbDynamic { avx: ManuallyDrop::new(AES128EcbAVX::new(key)) },
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => AES128EcbDynamic { hw: ManuallyDrop::new(AES128EcbHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => AES128EcbDynamic { hw: ManuallyDrop::new(AES128EcbHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => AES128EcbDynamic { avx512: ManuallyDrop::new(AES128EcbAVX512::new(key)) },
				2 => AES128EcbDynamic { sw: ManuallyDrop::new(AES128EcbSoft::new(key)) },
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
	pub fn encrypt_slice(&self, data: &mut [u8]) {
		unsafe {
			match AES_ECB_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.encrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.encrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.encrypt_slice(data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.encrypt_slice(data),
				2 => self.sw.encrypt_slice(data),
				_ => unreachable!(),
			}
		}
	}

	#[inline(never)]
	pub fn decrypt_slice(&self, data: &mut [u8]) {
		unsafe {
			match AES_ECB_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.decrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.decrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.decrypt_slice(data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.decrypt_slice(data),
				2 => self.sw.decrypt_slice(data),
				_ => unreachable!(),
			}
		}
	}
}

impl Drop for AES128EcbDynamic {
	#[inline]
	fn drop(&mut self) {
		unsafe {
			match AES_ECB_IDX {
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

impl AES256EcbDynamic {
	pub const KEY_LEN: usize = 32;
	pub const BLOCK_LEN: usize = 16;

	pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
		unsafe {
			if AES_ECB_IDX == u32::MAX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				{
					if cfg!(avx512_feature)
						&& crate::is_hw_feature_detected!(
							"x86" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
							"x86_64" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
						)
					{
						AES_ECB_IDX = 3;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("avx", "aes"),
						"x86_64" => ("avx", "aes"),
					) {
						AES_ECB_IDX = 0;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("sse2", "aes"),
						"x86_64" => ("sse2", "aes"),
					) {
						AES_ECB_IDX = 1;
					} else {
						AES_ECB_IDX = 2;
					}
				}
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				{
					if crate::is_hw_feature_detected!(
						"aarch64" => ("aes", "neon"),
						"arm" => ("neon", "aes"),
					) {
						AES_ECB_IDX = 0;
					} else {
						AES_ECB_IDX = 2;
					}
				}
				#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
				{
					AES_ECB_IDX = 2;
				}
			}

			match AES_ECB_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => AES256EcbDynamic { avx: ManuallyDrop::new(AES256EcbAVX::new(key)) },
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => AES256EcbDynamic { hw: ManuallyDrop::new(AES256EcbHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => AES256EcbDynamic { hw: ManuallyDrop::new(AES256EcbHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => AES256EcbDynamic { avx512: ManuallyDrop::new(AES256EcbAVX512::new(key)) },
				2 => AES256EcbDynamic { sw: ManuallyDrop::new(AES256EcbSoft::new(key)) },
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
	pub fn encrypt_slice(&self, data: &mut [u8]) {
		unsafe {
			match AES_ECB_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.encrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.encrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.encrypt_slice(data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.encrypt_slice(data),
				2 => self.sw.encrypt_slice(data),
				_ => unreachable!(),
			}
		}
	}

	#[inline(never)]
	pub fn decrypt_slice(&self, data: &mut [u8]) {
		unsafe {
			match AES_ECB_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.decrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.decrypt_slice(data),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.decrypt_slice(data),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.decrypt_slice(data),
				2 => self.sw.decrypt_slice(data),
				_ => unreachable!(),
			}
		}
	}
}

impl Drop for AES256EcbDynamic {
	#[inline]
	fn drop(&mut self) {
		unsafe {
			match AES_ECB_IDX {
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

	macro_rules! test_aes128_ecb_nist_impl {
		($cipher_type:ty) => {{
			// NIST SP 800-38A, F.1.1 ECB-AES128.Encrypt
			let key: [u8; 16] = [
				0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
				0x4f, 0x3c,
			];
			let plaintext: [u8; 64] = [
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
				0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
				0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
				0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
				0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
			];
			let expected_ciphertext: [u8; 64] = [
				0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24,
				0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85,
				0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf, 0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce,
				0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88, 0x7b, 0x0c, 0x78, 0x5e,
				0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
			];

			let cipher = <$cipher_type>::new(key);

			// Encrypt
			let mut buf = plaintext;
			cipher.encrypt_slice(&mut buf);
			assert_eq!(
				buf, expected_ciphertext,
				"cipher_type: {} encrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);

			// Decrypt
			cipher.decrypt_slice(&mut buf);
			assert_eq!(
				buf, plaintext,
				"cipher_type: {} decrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);
		}};
	}

	macro_rules! test_aes256_ecb_nist_impl {
		($cipher_type:ty) => {{
			// NIST SP 800-38A, F.1.5 ECB-AES256.Encrypt
			let key: [u8; 32] = [
				0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
				0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
				0x09, 0x14, 0xdf, 0xf4,
			];
			let plaintext: [u8; 64] = [
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
				0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
				0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
				0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
				0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
			];
			let expected_ciphertext: [u8; 64] = [
				0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d,
				0xb1, 0x81, 0xf8, 0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 0xdc, 0x5b,
				0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70, 0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4,
				0xf9, 0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d, 0x23, 0x30, 0x4b, 0x7a,
				0x39, 0xf9, 0xf3, 0xff, 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7,
			];

			let cipher = <$cipher_type>::new(key);

			// Encrypt
			let mut buf = plaintext;
			cipher.encrypt_slice(&mut buf);
			assert_eq!(
				buf, expected_ciphertext,
				"cipher_type: {} encrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);

			// Decrypt
			cipher.decrypt_slice(&mut buf);
			assert_eq!(
				buf, plaintext,
				"cipher_type: {} decrypt mismatch",
				core::any::type_name::<$cipher_type>()
			);
		}};
	}

	macro_rules! test_ecb_roundtrip_impl {
		($cipher_type:ty, $key_len:expr) => {{
			let key = [0x42u8; $key_len];
			let cipher = <$cipher_type>::new(key);

			// Test various lengths that are multiples of 16
			for num_blocks in [1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 64, 100] {
				let len = num_blocks * 16;
				let mut data = vec![0u8; len];
				for (i, b) in data.iter_mut().enumerate() {
					*b = (i as u8).wrapping_mul(31).wrapping_add(7);
				}
				let original = data.clone();

				cipher.encrypt_slice(&mut data);
				// Ciphertext should differ from plaintext (unless trivially all-zero, which it isn't)
				assert_ne!(
					data, original,
					"cipher_type: {} encrypt produced identical output for {} blocks",
					core::any::type_name::<$cipher_type>(), num_blocks
				);

				cipher.decrypt_slice(&mut data);
				assert_eq!(
					data, original,
					"cipher_type: {} roundtrip failed for {} blocks",
					core::any::type_name::<$cipher_type>(), num_blocks
				);
			}
		}};
	}

	#[test]
	fn test_aes_ecb_all_backends() {
		// Always test soft backends.
		test_aes128_ecb_nist_impl!(AES128EcbSoft);
		test_aes256_ecb_nist_impl!(AES256EcbSoft);
		test_ecb_roundtrip_impl!(AES128EcbSoft, 16);
		test_ecb_roundtrip_impl!(AES256EcbSoft, 32);

		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		if crate::is_hw_feature_detected!("sse2", "aes") {
			test_aes128_ecb_nist_impl!(AES128EcbSSE);
			test_aes256_ecb_nist_impl!(AES256EcbSSE);
			test_ecb_roundtrip_impl!(AES128EcbSSE, 16);
			test_ecb_roundtrip_impl!(AES256EcbSSE, 32);
		}
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		if crate::is_hw_feature_detected!("avx", "aes") {
			test_aes128_ecb_nist_impl!(AES128EcbAVX);
			test_aes256_ecb_nist_impl!(AES256EcbAVX);
			test_ecb_roundtrip_impl!(AES128EcbAVX, 16);
			test_ecb_roundtrip_impl!(AES256EcbAVX, 32);
		}
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		#[cfg(avx512_feature)]
		if crate::is_hw_feature_detected!("avx512f", "avx512bw", "avx512vl", "vaes") {
			test_aes128_ecb_nist_impl!(AES128EcbAVX512);
			test_aes256_ecb_nist_impl!(AES256EcbAVX512);
			test_ecb_roundtrip_impl!(AES128EcbAVX512, 16);
			test_ecb_roundtrip_impl!(AES256EcbAVX512, 32);
		}

		#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
		if crate::is_hw_feature_detected!(
			"aarch64" => ("aes", "neon"),
			"arm" => ("aes", "neon"),
		) {
			test_aes128_ecb_nist_impl!(AES128EcbHW);
			test_aes256_ecb_nist_impl!(AES256EcbHW);
			test_ecb_roundtrip_impl!(AES128EcbHW, 16);
			test_ecb_roundtrip_impl!(AES256EcbHW, 32);
		}

		// Finally, always test dynamic dispatch.
		test_aes128_ecb_nist_impl!(AES128EcbDynamic);
		test_aes256_ecb_nist_impl!(AES256EcbDynamic);
		test_ecb_roundtrip_impl!(AES128EcbDynamic, 16);
		test_ecb_roundtrip_impl!(AES256EcbDynamic, 32);
	}
}
