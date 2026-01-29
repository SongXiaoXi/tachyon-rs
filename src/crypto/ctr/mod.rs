use crate::utils::portable::xor_si128_inplace;
use core::mem::ManuallyDrop;

#[allow(unused_imports)]
use unsafe_target_feature::unsafe_target_feature;

pub const NONCE_LEN: usize = 16;

#[derive(Clone, Copy)]
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
	#[inline(always)]
	pub fn new(value: [u8; NONCE_LEN]) -> Self {
		Self(value)
	}
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
	#[inline(always)]
	fn as_ref(&self) -> &[u8; NONCE_LEN] {
		&self.0
	}
}

const CTR_BLOCK_LEN: usize = 16;

#[inline(always)]
fn ctr128_inc_be(counter: &mut [u8; 16]) {
	let v = u128::from_be_bytes(*counter);
	*counter = v.wrapping_add(1).to_be_bytes();
}

#[inline(always)]
fn ctr128_inc_be_by(counter: &mut [u8; 16], n: u32) {
	let v = u128::from_be_bytes(*counter);
	*counter = v.wrapping_add(n as u128).to_be_bytes();
}

macro_rules! impl_block_cipher_with_ctr_mode {
	($name:tt, $cipher:ty, $klen:expr$(, $feature:literal)?) => {
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
				// CTR works only with block ciphers that have a block size of 16 bytes.
				assert_eq!(Self::BLOCK_LEN, CTR_BLOCK_LEN);
				let cipher = <$cipher>::new(key);
				Self { cipher }
			}

			#[inline(always)]
			pub fn from_slice(key: &[u8]) -> Self {
				assert_eq!(key.len(), $klen);
				let key = unsafe { *crate::utils::slice_to_array(key) };
				Self::new(key)
			}

			/// XORs `text` with the AES-CTR keystream.
			///
			/// This is a convenience wrapper around `xor_slice_streaming`.
			#[inline(always)]
			pub fn xor_slice(&self, nonce: &[u8; NONCE_LEN], text_in_out: &mut [u8]) {
				let mut ctr = *nonce;
				let mut block_off = 0usize;
				self.xor_slice_streaming(&mut ctr, &mut block_off, text_in_out)
			}

			/// XORs `text` with the AES-CTR keystream, updating the stream state.
			///
			/// - `ctr` is a big-endian 128-bit counter block (updated in-place)
			/// - `block_off` is the byte offset within the current keystream block (0..16)
			///
			#[inline(always)]
			pub fn xor_slice_streaming(
				&self,
				ctr: &mut [u8; 16],
				block_off: &mut usize,
				text_in_out: &mut [u8],
			) {
				debug_assert!(*block_off < 16);
				if text_in_out.is_empty() {
					return;
				}

				let mut pos = 0usize;

				// If we're mid-block, finish that block byte-by-byte.
				if *block_off != 0 {
					let mut keystream = *ctr;
					self.cipher.encrypt(&mut keystream);
					while *block_off < 16 && pos < text_in_out.len() {
						text_in_out[pos] ^= keystream[*block_off];
						*block_off += 1;
						pos += 1;
					}
					if *block_off == 16 {
						*block_off = 0;
						ctr128_inc_be(ctr);
					}
				}

				// Process full blocks. Prefer 4x blocks when possible.
				while pos + 16 * 4 <= text_in_out.len() {
					let c0 = *ctr;
					let mut c1 = c0;
					let mut c2 = c0;
					let mut c3 = c0;
					ctr128_inc_be(&mut c1);
					ctr128_inc_be_by(&mut c2, 2);
					ctr128_inc_be_by(&mut c3, 3);

					let chunk = &mut text_in_out[pos..pos + 16 * 4];
					// SAFETY: chunk is exactly 64 bytes.
					let b0 = unsafe { &mut *(chunk.as_mut_ptr().add(0) as *mut [u8; 16]) };
					let b1 = unsafe { &mut *(chunk.as_mut_ptr().add(16) as *mut [u8; 16]) };
					let b2 = unsafe { &mut *(chunk.as_mut_ptr().add(32) as *mut [u8; 16]) };
					let b3 = unsafe { &mut *(chunk.as_mut_ptr().add(48) as *mut [u8; 16]) };

					self.cipher.encrypt_4_blocks_xor([&c0, &c1, &c2, &c3], [b0, b1, b2, b3]);

					ctr128_inc_be_by(ctr, 4);
					pos += 16 * 4;
				}

				while pos + 16 <= text_in_out.len() {
					let mut keystream = *ctr;
					self.cipher.encrypt(&mut keystream);
					// SAFETY: 16-byte aligned slice.
					let block = unsafe {
						&mut *(text_in_out.as_mut_ptr().add(pos) as *mut [u8; 16])
					};
					xor_si128_inplace(block, &keystream);
					ctr128_inc_be(ctr);
					pos += 16;
				}

				// Remainder (<16 bytes)
				let rem = &mut text_in_out[pos..];
				if !rem.is_empty() {
					let mut keystream = *ctr;
					self.cipher.encrypt(&mut keystream);
					for i in 0..rem.len() {
						rem[i] ^= keystream[i];
					}
					*block_off = rem.len();
					debug_assert!(*block_off < 16);
				}
			}
		}
	};
}

use crate::crypto::aes::soft::AES128 as AES128Soft;
use crate::crypto::aes::soft::AES256 as AES256Soft;

impl_block_cipher_with_ctr_mode!(AES128CtrSoft, AES128Soft, 16);
impl_block_cipher_with_ctr_mode!(AES256CtrSoft, AES256Soft, 32);

cfg_if::cfg_if! {
	if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
		use crate::crypto::aes::x86::AES128 as AES128SSE;
		use crate::crypto::aes::x86::AES256 as AES256SSE;
		impl_block_cipher_with_ctr_mode!(AES128CtrSSE, AES128SSE, 16, "sse2,aes");
		impl_block_cipher_with_ctr_mode!(AES256CtrSSE, AES256SSE, 32, "sse2,aes");
		type AES128CtrHW = AES128CtrSSE;
		type AES256CtrHW = AES256CtrSSE;

		use crate::crypto::aes::x86_avx::AES128 as AES128AVX;
		use crate::crypto::aes::x86_avx::AES256 as AES256AVX;
		impl_block_cipher_with_ctr_mode!(AES128CtrAVX, AES128AVX, 16, "avx,aes");
		impl_block_cipher_with_ctr_mode!(AES256CtrAVX, AES256AVX, 32, "avx,aes");

		#[cfg(avx512_feature)]
		use crate::crypto::aes::x86_avx512::AES128 as AES128AVX512;
		#[cfg(avx512_feature)]
		use crate::crypto::aes::x86_avx512::AES256 as AES256AVX512;
		#[cfg(avx512_feature)]
		impl_block_cipher_with_ctr_mode!(
			AES128CtrAVX512,
			AES128AVX512,
			16,
			"avx512f,avx512bw,avx512vl,vaes"
		);
		#[cfg(avx512_feature)]
		impl_block_cipher_with_ctr_mode!(
			AES256CtrAVX512,
			AES256AVX512,
			32,
			"avx512f,avx512bw,avx512vl,vaes"
		);
	} else if #[cfg(any(target_arch = "aarch64", target_arch = "arm"))] {
		use crate::crypto::aes::arm::AES128 as AES128Arm;
		use crate::crypto::aes::arm::AES256 as AES256Arm;
		impl_block_cipher_with_ctr_mode!(AES128CtrHW, AES128Arm, 16);
		impl_block_cipher_with_ctr_mode!(AES256CtrHW, AES256Arm, 32);
	}
}

cfg_if::cfg_if! {
	if #[cfg(all(avx512_feature, any(target_arch = "x86", target_arch = "x86_64"), target_feature = "vaes", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx512bw"))] {
		pub type AES128Ctr = AES128CtrAVX512;
		pub type AES256Ctr = AES256CtrAVX512;
	} else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx", target_feature = "aes"))] {
		pub type AES128Ctr = AES128CtrAVX;
		pub type AES256Ctr = AES256CtrAVX;
	} else if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sse2", target_feature = "aes"))] {
		pub type AES128Ctr = AES128CtrSSE;
		pub type AES256Ctr = AES256CtrSSE;
	} else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "aes"))] {
		pub type AES128Ctr = AES128CtrHW;
		pub type AES256Ctr = AES256CtrHW;
	} else if #[cfg(all(target_arch = "arm", target_feature = "neon", target_feature = "aes"))] {
		pub type AES128Ctr = AES128CtrHW;
		pub type AES256Ctr = AES256CtrHW;
	} else {
		pub type AES128Ctr = AES128CtrDynamic;
		pub type AES256Ctr = AES256CtrDynamic;
	}
}

// x86: 0 - avx aes-ni, 1 - sse aes-ni, 2 - soft, 3 - avx512 (vaes)
// arm/aarch64: 0 - aes, 2 - soft
static mut AES_128_CTR_IDX: u32 = u32::MAX;
static mut AES_256_CTR_IDX: u32 = u32::MAX;

pub union AES128CtrDynamic {
	#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
	hw: ManuallyDrop<AES128CtrHW>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	avx: ManuallyDrop<AES128CtrAVX>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	#[cfg(avx512_feature)]
	avx512: ManuallyDrop<AES128CtrAVX512>,
	sw: ManuallyDrop<AES128CtrSoft>,
}

pub union AES256CtrDynamic {
	#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
	hw: ManuallyDrop<AES256CtrHW>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	avx: ManuallyDrop<AES256CtrAVX>,
	#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
	#[cfg(avx512_feature)]
	avx512: ManuallyDrop<AES256CtrAVX512>,
	sw: ManuallyDrop<AES256CtrSoft>,
}

impl AES128CtrDynamic {
	pub const KEY_LEN: usize = 16;
	pub const BLOCK_LEN: usize = 16;
	pub const NONCE_LEN: usize = 16;

	pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
		unsafe {
			if AES_128_CTR_IDX == u32::MAX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				{
					if cfg!(avx512_feature)
						&& crate::is_hw_feature_detected!(
							"x86" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
							"x86_64" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
						)
					{
						AES_128_CTR_IDX = 3;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("avx", "aes"),
						"x86_64" => ("avx", "aes"),
					) {
						AES_128_CTR_IDX = 0;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("sse2", "aes"),
						"x86_64" => ("sse2", "aes"),
					) {
						AES_128_CTR_IDX = 1;
					} else {
						AES_128_CTR_IDX = 2;
					}
				}
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				{
					if crate::is_hw_feature_detected!(
						"aarch64" => ("aes", "neon"),
						"arm" => ("neon", "aes"),
					) {
						AES_128_CTR_IDX = 0;
					} else {
						AES_128_CTR_IDX = 2;
					}
				}
				#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
				{
					AES_128_CTR_IDX = 2;
				}
			}

			match AES_128_CTR_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => AES128CtrDynamic { avx: ManuallyDrop::new(AES128CtrAVX::new(key)) },
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => AES128CtrDynamic { hw: ManuallyDrop::new(AES128CtrHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => AES128CtrDynamic { hw: ManuallyDrop::new(AES128CtrHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => AES128CtrDynamic { avx512: ManuallyDrop::new(AES128CtrAVX512::new(key)) },
				2 => AES128CtrDynamic { sw: ManuallyDrop::new(AES128CtrSoft::new(key)) },
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
	pub fn xor_slice(&self, nonce: &[u8; 16], text_in_out: &mut [u8]) {
		unsafe {
			match AES_128_CTR_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.xor_slice(nonce, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.xor_slice(nonce, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.xor_slice(nonce, text_in_out),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.xor_slice(nonce, text_in_out),
				2 => self.sw.xor_slice(nonce, text_in_out),
				_ => unreachable!(),
			}
		}
	}

	#[inline(never)]
	pub fn xor_slice_streaming(&self, ctr: &mut [u8; 16], block_off: &mut usize, text_in_out: &mut [u8]) {
		unsafe {
			match AES_128_CTR_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.xor_slice_streaming(ctr, block_off, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.xor_slice_streaming(ctr, block_off, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.xor_slice_streaming(ctr, block_off, text_in_out),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.xor_slice_streaming(ctr, block_off, text_in_out),
				2 => self.sw.xor_slice_streaming(ctr, block_off, text_in_out),
				_ => unreachable!(),
			}
		}
	}
}

impl Drop for AES128CtrDynamic {
	#[inline]
	fn drop(&mut self) {
		unsafe {
			match AES_128_CTR_IDX {
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

impl AES256CtrDynamic {
	pub const KEY_LEN: usize = 32;
	pub const BLOCK_LEN: usize = 16;
	pub const NONCE_LEN: usize = 16;

	pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
		unsafe {
			if AES_256_CTR_IDX == u32::MAX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				{
					if cfg!(avx512_feature)
						&& crate::is_hw_feature_detected!(
							"x86" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
							"x86_64" => ("avx512f", "avx512bw", "avx512vl", "vaes"),
						)
					{
						AES_256_CTR_IDX = 3;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("avx", "aes"),
						"x86_64" => ("avx", "aes"),
					) {
						AES_256_CTR_IDX = 0;
					} else if crate::is_hw_feature_detected!(
						"x86" => ("sse2", "aes"),
						"x86_64" => ("sse2", "aes"),
					) {
						AES_256_CTR_IDX = 1;
					} else {
						AES_256_CTR_IDX = 2;
					}
				}
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				{
					if crate::is_hw_feature_detected!(
						"aarch64" => ("aes", "neon"),
						"arm" => ("neon", "aes"),
					) {
						AES_256_CTR_IDX = 0;
					} else {
						AES_256_CTR_IDX = 2;
					}
				}
				#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
				{
					AES_256_CTR_IDX = 2;
				}
			}

			match AES_256_CTR_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => AES256CtrDynamic { avx: ManuallyDrop::new(AES256CtrAVX::new(key)) },
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => AES256CtrDynamic { hw: ManuallyDrop::new(AES256CtrHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => AES256CtrDynamic { hw: ManuallyDrop::new(AES256CtrHW::new(key)) },
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => AES256CtrDynamic { avx512: ManuallyDrop::new(AES256CtrAVX512::new(key)) },
				2 => AES256CtrDynamic { sw: ManuallyDrop::new(AES256CtrSoft::new(key)) },
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
	pub fn xor_slice(&self, nonce: &[u8; 16], text_in_out: &mut [u8]) {
		unsafe {
			match AES_256_CTR_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.xor_slice(nonce, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.xor_slice(nonce, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.xor_slice(nonce, text_in_out),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.xor_slice(nonce, text_in_out),
				2 => self.sw.xor_slice(nonce, text_in_out),
				_ => unreachable!(),
			}
		}
	}

	#[inline(never)]
	pub fn xor_slice_streaming(&self, ctr: &mut [u8; 16], block_off: &mut usize, text_in_out: &mut [u8]) {
		unsafe {
			match AES_256_CTR_IDX {
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				0 => self.avx.xor_slice_streaming(ctr, block_off, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				1 => self.hw.xor_slice_streaming(ctr, block_off, text_in_out),
				#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
				#[cfg(avx512_feature)]
				3 => self.avx512.xor_slice_streaming(ctr, block_off, text_in_out),
				#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
				0 => self.hw.xor_slice_streaming(ctr, block_off, text_in_out),
				2 => self.sw.xor_slice_streaming(ctr, block_off, text_in_out),
				_ => unreachable!(),
			}
		}
	}
}

impl Drop for AES256CtrDynamic {
	#[inline]
	fn drop(&mut self) {
		unsafe {
			match AES_256_CTR_IDX {
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

	macro_rules! test_aes128_ctr_nist_impl {
		($cipher_type:ty) => {{
			// NIST SP 800-38A, F.5.1 CTR-AES128
			let key: [u8; 16] = [
				0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
				0x4f, 0x3c,
			];
			let iv: [u8; 16] = [
				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
				0xfe, 0xff,
			];
			let plaintext: [u8; 64] = [
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
				0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
				0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
				0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
				0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
			];
			let expected_ciphertext: [u8; 64] = [
				0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99,
				0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17,
				0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff, 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3,
				0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda,
				0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
			];

			let cipher = <$cipher_type>::new(key);
			let mut buf = plaintext;
			cipher.xor_slice(&iv, &mut buf);
			assert_eq!(
				buf, expected_ciphertext,
				"cipher_type: {} ciphertext mismatch",
				core::any::type_name::<$cipher_type>()
			);
		}};
	}

	macro_rules! test_aes256_ctr_nist_impl {
		($cipher_type:ty) => {{
			// NIST SP 800-38A, F.5.5 CTR-AES256
			let key: [u8; 32] = [
				0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
				0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
				0x09, 0x14, 0xdf, 0xf4,
			];
			let iv: [u8; 16] = [
				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
				0xfe, 0xff,
			];
			let plaintext: [u8; 64] = [
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
				0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
				0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4,
				0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45,
				0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
			];
			let expected_ciphertext: [u8; 64] = [
				0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3,
				0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90,
				0xca, 0xca, 0xf5, 0xc5, 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70,
				0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
				0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
			];

			let cipher = <$cipher_type>::new(key);
			let mut buf = plaintext;
			cipher.xor_slice(&iv, &mut buf);
			assert_eq!(
				buf, expected_ciphertext,
				"cipher_type: {} ciphertext mismatch",
				core::any::type_name::<$cipher_type>()
			);
		}};
	}

	macro_rules! test_ctr_streaming_matches_one_shot_impl {
		($cipher_type:ty, $key_len:expr) => {{
			let key = [0x11u8; $key_len];
			let iv = [0x22u8; 16];
			let mut plain = vec![0u8; 1000];
			for (i, b) in plain.iter_mut().enumerate() {
				*b = (i as u8).wrapping_mul(31).wrapping_add(7);
			}

			let cipher = <$cipher_type>::new(key);
			let mut one_shot = plain.clone();
			cipher.xor_slice(&iv, &mut one_shot);

			let mut chunked = plain.clone();
			let mut ctr = iv;
			let mut off = 0usize;
			for chunk in chunked.chunks_mut(7) {
				cipher.xor_slice_streaming(&mut ctr, &mut off, chunk);
			}
			assert_eq!(
				one_shot, chunked,
				"cipher_type: {} streaming mismatch",
				core::any::type_name::<$cipher_type>()
			);
		}};
	}

	#[test]
	fn test_aes_ctr_all_backends() {
		// Always test soft backends.
		test_aes128_ctr_nist_impl!(AES128CtrSoft);
		test_aes256_ctr_nist_impl!(AES256CtrSoft);
		test_ctr_streaming_matches_one_shot_impl!(AES128CtrSoft, 16);
		test_ctr_streaming_matches_one_shot_impl!(AES256CtrSoft, 32);

		// x86 / x86_64 feature-gated backends.
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		if crate::is_hw_feature_detected!("sse2", "aes") {
			test_aes128_ctr_nist_impl!(AES128CtrSSE);
			test_aes256_ctr_nist_impl!(AES256CtrSSE);
			test_ctr_streaming_matches_one_shot_impl!(AES128CtrSSE, 16);
			test_ctr_streaming_matches_one_shot_impl!(AES256CtrSSE, 32);
		}
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		if crate::is_hw_feature_detected!("avx", "aes") {
			test_aes128_ctr_nist_impl!(AES128CtrAVX);
			test_aes256_ctr_nist_impl!(AES256CtrAVX);
			test_ctr_streaming_matches_one_shot_impl!(AES128CtrAVX, 16);
			test_ctr_streaming_matches_one_shot_impl!(AES256CtrAVX, 32);
		}
		#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
		#[cfg(avx512_feature)]
		if crate::is_hw_feature_detected!("avx512f", "avx512bw", "avx512vl", "vaes") {
			test_aes128_ctr_nist_impl!(AES128CtrAVX512);
			test_aes256_ctr_nist_impl!(AES256CtrAVX512);
			test_ctr_streaming_matches_one_shot_impl!(AES128CtrAVX512, 16);
			test_ctr_streaming_matches_one_shot_impl!(AES256CtrAVX512, 32);
		}

		// ARM/AArch64 hardware AES backend.
		#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
		if crate::is_hw_feature_detected!(
			"aarch64" => ("aes", "neon"),
			"arm" => ("aes", "neon"),
		) {
			test_aes128_ctr_nist_impl!(AES128CtrHW);
			test_aes256_ctr_nist_impl!(AES256CtrHW);
			test_ctr_streaming_matches_one_shot_impl!(AES128CtrHW, 16);
			test_ctr_streaming_matches_one_shot_impl!(AES256CtrHW, 32);
		}

		// Finally, always test dynamic dispatch.
		test_aes128_ctr_nist_impl!(AES128CtrDynamic);
		test_aes256_ctr_nist_impl!(AES256CtrDynamic);
		test_ctr_streaming_matches_one_shot_impl!(AES128CtrDynamic, 16);
		test_ctr_streaming_matches_one_shot_impl!(AES256CtrDynamic, 32);
	}
}

