use crate::utils::portable::xor_si128_inplace;
use crate::utils::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

pub const NONCE_LEN: usize = 96 / 8;
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

const GCM_BLOCK_LEN: usize = 16;

macro_rules! impl_block_cipher_with_gcm_mode {
    ($name:tt$(,$blocks_4x4:literal)?, $cipher:ty, $ghash:ty, $tlen:tt$(, $feature:literal)?) => {
        #[derive(Clone, Copy)]
        pub struct $name {
            cipher: $cipher,
            ghash: $ghash,
        }

        impl $name {
            #[inline(always)]
            fn ctr32(counter_block: &mut [u8; 16]) -> [u8; 16] {
                let counter = u32::from_be_bytes(unsafe { crate::utils::slice_to_array_at(counter_block, 12).clone() });
                let counter = counter.wrapping_add(1);
                unsafe {
                    *crate::utils::slice_to_array_at_mut(counter_block, Self::NONCE_LEN) = counter.to_be_bytes();
                }
                counter_block.clone()
            }

            #[inline(always)]
            fn ctr32x4(counter_block: &mut [u8; 16]) -> [[u8; 16]; 4] {
                [
                    Self::ctr32(counter_block),
                    Self::ctr32(counter_block),
                    Self::ctr32(counter_block),
                    Self::ctr32(counter_block),
                ]
            }

            #[inline(always)]
            fn ctr32_(nonce_block: &[u8; 16], counter: &mut u32) -> [u8; 16] {
                let mut ctr = nonce_block.clone();
                unsafe {
                    *crate::utils::slice_to_array_at_mut(&mut ctr, Self::NONCE_LEN) = counter.wrapping_add(1).to_be_bytes();
                }
                *counter = counter.wrapping_add(1);
                ctr
            }

            #[inline(always)]
            fn ctr32x4_(nonce_block: &[u8; 16], counter: &mut u32) -> [[u8; 16]; 4] {
                let mut ctr0 = nonce_block.clone();
                let mut ctr1 = nonce_block.clone();
                let mut ctr2 = nonce_block.clone();
                let mut ctr3 = nonce_block.clone();
                unsafe {
                    *crate::utils::slice_to_array_at_mut(&mut ctr0, Self::NONCE_LEN) = counter.wrapping_add(1).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr1, Self::NONCE_LEN) = counter.wrapping_add(2).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr2, Self::NONCE_LEN) = counter.wrapping_add(3).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr3, Self::NONCE_LEN) = counter.wrapping_add(4).to_be_bytes();
                }
                *counter = counter.wrapping_add(4);
                [ctr0, ctr1, ctr2, ctr3]
            }

            #[inline(always)]
            fn ctr32x6_(nonce_block: &[u8; 16], counter: &mut u32) -> [[u8; 16]; 6] {
                let mut ctr0 = nonce_block.clone();
                let mut ctr1 = nonce_block.clone();
                let mut ctr2 = nonce_block.clone();
                let mut ctr3 = nonce_block.clone();
                let mut ctr4 = nonce_block.clone();
                let mut ctr5 = nonce_block.clone();
                unsafe {
                    *crate::utils::slice_to_array_at_mut(&mut ctr0, Self::NONCE_LEN) = counter.wrapping_add(1).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr1, Self::NONCE_LEN) = counter.wrapping_add(2).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr2, Self::NONCE_LEN) = counter.wrapping_add(3).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr3, Self::NONCE_LEN) = counter.wrapping_add(4).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr4, Self::NONCE_LEN) = counter.wrapping_add(5).to_be_bytes();
                    *crate::utils::slice_to_array_at_mut(&mut ctr5, Self::NONCE_LEN) = counter.wrapping_add(6).to_be_bytes();
                }
                *counter = counter.wrapping_add(6);
                [ctr0, ctr1, ctr2, ctr3, ctr4, ctr5]
            }

            #[inline(always)]
            #[allow(unused_variables)]
            fn ctr32x6_next(nonce_block: &[u8; 16], ectr: &mut [[u8; 16]; 6], counter: &mut u32) {
                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                {
                    let ret = Self::ctr32x6_(&ectr[ectr.len() - 1], counter);
                    ectr[0] = ret[0];
                    ectr[1] = ret[1];
                    ectr[2] = ret[2];
                    ectr[3] = ret[3];
                    ectr[4] = ret[4];
                    ectr[5] = ret[5];
                }
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    unsafe {
                        let mut ctr0_xmm;
                        let mut ctr1_xmm;
                        let mut ctr2_xmm;
                        let mut ctr3_xmm;
                        let mut ctr4_xmm;
                        let mut ctr5_xmm;

                        ctr5_xmm = _mm_loadu_si128(ectr[5].as_ptr() as _);
                        
                        let bswap_shuffle = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
                        ctr5_xmm = _mm_shuffle_epi8(ctr5_xmm, bswap_shuffle);

                        let delta = _mm_setr_epi32(1, 0, 0, 0);
                        ctr0_xmm = _mm_add_epi32(ctr5_xmm, delta);
                        ctr1_xmm = _mm_add_epi32(ctr0_xmm, delta);
                        ctr2_xmm = _mm_add_epi32(ctr1_xmm, delta);
                        ctr3_xmm = _mm_add_epi32(ctr2_xmm, delta);
                        ctr4_xmm = _mm_add_epi32(ctr3_xmm, delta);
                        ctr5_xmm = _mm_add_epi32(ctr4_xmm, delta);

                        ctr0_xmm = _mm_shuffle_epi8(ctr0_xmm, bswap_shuffle);
                        ctr1_xmm = _mm_shuffle_epi8(ctr1_xmm, bswap_shuffle);
                        ctr2_xmm = _mm_shuffle_epi8(ctr2_xmm, bswap_shuffle);
                        ctr3_xmm = _mm_shuffle_epi8(ctr3_xmm, bswap_shuffle);
                        ctr4_xmm = _mm_shuffle_epi8(ctr4_xmm, bswap_shuffle);
                        ctr5_xmm = _mm_shuffle_epi8(ctr5_xmm, bswap_shuffle);

                        _mm_storeu_si128(ectr[0].as_mut_ptr() as _, ctr0_xmm);
                        _mm_storeu_si128(ectr[1].as_mut_ptr() as _, ctr1_xmm);
                        _mm_storeu_si128(ectr[2].as_mut_ptr() as _, ctr2_xmm);
                        _mm_storeu_si128(ectr[3].as_mut_ptr() as _, ctr3_xmm);
                        _mm_storeu_si128(ectr[4].as_mut_ptr() as _, ctr4_xmm);
                        _mm_storeu_si128(ectr[5].as_mut_ptr() as _, ctr5_xmm);
                    }
                    *counter = counter.wrapping_add(6);
                }
            }

            #[inline(always)]
            fn ctr32_4x4_(nonce_block: &[u8; 16], counter: &mut u32) -> [[u8; 64]; 4] {
                let mut ctr = [nonce_block.clone(); 16];

                crate::const_loop!(i, 0, 16, {
                    unsafe {
                        *crate::utils::slice_to_array_at_mut(&mut ctr[i], Self::NONCE_LEN) = counter.wrapping_add((i + 1) as u32).to_be_bytes();
                    }
                });
                *counter = counter.wrapping_add(16);
                unsafe {
                    core::mem::transmute::<[[u8; 16]; 16], [[u8; 64]; 4]>(ctr)
                }
            }

            #[inline(always)]
            #[allow(unused_variables)]
            fn ctr32_4x4_next(nonce_block: &[u8; 16], ctrs: &mut [[u8; 64]; 4], counter: &mut u32) {
                #[cfg(not(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature)))]
                {
                    let ret = Self::ctr32_4x4_(nonce_block, counter);
                    ctrs[0] = ret[0];
                    ctrs[1] = ret[1];
                    ctrs[2] = ret[2];
                    ctrs[3] = ret[3];
                }
                #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), avx512_feature))]
                {
                    unsafe {
                        let mut ctr_zmm0;
                        let mut ctr_zmm1;
                        let mut ctr_zmm2;
                        let mut ctr_zmm3 = _mm512_loadu_si512(ctrs[3].as_ptr() as _);

                        if counter.wrapping_add(16) >> 8 == counter.wrapping_sub(3) >> 8 {
                            let delta = _mm512_broadcast_i32x4(_mm_set_epi32(0x4000000, 0, 0, 0));
                            ctr_zmm0 = _mm512_add_epi32(ctr_zmm3, delta);
                            ctr_zmm1 = _mm512_add_epi32(ctr_zmm0, delta);
                            ctr_zmm2 = _mm512_add_epi32(ctr_zmm1, delta);
                            ctr_zmm3 = _mm512_add_epi32(ctr_zmm2, delta);
                        } else {
                            #[cold]
                            #[inline(always)]
                            fn cold() {}
                            cold();

                            let bswap_shuffle = _mm512_broadcast_i32x4(_mm_set_epi8(
                                0, 1, 2, 3, 4, 5, 6, 7,
                                8, 9, 10, 11, 12, 13, 14, 15
                            ));
                            ctr_zmm3 = _mm512_shuffle_epi8(ctr_zmm3, bswap_shuffle);

                            let delta = _mm512_broadcast_i32x4(_mm_setr_epi32(4, 0, 0, 0));
                            ctr_zmm0 = _mm512_add_epi32(ctr_zmm3, delta);
                            ctr_zmm1 = _mm512_add_epi32(ctr_zmm0, delta);
                            ctr_zmm2 = _mm512_add_epi32(ctr_zmm1, delta);
                            ctr_zmm3 = _mm512_add_epi32(ctr_zmm2, delta);

                            ctr_zmm0 = _mm512_shuffle_epi8(ctr_zmm0, bswap_shuffle);
                            ctr_zmm1 = _mm512_shuffle_epi8(ctr_zmm1, bswap_shuffle);
                            ctr_zmm2 = _mm512_shuffle_epi8(ctr_zmm2, bswap_shuffle);
                            ctr_zmm3 = _mm512_shuffle_epi8(ctr_zmm3, bswap_shuffle);
                        }

                        _mm512_storeu_si512(ctrs[0].as_mut_ptr() as _, ctr_zmm0);
                        _mm512_storeu_si512(ctrs[1].as_mut_ptr() as _, ctr_zmm1);
                        _mm512_storeu_si512(ctrs[2].as_mut_ptr() as _, ctr_zmm2);
                        _mm512_storeu_si512(ctrs[3].as_mut_ptr() as _, ctr_zmm3);
                        *counter = counter.wrapping_add(16);
                    }
                }
            }
        }

        // 6.  AES GCM Algorithms for Secure Shell
        // https://tools.ietf.org/html/rfc5647#section-6
        $(#[unsafe_target_feature($feature)])?
        impl $name {
            pub const KEY_LEN: usize = <$cipher>::KEY_LEN;
            pub const BLOCK_LEN: usize = <$cipher>::BLOCK_LEN;
            // NOTE: variable-length IVs are supported by the GCM authenticated encryption algorithm,
            //       but the current practice is to restrict the IV length to 12 octets.
            //       This is because the IV is concatenated with the BlockCounter (u32) to form a Nonce of 12 + 4 = 16 octets.
            pub const NONCE_LEN: usize = 12;
            pub const TAG_LEN: usize = $tlen;

            #[cfg(target_pointer_width = "64")]
            pub const A_MAX: usize = 2305843009213693951; // 2^61 - 1
            #[cfg(target_pointer_width = "32")]
            pub const A_MAX: usize = usize::MAX; // 2^32 - 1

            #[cfg(target_pointer_width = "64")]
            pub const P_MAX: usize = 68719476735; // 2^36 - 31
            #[cfg(target_pointer_width = "32")]
            pub const P_MAX: usize = usize::MAX - Self::TAG_LEN; // 2^36 - 31

            #[cfg(target_pointer_width = "64")]
            pub const C_MAX: usize = 68719476721; // 2^36 - 15
            #[cfg(target_pointer_width = "32")]
            pub const C_MAX: usize = usize::MAX; // 2^36 - 15

            pub const N_MIN: usize = Self::NONCE_LEN;
            pub const N_MAX: usize = Self::NONCE_LEN;

            #[inline]
            pub fn new(key: [u8; 16]) -> Self {
                // NOTE: GCM works only with block ciphers that have a block size of 16 bytes.
                assert_eq!(Self::BLOCK_LEN, GCM_BLOCK_LEN);
                assert_eq!(Self::BLOCK_LEN, <$ghash>::BLOCK_LEN);

                let cipher = <$cipher>::new(key);

                let mut h = [0u8; Self::BLOCK_LEN];
                cipher.encrypt(&mut h);

                let ghash = <$ghash>::new(&h);

                Self { cipher, ghash }
            }

            #[inline]
            pub fn from_slice(key: &[u8]) -> Self {
                // NOTE: GCM works only with block ciphers that have a block size of 16 bytes.
                assert_eq!(Self::BLOCK_LEN, GCM_BLOCK_LEN);
                assert_eq!(Self::BLOCK_LEN, <$ghash>::BLOCK_LEN);
                assert_eq!(key.len(), Self::KEY_LEN);

                let cipher = <$cipher>::from_slice(key);

                let mut h = [0u8; Self::BLOCK_LEN];
                cipher.encrypt(&mut h);

                let ghash = <$ghash>::new(&h);

                Self { cipher, ghash }
            }

            #[inline(always)]
            pub fn encrypt_slice(&self, nonce: &[u8; 12], aad: &[u8], aead_pkt: &mut [u8]) {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let plen = aead_pkt.len() - Self::TAG_LEN;
                let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);
                // SAFETY: tag_out is guaranteed to be of length Self::TAG_LEN
                let tag_out = unsafe { &mut *(tag_out.as_mut_ptr() as *mut [u8; Self::TAG_LEN]) };

                self.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out)
            }

            #[inline]
            pub fn decrypt_slice(&self, nonce: &[u8; 12], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let clen = aead_pkt.len() - Self::TAG_LEN;
                let (ciphertext_in_plaintext_out, tag_in) = aead_pkt.split_at_mut(clen);
                // SAFETY: tag_in is guaranteed to be of length Self::TAG_LEN
                let tag_in = unsafe { &*(tag_in.as_ptr() as *const [u8; Self::TAG_LEN]) };

                self.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in)
            }
            
            #[inline]
            pub fn encrypt_slice_detached(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                plaintext_in_ciphertext_out: &mut [u8],
                tag_out: &mut [u8; $tlen],
            ) {
                // NOTE: the first 12 bytes are IV, the last 4 bytes are BlockCounter.
                assert_eq!(nonce.len(), Self::NONCE_LEN);

                let alen = aad.len();
                let plen = plaintext_in_ciphertext_out.len();
                let tlen = tag_out.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(plen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut mac = self.ghash.clone();

                let mut counter = 1u32;
                let mut counter_block = [0u8; Self::BLOCK_LEN];
                counter_block[..Self::NONCE_LEN].copy_from_slice(&nonce[..Self::NONCE_LEN]);
                unsafe {
                    *crate::utils::slice_to_array_at_mut(&mut counter_block, Self::NONCE_LEN) = counter.to_be_bytes();
                }

                let mut base_ectr = counter_block.clone();
                self.cipher.encrypt(&mut base_ectr);

                mac.update(aad);

                let mut start = 0;
                let mut plen_remain = plen;

                const IS_SOFT: bool = <$cipher>::IS_SOFT && <$ghash>::IS_SOFT;

                $(
                _ = $blocks_4x4;
                if plen_remain >= Self::BLOCK_LEN * 4 * 4 {
                    let mut ctrs = Self::ctr32_4x4_(&mut counter_block, &mut counter);
                    let mut blocks = [
                        unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start).clone()},
                        unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4).clone()},
                        unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4 * 2).clone()},
                        unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4 * 3).clone()},
                    ];
                    debug_assert!(ctrs[0].len() == Self::BLOCK_LEN * 4);
                    self.cipher.encrypt_blocks_xor_4x4(
                        ctrs,
                        &mut blocks,
                    );
                    
                    Self::ctr32_4x4_next(&counter_block, &mut ctrs, &mut counter);
                    unsafe {
                        crate::const_loop!(i, 0, 4, {
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + i * Self::BLOCK_LEN * 4) = blocks[i];
                        });
                    }

                    start += Self::BLOCK_LEN * 4 * 4;
                    plen_remain -= Self::BLOCK_LEN * 4 * 4;

                    while plen_remain >= Self::BLOCK_LEN * 4 * 4 {
                        let mut next_blocks = [
                            unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4 * 0).clone()},
                            unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4 * 1).clone()},
                            unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4 * 2).clone()},
                            unsafe {slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4 * 3).clone()},
                        ];
                        self.cipher.encrypt_blocks_xor_4x4(ctrs, &mut next_blocks);
                        mac.update_blocks_4x4(&blocks);

                        blocks = next_blocks;

                        Self::ctr32_4x4_next(&counter_block, &mut ctrs, &mut counter);

                        unsafe {
                            crate::const_loop!(i, 0, 4, {
                                *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + i * Self::BLOCK_LEN * 4) = blocks[i];
                            });
                        }

                        start += Self::BLOCK_LEN * 4 * 4;
                        plen_remain -= Self::BLOCK_LEN * 4 * 4;
                    }

                    counter -= 16;
                    mac.update_blocks_4x4(&blocks);
                }
                )?

                #[cfg(ghash_block_x6)]
                if !<$cipher>::IS_SOFT && !<$ghash>::IS_SOFT && plen_remain >= Self::BLOCK_LEN * 6 {
                    // let [mut ectr0, mut ectr1, mut ectr2, mut ectr3, mut ectr4, mut ectr5] = Self::ctr32x6_(&counter_block, &mut counter);
                    let mut ectr = Self::ctr32x6_(&mut counter_block, &mut counter);

                    let mut block0 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start).clone()};
                    let mut block1 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN).clone()};
                    let mut block2 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2).clone()};
                    let mut block3 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3).clone()};
                    let mut block4 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4).clone()};
                    let mut block5 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 5).clone()};

                    self.cipher.encrypt_6_blocks_xor(
                        std::array::from_fn(|i| &ectr[i]),
                        [&mut block0,
                        &mut block1,
                        &mut block2,
                        &mut block3,
                        &mut block4,
                        &mut block5],
                    );

                    Self::ctr32x6_next(&counter_block, &mut ectr, &mut counter);

                    unsafe {
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start) = block0;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN) = block1;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2) = block2;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3) = block3;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4) = block4;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 5) = block5;
                    }

                    start += Self::BLOCK_LEN * 6;
                    plen_remain -= Self::BLOCK_LEN * 6;

                    while plen_remain >= Self::BLOCK_LEN * 6 {
                        let next_block0 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start).clone()};
                        let next_block1 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN).clone()};
                        let next_block2 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2).clone()};
                        let next_block3 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3).clone()};
                        let next_block4 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4).clone()};
                        let next_block5 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 5).clone()};

                        mac.update_6block_for_aes([&block0, &block1, &block2, &block3, &block4, &block5]);

                        block0 = next_block0;
                        block1 = next_block1;
                        block2 = next_block2;
                        block3 = next_block3;
                        block4 = next_block4;
                        block5 = next_block5;

                        self.cipher.encrypt_6_blocks_xor(
                            std::array::from_fn(|i| &ectr[i]),
                            [&mut block0,
                            &mut block1,
                            &mut block2,
                            &mut block3,
                            &mut block4,
                            &mut block5,],
                        );
                        Self::ctr32x6_next(&counter_block, &mut ectr, &mut counter);

                        unsafe {
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start) = block0;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN) = block1;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2) = block2;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3) = block3;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 4) = block4;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 5) = block5;
                        }

                        start += Self::BLOCK_LEN * 6;
                        plen_remain -= Self::BLOCK_LEN * 6;
                    }

                    counter -= 6;
                    mac.update_6block_for_aes([&block0, &block1, &block2, &block3, &block4, &block5]);
                }

                while IS_SOFT && plen_remain >= Self::BLOCK_LEN * 4 {
                    let [mut ectr0, mut ectr1, mut ectr2, mut ectr3] = Self::ctr32x4(&mut counter_block);
                    counter += 4;
                    self.cipher.encrypt_4_blocks(&mut ectr0, &mut ectr1, &mut ectr2, &mut ectr3);

                    let mut block0 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start).clone()};
                    let mut block1 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN).clone()};
                    let mut block2 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2).clone()};
                    let mut block3 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3).clone()};
                    xor_si128_inplace(&mut block0, &ectr0);
                    xor_si128_inplace(&mut block1, &ectr1);
                    xor_si128_inplace(&mut block2, &ectr2);
                    xor_si128_inplace(&mut block3, &ectr3);
                    unsafe {
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start) = block0;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN) = block1;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2) = block2;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3) = block3;
                    }
                    mac.update_4block_for_aes([&block0, &block1, &block2, &block3]);

                    start += Self::BLOCK_LEN * 4;
                    plen_remain -= Self::BLOCK_LEN * 4;
                }
                
                if !IS_SOFT && plen_remain >= Self::BLOCK_LEN * 4 {
                    let [mut ectr0, mut ectr1, mut ectr2, mut ectr3] = Self::ctr32x4_(&counter_block, &mut counter);

                    let mut block0 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start).clone()};
                    let mut block1 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN).clone()};
                    let mut block2 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2).clone()};
                    let mut block3 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3).clone()};

                    self.cipher.encrypt_4_blocks_xor(
                        [&ectr0,
                        &ectr1,
                        &ectr2,
                        &ectr3],
                        [&mut block0,
                        &mut block1,
                        &mut block2,
                        &mut block3],
                    );
                    
                    [ectr0, ectr1, ectr2, ectr3] = Self::ctr32x4_(&counter_block, &mut counter);

                    unsafe {
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start) = block0;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN) = block1;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2) = block2;
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3) = block3;
                    }

                    start += Self::BLOCK_LEN * 4;
                    plen_remain -= Self::BLOCK_LEN * 4;

                    while plen_remain >= Self::BLOCK_LEN * 4 {
                        let next_block0 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start).clone()};
                        let next_block1 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN).clone()};
                        let next_block2 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2).clone()};
                        let next_block3 = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3).clone()};
                        mac.update_4block_for_aes([&block0, &block1, &block2, &block3]);

                        block0 = next_block0;
                        block1 = next_block1;
                        block2 = next_block2;
                        block3 = next_block3;

                        self.cipher.encrypt_4_blocks_xor(
                            [&ectr0,
                            &ectr1,
                            &ectr2,
                            &ectr3],
                            [&mut block0,
                            &mut block1,
                            &mut block2,
                            &mut block3],
                        );

                        [ectr0, ectr1, ectr2, ectr3] = Self::ctr32x4_(&counter_block, &mut counter);

                        unsafe {
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start) = block0;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN) = block1;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 2) = block2;
                            *slice_to_array_at_mut(plaintext_in_ciphertext_out, start + Self::BLOCK_LEN * 3) = block3;
                        }

                        start += Self::BLOCK_LEN * 4;
                        plen_remain -= Self::BLOCK_LEN * 4;
                    }

                    counter -= 4;
                    mac.update_4block_for_aes([&block0, &block1, &block2, &block3]);
                }
                
                while plen_remain >= Self::BLOCK_LEN {
                    let mut block: [u8; Self::BLOCK_LEN] = unsafe {slice_to_array_at(plaintext_in_ciphertext_out, start).clone()};

                    let mut ectr = Self::ctr32_(&counter_block, &mut counter);

                    self.cipher.encrypt(&mut ectr);

                    xor_si128_inplace(&mut block, &ectr);

                    mac.update(&block);
                    unsafe {
                        *slice_to_array_at_mut(plaintext_in_ciphertext_out, start) = block;
                    }
                    plen_remain -= Self::BLOCK_LEN;
                    start += Self::BLOCK_LEN;
                }

                if plen_remain != 0 {
                    let mut ectr = Self::ctr32_(&counter_block, &mut counter);

                    self.cipher.encrypt(&mut ectr);

                    let rem = unsafe { plaintext_in_ciphertext_out.get_unchecked_mut(start..) };
                    unsafe {
                        assume(rem.len() < Self::BLOCK_LEN);
                        assume(plen_remain == rem.len());
                    }
                    for i in 0..rem.len() {
                        *unsafe { rem.get_unchecked_mut(i) } ^= ectr[i];
                    }

                    mac.update(&rem);
                }

                // Finalize
                let mut octets = [0u8; Self::BLOCK_LEN];
                octets[0..8].copy_from_slice(&((alen as u64) * 8).to_be_bytes());
                octets[8..16].copy_from_slice(&((plen as u64) * 8).to_be_bytes());

                mac.update(&octets);

                let mut tag = [0u8; Self::TAG_LEN];
                tag[..Self::TAG_LEN].copy_from_slice(&base_ectr[..Self::TAG_LEN]);

                let code = mac.finalize();
                if Self::TAG_LEN == 16 {
                    xor_si128_inplace(&mut tag, &code);
                } else {
                    for i in 0..Self::TAG_LEN {
                        tag[i] ^= code[i];
                    }
                }

                tag_out.copy_from_slice(&tag[..Self::TAG_LEN]);
            }
            #[inline]
            // #[must_use]
            pub fn decrypt_slice_detached(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                ciphertext_in_plaintext_out: &mut [u8],
                tag_in: &[u8; $tlen],
            ) -> bool {
                // NOTE: the first 12 bytes are IV, the last 4 bytes are BlockCounter.
                assert_eq!(nonce.len(), Self::NONCE_LEN);

                let alen = aad.len();
                let clen = ciphertext_in_plaintext_out.len();
                let tlen = tag_in.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(clen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut mac = self.ghash.clone();

                let mut counter = 1u32;
                let mut counter_block = [0u8; Self::BLOCK_LEN];
                counter_block[..Self::NONCE_LEN].copy_from_slice(&nonce[..Self::NONCE_LEN]);
                unsafe {
                    *crate::utils::slice_to_array_at_mut(&mut counter_block, Self::NONCE_LEN) = counter.to_be_bytes();
                }

                let mut base_ectr = counter_block.clone();
                self.cipher.encrypt(&mut base_ectr);

                mac.update(&aad);

                let mut start = 0;
                let mut clen_remain = clen;

                const IS_SOFT: bool = <$cipher>::IS_SOFT && <$ghash>::IS_SOFT;

                $(
                _ = $blocks_4x4;
                while clen_remain >= Self::BLOCK_LEN * 4 * 4 {
                    let ctrs = Self::ctr32_4x4_(&mut counter_block, &mut counter);
                    let mut blocks = [
                        unsafe {slice_to_array_at_mut(ciphertext_in_plaintext_out, start).clone()},
                        unsafe {slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 4).clone()},
                        unsafe {slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 4 * 2).clone()},
                        unsafe {slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 4 * 3).clone()},
                    ];
                    mac.update_blocks_4x4(&blocks);
                    debug_assert!(ctrs[0].len() == Self::BLOCK_LEN * 4);
                    self.cipher.encrypt_blocks_xor_4x4(
                        ctrs,
                        &mut blocks,
                    );
                    
                    unsafe {
                        crate::const_loop!(i, 0, 4, {
                            *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + i * Self::BLOCK_LEN * 4) = blocks[i];
                        });
                    }

                    start += Self::BLOCK_LEN * 4 * 4;
                    clen_remain -= Self::BLOCK_LEN * 4 * 4;
                }
                )?

                while IS_SOFT && clen_remain >= Self::BLOCK_LEN * 4 {
                    let [mut ectr0, mut ectr1, mut ectr2, mut ectr3] = Self::ctr32x4_(&counter_block, &mut counter);
                    self.cipher.encrypt_4_blocks(&mut ectr0, &mut ectr1, &mut ectr2, &mut ectr3);

                    let mut block0 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start).clone()};
                    let mut block1 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN).clone()};
                    let mut block2 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 2).clone()};
                    let mut block3 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 3).clone()};

                    mac.update_4block_for_aes([&block0, &block1, &block2, &block3]);

                    xor_si128_inplace(&mut block0, &ectr0);
                    xor_si128_inplace(&mut block1, &ectr1);
                    xor_si128_inplace(&mut block2, &ectr2);
                    xor_si128_inplace(&mut block3, &ectr3);

                    unsafe {
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start) = block0;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN) = block1;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 2) = block2;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 3) = block3;
                    }
                    start += Self::BLOCK_LEN * 4;
                    clen_remain -= Self::BLOCK_LEN * 4;
                }

                while !IS_SOFT && clen_remain >= Self::BLOCK_LEN * 8 {
                    let [ectr0, ectr1, ectr2, ectr3] = Self::ctr32x4_(&counter_block, &mut counter);

                    let mut block0 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start).clone()};
                    let mut block1 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN).clone()};
                    let mut block2 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 2).clone()};
                    let mut block3 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 3).clone()};

                    mac.update_4block_for_aes([&block0, &block1, &block2, &block3]);

                    self.cipher.encrypt_4_blocks_xor(
                        [&ectr0, &ectr1, &ectr2, &ectr3],
                        [&mut block0, &mut block1, &mut block2, &mut block3],
                    );

                    let [ectr0, ectr1, ectr2, ectr3] = Self::ctr32x4_(&counter_block, &mut counter);

                    unsafe {
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start) = block0;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN) = block1;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 2) = block2;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 3) = block3;
                    }

                    let mut block4 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 4).clone()};
                    let mut block5 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 5).clone()};
                    let mut block6 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 6).clone()};
                    let mut block7 = unsafe {slice_to_array_at(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 7).clone()};

                    mac.update_4block_for_aes([&block4, &block5, &block6, &block7]);

                    self.cipher.encrypt_4_blocks_xor(
                        [&ectr0, &ectr1, &ectr2, &ectr3],
                        [&mut block4, &mut block5, &mut block6, &mut block7],
                    );

                    unsafe {
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 4) = block4;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 5) = block5;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 6) = block6;
                        *slice_to_array_at_mut(ciphertext_in_plaintext_out, start + Self::BLOCK_LEN * 7) = block7;
                    }

                    start += Self::BLOCK_LEN * 8;
                    clen_remain -= Self::BLOCK_LEN * 8;
                }

                while clen_remain >= Self::BLOCK_LEN {
                    let mut ectr = Self::ctr32_(&counter_block, &mut counter);
                    self.cipher.encrypt(&mut ectr);

                    let block = unsafe {
                        slice_to_array_at_mut(ciphertext_in_plaintext_out, start)
                    };

                    mac.update(block);

                    xor_si128_inplace(block, &ectr);
                    clen_remain -= Self::BLOCK_LEN;
                    start += Self::BLOCK_LEN;
                }

                if clen_remain != 0 {
                    let mut ectr = Self::ctr32_(&counter_block, &mut counter);

                    self.cipher.encrypt(&mut ectr);

                    let rem = unsafe {ciphertext_in_plaintext_out.get_unchecked_mut(start..)};
                    unsafe {
                        assume(rem.len() < Self::BLOCK_LEN);
                    }

                    mac.update(&rem);

                    for i in 0..rem.len() {
                        rem[i] ^= ectr[i];
                    }
                }

                // Finalize
                let mut octets = [0u8; 16];
                octets[0..8].copy_from_slice(&((alen as u64) * 8).to_be_bytes());
                octets[8..16].copy_from_slice(&((clen as u64) * 8).to_be_bytes());

                mac.update(&octets);

                let mut tag = [0u8; Self::TAG_LEN];
                tag[..Self::TAG_LEN].copy_from_slice(&base_ectr[..Self::TAG_LEN]);

                let code = mac.finalize();
                if Self::TAG_LEN == 16 {
                    xor_si128_inplace(&mut tag, &code);
                } else {
                    for i in 0..Self::TAG_LEN {
                        tag[i] ^= code[i];
                    }
                }
                // Verify
                constant_time_eq(tag_in, &tag[..Self::TAG_LEN])
            }
        }
    };
}

use crate::crypto::aes::soft::AES128 as AES128Soft;
use crate::crypto::ghash::soft::GHash as GHashSoft;

#[allow(unused_imports)]
use unsafe_target_feature::unsafe_target_feature;
impl_block_cipher_with_gcm_mode!(AES128GcmSoft, AES128Soft, GHashSoft, 16);

cfg_if::cfg_if!{
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        use crate::crypto::aes::x86::AES128 as AES128SSE;
        use crate::crypto::ghash::x86::GHash as GHashSSE;
        impl_block_cipher_with_gcm_mode!(AES128GcmSSE, AES128SSE, GHashSSE, 16, "sse2,ssse3,aes,pclmulqdq");
        type AES128GcmHW = AES128GcmSSE;
        use crate::crypto::aes::x86_avx::AES128 as AES128AVX;
        use crate::crypto::ghash::x86_avx::GHash as GHashAVX;
        impl_block_cipher_with_gcm_mode!(AES128GcmAVX, AES128AVX, GHashAVX, 16, "avx,aes,pclmulqdq");
        use crate::crypto::ghash::x86_avx2::GHash as GHashAVX2;
        impl_block_cipher_with_gcm_mode!(AES128GcmAVX2, AES128AVX, GHashAVX2, 16, "avx2,aes,pclmulqdq,bmi1,bmi2,movbe");
        #[cfg(avx512_feature)]
        impl_block_cipher_with_gcm_mode!(AES128GcmAVX512, "avx512", crate::crypto::aes::x86_avx512::AES128, crate::crypto::ghash::x86_avx512::GHash, 16, "avx512f,avx512bw,avx512vl,vpclmulqdq,vaes");
    } else if #[cfg(target_arch = "aarch64")] {
        use crate::crypto::aes::arm::AES128 as AES128Aarch64;
        use crate::crypto::ghash::aarch64::GHash as GHashAarch64;
        impl_block_cipher_with_gcm_mode!(AES128GcmHW, AES128Aarch64, GHashAarch64, 16, "aes,neon");
        use crate::crypto::ghash::arm::GHash as GHashNEON;
        impl_block_cipher_with_gcm_mode!(AES128GcmNEON, AES128Soft, GHashNEON, 16, "neon");
    } else if #[cfg(target_arch = "arm")] {
        use crate::crypto::aes::arm::AES128 as AES128Arm;
        use crate::crypto::ghash::arm::GHash as GHashNEON;
        impl_block_cipher_with_gcm_mode!(AES128GcmHW, AES128Arm, GHashNEON, 16, "v8,aes,neon");
        impl_block_cipher_with_gcm_mode!(AES128GcmNEON, AES128Soft, GHashNEON, 16, "v7,neon");
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(avx512_feature, any(target_arch = "x86", target_arch = "x86_64"), target_feature = "vaes", target_feature = "vpclmulqdq", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx512bw"))] {
        pub type AES128Gcm = AES128GcmDynamic;
    } else if #[cfg(all(not(avx512_feature), any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2", target_feature = "aes", target_feature = "pclmulqdq", target_feature = "bmi1", target_feature = "bmi2", target_feature = "movbe"))] {
        pub type AES128Gcm = AES128GcmAVX2;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "aes"))] {
        pub type AES128Gcm = AES128GcmHW;
    } else if #[cfg(all(target_arch = "arm", target_feature = "neon", target_feature = "aes"))] {
        pub type AES128Gcm = AES128GcmHW;
    } else {
        pub type AES128Gcm = AES128GcmDynamic;
    }
}

#[derive(Clone, Copy)]
pub union AES128GcmDynamic {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
    hw: AES128GcmHW,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx: AES128GcmAVX,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx2: AES128GcmAVX2,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(avx512_feature)]
    avx512: AES128GcmAVX512,
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    neon: AES128GcmNEON,
    sw: AES128GcmSoft,
}

// x86: 0 - vex aes-ni, 1 - sse aes-ni, 2 - soft, 3 - avx512, 4 - avx2
// arm/aarch64: 0 - aes-ni, 1 - neon, 2 - soft
static mut AES_128_GCM_IDX: u32 = u32::MAX;

impl AES128GcmDynamic {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    pub fn new(key: [u8; Self::KEY_LEN]) -> Self {
        unsafe {
            if AES_128_GCM_IDX == u32::MAX {
                if cfg!(avx512_feature) && crate::is_hw_feature_detected!(
                    "x86" => ("avx512f", "avx512bw", "avx512vl", "vaes", "vpclmulqdq"),
                    "x86_64" => ("avx512f", "avx512bw", "avx512vl", "vaes", "vpclmulqdq"),
                ) {
                    AES_128_GCM_IDX = 3;
                } else if crate::is_hw_feature_detected!(
                    "x86" => ("pclmulqdq", "aes", "sse2", "ssse3"),
                    "x86_64" => ("pclmulqdq", "aes", "sse2", "ssse3"),
                    "aarch64" => ("neon"),
                    "arm" => ("neon"),
                ) {
                    AES_128_GCM_IDX = 1;
                    if crate::is_hw_feature_detected!(
                        "x86" => ("avx"),
                        "x86_64" => ("avx"),
                        "aarch64" => ("aes"),
                        "arm" => ("aes"),
                    ) {
                        AES_128_GCM_IDX = 0;
                        if crate::is_hw_feature_detected!(
                            "x86" => ("avx2", "bmi2", "movbe"),
                            "x86_64" => ("avx2", "bmi2", "movbe"),
                        ) {
                            AES_128_GCM_IDX = 4;
                        }
                    }
                } else {
                    AES_128_GCM_IDX = 2;
                }
            }
            match AES_128_GCM_IDX {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                0 => AES128GcmDynamic {
                    avx: AES128GcmAVX::new(key),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                0 => AES128GcmDynamic {
                    hw: AES128GcmHW::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => AES128GcmDynamic {
                    hw: AES128GcmHW::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => AES128GcmDynamic {
                    avx2: AES128GcmAVX2::new(key),
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                #[cfg(avx512_feature)]
                3 => AES128GcmDynamic {
                    avx512: AES128GcmAVX512::new(key),
                },
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => AES128GcmDynamic {
                    neon: AES128GcmNEON::new(key),
                },
                2 => AES128GcmDynamic {
                    sw: AES128GcmSoft::new(key),
                },
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
    pub fn encrypt_slice(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], aead_pkt: &mut [u8]) {
        unsafe {
            match AES_128_GCM_IDX {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                0 => self.avx.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                0 => self.hw.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.hw.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                #[cfg(avx512_feature)]
                3 => self.avx512.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.avx2.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon.encrypt_slice(nonce, aad, aead_pkt),
                2 => self.sw.encrypt_slice(nonce, aad, aead_pkt),
                _ => unreachable!(),
            }
        }
    }

    #[inline(never)]
    pub fn decrypt_slice(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        unsafe {
            match AES_128_GCM_IDX {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                0 => self.avx.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                #[cfg(avx512_feature)]
                3 => self.avx512.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.avx2.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                0 => self.hw.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.hw.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon.decrypt_slice(nonce, aad, aead_pkt),
                2 => self.sw.decrypt_slice(nonce, aad, aead_pkt),
                _ => unreachable!(),
            }
        }
    }

    #[inline(never)]
    pub fn encrypt_slice_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8; 16],
    ) {
        unsafe {
            match AES_128_GCM_IDX {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                0 => self.avx.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                #[cfg(avx512_feature)]
                3 => self.avx512.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.avx2.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                0 => self.hw.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.hw.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                2 => self.sw.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                _ => unreachable!(),
            }
        }
    }

    #[inline(never)]
    pub fn decrypt_slice_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext_in_plaintext_out: &mut [u8],
        tag_in: &[u8; 16],
    ) -> bool {
        unsafe {
            match AES_128_GCM_IDX {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                0 => self.avx.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                0 => self.hw.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.hw.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
                1 => self.neon.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                2 => self.sw.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                #[cfg(avx512_feature)]
                3 => self.avx512.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                4 => self.avx2.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                _ => unreachable!(),
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_aes128_gcm_impl {
        ($cipher_type:ty) => {{
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let cipher = <$cipher_type>::from_slice(&key);
        let nonce = [0x00; NONCE_LEN];

        let aad = &[0u8; 20];
        let plaintext = b"Hello, world!";
        let text = plaintext.to_vec();
        let mut ciphertext = text.repeat(1000);
        let ciphertext_orig = ciphertext.clone();
        // use detatched mode
        let mut tag = [0u8; 16];
        cipher.encrypt_slice_detached(&nonce, aad, &mut ciphertext, &mut tag);

        let mut ciphertext_ring = ciphertext_orig.clone();
        let key = ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key).unwrap());
        let nonce_ring = ring::aead::Nonce::try_assume_unique_for_key(&nonce).unwrap();
        let aad_ring = ring::aead::Aad::from(aad);
        let ret = key.seal_in_place_separate_tag(nonce_ring, aad_ring, &mut ciphertext_ring);
        assert_eq!(&ciphertext, &ciphertext_ring, "cipher_type: {} ciphertext mismatch", std::any::type_name::<$cipher_type>());
        assert_eq!(tag, ret.unwrap().as_ref(), "cipher_type: {} tag mismatch", std::any::type_name::<$cipher_type>());

        let ret = cipher.decrypt_slice_detached(&nonce, aad, &mut ciphertext, &tag);
        assert!(ret, "cipher_type: {} decrypt_slice_detached failed", std::any::type_name::<$cipher_type>());
        assert_eq!(&ciphertext_orig, &ciphertext[..], "cipher_type: {} plaintext mismatch after decrypt", std::any::type_name::<$cipher_type>());

        for _ in 0..100 {
            let length = (rand::random::<u32>() % 8192) as usize;
            let data = (0..length).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
            let mut ciphertext = data.clone();
            let mut tag = [0u8; 16];
            cipher.encrypt_slice_detached(&nonce, aad, &mut ciphertext, &mut tag);

            let mut ciphertext_ring = data.clone();
            let nonce_ring = ring::aead::Nonce::try_assume_unique_for_key(&nonce).unwrap();
            let tag_ring = key.seal_in_place_separate_tag(nonce_ring, aad_ring, &mut ciphertext_ring);
            assert_eq!(&ciphertext, &ciphertext_ring, "cipher_type: {} ciphertext mismatch for random data", std::any::type_name::<$cipher_type>());
            assert_eq!(tag, tag_ring.unwrap().as_ref(), "cipher_type: {} tag mismatch for random data", std::any::type_name::<$cipher_type>());

            let ret = cipher.decrypt_slice_detached(&nonce, aad, &mut ciphertext, &tag);
            assert!(ret, "cipher_type: {} decrypt_slice_detached failed for random data", std::any::type_name::<$cipher_type>());
            assert_eq!(&data, &ciphertext[..], "cipher_type: {} plaintext mismatch after decrypt for random data", std::any::type_name::<$cipher_type>());
        }

        }};
    }

    #[test]
    fn test_aes128_gcm() {
        test_aes128_gcm_impl!(AES128GcmSoft);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if crate::is_hw_feature_detected!("sse2", "ssse3", "aes", "pclmulqdq") {
            test_aes128_gcm_impl!(AES128GcmSSE);
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if crate::is_hw_feature_detected!("avx", "aes", "pclmulqdq") {
            test_aes128_gcm_impl!(AES128GcmAVX);
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        #[cfg(avx512_feature)]
        if crate::is_hw_feature_detected!("avx512f", "avx512vl", "avx512bw", "vaes", "vpclmulqdq") {
            test_aes128_gcm_impl!(AES128GcmAVX512);
        }
        #[cfg(target_arch = "aarch64")]
        if crate::is_hw_feature_detected!("aes", "neon") {
            test_aes128_gcm_impl!(AES128GcmHW);
        }
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        if crate::is_hw_feature_detected!("neon") {
            test_aes128_gcm_impl!(AES128GcmNEON);
        }
        #[cfg(target_arch = "arm")]
        if crate::is_hw_feature_detected!("v8", "aes", "neon") {
            test_aes128_gcm_impl!(AES128GcmHW);
        }
        test_aes128_gcm_impl!(AES128GcmDynamic);
    }
}
