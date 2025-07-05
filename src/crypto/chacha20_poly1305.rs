use crate::utils::constant_time_eq;

macro_rules! impl_chacha20_for_target {
    ($name:tt$(,$avx2:literal)?, $chacha20:ty$(,$avx512:literal)?, $poly1305:ty, $key_len:literal, $block_len:literal, $nonce_len:literal, $tag_len:literal$(, $feature:literal)?) => {
#[derive(Clone, Copy)]
pub struct $name {
    chacha20: $chacha20,
}

impl $name {
    pub const KEY_LEN: usize = <$chacha20>::KEY_LEN; // 32 bytes
    pub const BLOCK_LEN: usize = <$chacha20>::BLOCK_LEN; // 64 bytes
    pub const NONCE_LEN: usize = <$chacha20>::NONCE_LEN; // 12 bytes
    pub const TAG_LEN: usize = <$poly1305>::TAG_LEN; // 16 bytes

    pub const A_MAX: usize = usize::MAX;
    #[cfg(target_pointer_width = "32")]
    pub const P_MAX: usize = usize::MAX;
    #[cfg(target_pointer_width = "64")]
    pub const P_MAX: usize = 274877906880; // (2^32 - 1) * BLOCK_LEN
    #[cfg(target_pointer_width = "32")]
    pub const C_MAX: usize = Self::P_MAX - Self::TAG_LEN;
    #[cfg(target_pointer_width = "64")]
    pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 274,877,906,896
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;

    #[inline(always)]
    pub fn new(key: [u8; $key_len]) -> Self {
        let chacha20 = <$chacha20>::new(key);
        Self { chacha20 }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        Self::new(unsafe { crate::utils::slice_to_array(key).clone() })
    }
}

$(#[unsafe_target_feature::unsafe_target_feature($feature)])?
impl $name {

    #[inline(always)]
    pub fn encrypt_slice(&self, nonce: &[u8; $nonce_len], aad: &[u8], aead_pkt: &mut [u8]) {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let plen = aead_pkt.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

        let tag_out = unsafe { crate::utils::slice_to_array_mut(tag_out) };
        self.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out)
    }

    #[inline(always)]
    pub fn decrypt_slice(&self, nonce: &[u8; $nonce_len], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let clen = aead_pkt.len() - Self::TAG_LEN;
        let (ciphertext_in_plaintext_out, tag_in) = aead_pkt.split_at_mut(clen);

        let tag_in = unsafe { crate::utils::slice_to_array(tag_in) };
        self.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, &tag_in)
    }

    #[inline]
    pub fn encrypt_slice_detached(
        &self,
        nonce: &[u8; $nonce_len],
        aad: &[u8],
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8; $tag_len],
    ) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let plen = plaintext_in_ciphertext_out.len();
        let tlen = tag_out.len();

        assert!(alen <= Self::A_MAX && plen <= Self::P_MAX && tlen <= Self::TAG_LEN);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            self.chacha20.op_1block(0, &nonce, &mut keystream);
            let mut poly1305_key = [0u8; <$poly1305>::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..<$poly1305>::KEY_LEN]);

            <$poly1305>::new(poly1305_key)
        };

        poly1305.update(aad);

        let mut start = 0;
        let mut len_remain = plen;
        let mut chacha_counter = 1;

        use crate::crypto::chacha20;

        

        $(
            _ = $avx2;
            if len_remain >= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2 {
                               
                type Blocks = [u8; <$chacha20>::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2];
                // SAFETY: We know that the slice is at least BLOCK_LEN * PARALLEL_BLOCKS * 2 long
                let blocks: &mut Blocks = unsafe { crate::utils::slice_to_array_at_mut(plaintext_in_ciphertext_out, start) };
                // SAFETY: We know that the slice lifetime is valid
                let mut blocks: &mut Blocks = unsafe { core::mem::transmute(blocks) };

                self.chacha20.op_8blocks(chacha_counter, &nonce, blocks);
                chacha_counter += chacha20::PARALLEL_BLOCKS as u32 * 2;
                start += Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2;
                len_remain -= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2;
 

                while len_remain >= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2 {
                    let new_blocks: &mut Blocks = unsafe { crate::utils::slice_to_array_at_mut(plaintext_in_ciphertext_out, start) };
                    let new_blocks: &mut Blocks = unsafe { core::mem::transmute(new_blocks) };
                    
                    let poly_blocks_ptr = blocks.as_ptr() as *const [u8; Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS];
                    poly1305.update_16_blocks(&*poly_blocks_ptr);
                    poly1305.update_16_blocks(&*poly_blocks_ptr.add(1));
                    self.chacha20.op_8blocks(chacha_counter, &nonce, new_blocks);
                    blocks = new_blocks;
                    chacha_counter += chacha20::PARALLEL_BLOCKS as u32 * 2;
                    start += Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2;
                    len_remain -= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2;
                }
                let poly_blocks_ptr = blocks.as_ptr() as *const [u8; Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS];
                poly1305.update_16_blocks(&*poly_blocks_ptr);
                poly1305.update_16_blocks(&*poly_blocks_ptr.add(1));
            }
        )?

        if len_remain >= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS {
            // SAFETY: We know that the slice is at least BLOCK_LEN * PARALLEL_BLOCKS long
            let blocks: &mut [u8; Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS] = unsafe { crate::utils::slice_to_array_at_mut(plaintext_in_ciphertext_out, start) };
            // SAFETY: We know that the slice lifetime is valid
            let mut blocks: &mut [u8; Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS] = unsafe { core::mem::transmute(blocks) };

            self.chacha20.op_4blocks(chacha_counter, &nonce, blocks);
            chacha_counter += chacha20::PARALLEL_BLOCKS as u32;
            start += Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS;
            len_remain -= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS;
            
            type Blocks = [u8; <$chacha20>::BLOCK_LEN * chacha20::PARALLEL_BLOCKS];

            macro_rules! loop_body {
                () => {
                    let new_blocks: &mut Blocks = unsafe { crate::utils::slice_to_array_at_mut(plaintext_in_ciphertext_out, start) };
                    let new_blocks: &mut Blocks = unsafe { core::mem::transmute(new_blocks) };
                    poly1305.update_16_blocks(blocks);
                    self.chacha20.op_4blocks(chacha_counter, &nonce, new_blocks);
                    blocks = new_blocks;
                    chacha_counter += chacha20::PARALLEL_BLOCKS as u32;
                    start += Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS;
                    len_remain -= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS;
                }
            }

            // This will gain extra performance on out-of-order micro-archs, for example 
            // Cortex-A72, A78, X1, etc. But for in-order micro-archs, for example 
            // Cortex-A55, will cause performance degradation.
            #[cfg(target_arch = "aarch64")]
            while true && len_remain >= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS * 2 {
                loop_body!();
                loop_body!();
            }

            while len_remain >= Self::BLOCK_LEN * chacha20::PARALLEL_BLOCKS {
                loop_body!();
            }

            poly1305.update_16_blocks(blocks);
        }

        if len_remain > 0 {
            let block = unsafe { plaintext_in_ciphertext_out.get_unchecked_mut(start..) };
            self.chacha20.encrypt_slice(chacha_counter, &nonce, block);

            poly1305.update(block);

        }

        let mut len_block = [0u8; 16];
        len_block[0..8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(plen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();

        tag_out.copy_from_slice(&tag[..Self::TAG_LEN]);
    }

    /**
     * Decrypts the ciphertext and verifies the tag.
     * ciphertext will not be decrypted if the tag is invalid.
     */
    #[inline]
    pub fn decrypt_slice_detached(
        &self,
        nonce: &[u8; $nonce_len],
        aad: &[u8],
        ciphertext_in_plaintext_out: &mut [u8],
        tag_in: &[u8; $tag_len],
    ) -> bool {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let clen = ciphertext_in_plaintext_out.len();
        let tlen = tag_in.len();

        assert!(alen <= Self::A_MAX && clen <= Self::P_MAX && tlen == Self::TAG_LEN);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            self.chacha20.encrypt_slice(0, &nonce, &mut keystream);
            let mut poly1305_key = [0u8; <$poly1305>::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..<$poly1305>::KEY_LEN][..]);

            <$poly1305>::new(poly1305_key)
        };

        poly1305.update(aad);
        poly1305.update(&ciphertext_in_plaintext_out);

        let mut len_block = [0u8; 16];
        len_block[0..8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(clen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();

        // Verify
        let is_match = constant_time_eq(tag_in, &tag[..Self::TAG_LEN]);

        if is_match {
            self.chacha20
                .decrypt_slice(1, &nonce, ciphertext_in_plaintext_out);
        }

        is_match
    }

}

    };
}

impl_chacha20_for_target!(Chacha20Poly1305Soft, super::chacha20::Chacha20Soft, super::poly1305::Poly1305, 32, 64, 12, 16);

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        impl_chacha20_for_target!(Chacha20Poly1305SSE, super::chacha20::Chacha20SSE, super::poly1305::Poly1305, 32, 64, 12, 16, "sse2");
        impl_chacha20_for_target!(Chacha20Poly1305AVX, super::chacha20::Chacha20AVX, super::poly1305::Poly1305, 32, 64, 12, 16, "avx");
        impl_chacha20_for_target!(Chacha20Poly1305AVX2, "avx2", super::chacha20::Chacha20AVX2, super::poly1305::Poly1305, 32, 64, 12, 16, "avx2");
    } else if #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
        impl_chacha20_for_target!(Chacha20Poly1305Neon, super::chacha20::Chacha20Neon, super::poly1305::Poly1305, 32, 64, 12, 16, "neon");
    }
}

cfg_if::cfg_if!{
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx"))] {
        pub type Chacha20Poly1305 = Chacha20Poly1305AVX;
    } else if #[cfg(all(any(target_arch = "aarch64", target_arch = "arm"), target_feature = "neon"))] {
        pub type Chacha20Poly1305 = Chacha20Poly1305Neon;
    } else {
        pub type Chacha20Poly1305 = Chacha20Poly1305Dynamic;
    }
}

pub union Chacha20Poly1305Dynamic {
    soft: Chacha20Poly1305Soft,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    sse: Chacha20Poly1305SSE,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx: Chacha20Poly1305AVX,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    avx2: Chacha20Poly1305AVX2,
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    neon: Chacha20Poly1305Neon,
}

// x86: 0 - soft, 1 - sse2, 2 - avx, 3 - avx2, 4 - avx512
// arm: 0 - soft, 1 - neon
static mut CHACHA20_POLY1305_IDX: u32 = u32::MAX;

impl Chacha20Poly1305Dynamic {
    pub const KEY_LEN: usize = Chacha20Poly1305Soft::KEY_LEN; // 32 bytes
    pub const BLOCK_LEN: usize = Chacha20Poly1305Soft::BLOCK_LEN; // 64 bytes
    pub const NONCE_LEN: usize = Chacha20Poly1305Soft::NONCE_LEN; // 12 bytes
    pub const TAG_LEN: usize = Chacha20Poly1305Soft::TAG_LEN; // 16 bytes
    pub const A_MAX: usize = Chacha20Poly1305Soft::A_MAX;
    pub const P_MAX: usize = Chacha20Poly1305Soft::P_MAX;
    pub const C_MAX: usize = Chacha20Poly1305Soft::C_MAX;
    pub const N_MIN: usize = Chacha20Poly1305Soft::N_MIN;
    pub const N_MAX: usize = Chacha20Poly1305Soft::N_MAX;

    pub fn new(key: [u8; 32]) -> Self {
        let mut idx = unsafe { CHACHA20_POLY1305_IDX };
        if idx == u32::MAX {
            if crate::is_hw_feature_detected!(
                "x86" => ("sse2"),
                "x86_64" => ("sse2"),
                "arm" => ("neon"),
            ) {
                idx = 1;
                if crate::is_hw_feature_detected!(
                    "x86" => ("avx"),
                    "x86_64" => ("avx"),
                ) {
                    idx = 2;
                    if crate::is_hw_feature_detected!(
                        "x86" => ("avx2"),
                        "x86_64" => ("avx2"),
                    ) {
                        idx = 3;
                        #[cfg(feature = "nightly")]
                        if crate::is_hw_feature_detected!(
                            "x86" => ("avx512f","avx512dq"),
                            "x86_64" => ("avx512f","avx512dq"),
                        ) {
                            idx = 4;
                        }
                    }
                }
            } else {
                idx = 0;
            }
            unsafe { CHACHA20_POLY1305_IDX = idx };
        }

        match idx {
            0 => Chacha20Poly1305Dynamic { soft: Chacha20Poly1305Soft::new(key) },
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            1 => Chacha20Poly1305Dynamic { sse: Chacha20Poly1305SSE::new(key) },
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            2 => Chacha20Poly1305Dynamic { avx: Chacha20Poly1305AVX::new(key) },
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            3 => Chacha20Poly1305Dynamic { avx2: Chacha20Poly1305AVX2::new(key) },
            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            1 => Chacha20Poly1305Dynamic { neon: Chacha20Poly1305Neon::new(key) },
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub fn from_slice(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        Self::new(unsafe { crate::utils::slice_to_array(key).clone() })
    }

    pub fn encrypt_slice(
        &self,
        nonce: &[u8; Chacha20Poly1305Soft::NONCE_LEN],
        aad: &[u8],
        aead_pkt: &mut [u8],
    ) {
        unsafe {
            match CHACHA20_POLY1305_IDX {
                0 => self.soft.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.sse.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx2.encrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                1 => self.neon.encrypt_slice(nonce, aad, aead_pkt),
                _ => unreachable!(),
            }
        }
    }

    pub fn decrypt_slice(
        &self,
        nonce: &[u8; Chacha20Poly1305Soft::NONCE_LEN],
        aad: &[u8],
        aead_pkt: &mut [u8],
    ) -> bool {
        unsafe { 
            match CHACHA20_POLY1305_IDX {
                0 => self.soft.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.sse.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx2.decrypt_slice(nonce, aad, aead_pkt),
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                1 => self.neon.decrypt_slice(nonce, aad, aead_pkt),
                _ => unreachable!(),
            }
        }
    }

    pub fn encrypt_slice_detached(
        &self,
        nonce: &[u8; Chacha20Poly1305Soft::NONCE_LEN],
        aad: &[u8],
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8; Chacha20Poly1305Soft::TAG_LEN],
    ) {
        unsafe { 
            match CHACHA20_POLY1305_IDX {
                0 => self.soft.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.sse.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx2.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                1 => self.neon.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out),
                _ => unreachable!(),
            }
        }
    }

    pub fn decrypt_slice_detached(
        &self,
        nonce: &[u8; Chacha20Poly1305Soft::NONCE_LEN],
        aad: &[u8],
        ciphertext_in_plaintext_out: &mut [u8],
        tag_in: &[u8; Chacha20Poly1305Soft::TAG_LEN],
    ) -> bool {
        unsafe {
            match CHACHA20_POLY1305_IDX {
                0 => self.soft.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                1 => self.sse.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => self.avx.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => self.avx2.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                1 => self.neon.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in),
                _ => unreachable!(),
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_chacha20_poly1305_impl {
        ($cipher_type:ty) => {{
            use ring::aead;
            use ring::aead::Aad;
            use ring::aead::Nonce;
            use ring::aead::LessSafeKey;

            let key = [
                0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5,
                0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70,
                0x75, 0xc0,
            ];
            let nonce = [
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ];
            let aad = [
                0xf3, 0x33, 0x88, 0x86
            ];
            let plaintext = b"Hello, world!";
            let text = plaintext.to_vec();
            let mut ciphertext = text.repeat(1000);

            let plaintext = ciphertext.clone();
            let mut ciphertext_ring = ciphertext.clone();

            let cipher = <$cipher_type>::new(key);

            let mut tag = [0u8; 16];
            cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag);
            
            let ring_cipher = LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap());
            let nonce_ring = Nonce::try_assume_unique_for_key(&nonce).unwrap();
            let tag_ring = ring_cipher.seal_in_place_separate_tag(nonce_ring,  Aad::from(aad), &mut ciphertext_ring).unwrap();

            assert_eq!(ciphertext, ciphertext_ring);
            assert_eq!(tag, tag_ring.as_ref());

            let ret = cipher.decrypt_slice_detached(&nonce, &aad, &mut ciphertext, &tag);
            assert_eq!(ret, true);
            assert_eq!(ciphertext, plaintext);

            for _ in 0..100 {
                let length = (rand::random::<u32>() % 8192) as usize;
                let data = (0..length).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();
                let mut ciphertext = data.clone();
                let mut tag = [0u8; 16];
                cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag);

                let mut ciphertext_ring = data.clone();
                let nonce_ring = Nonce::try_assume_unique_for_key(&nonce).unwrap();
                let tag_ring = ring_cipher.seal_in_place_separate_tag(nonce_ring, Aad::from(aad), &mut ciphertext_ring).unwrap();

                assert_eq!(ciphertext, ciphertext_ring);
                assert_eq!(tag, tag_ring.as_ref());

                let ret = cipher.decrypt_slice_detached(&nonce, &aad, &mut ciphertext, &tag);
                assert_eq!(ret, true);
                assert_eq!(ciphertext, data);
            }
        }};
    }


    #[test]
    fn chacha20_poly1305() {
        test_chacha20_poly1305_impl!(Chacha20Poly1305Soft);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if crate::is_hw_feature_detected!("sse2") {
            test_chacha20_poly1305_impl!(Chacha20Poly1305SSE);
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if crate::is_hw_feature_detected!("avx") {
            test_chacha20_poly1305_impl!(Chacha20Poly1305AVX);
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if crate::is_hw_feature_detected!("avx2") {
            test_chacha20_poly1305_impl!(Chacha20Poly1305AVX2);
        }
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        if cfg!(target_feature = "neon") {
            test_chacha20_poly1305_impl!(Chacha20Poly1305Neon);
        }
        test_chacha20_poly1305_impl!(Chacha20Poly1305Dynamic);
    }
}
