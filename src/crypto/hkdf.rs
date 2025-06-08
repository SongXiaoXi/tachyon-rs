// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
// <https://tools.ietf.org/html/rfc5869>
use super::hmac::HmacSha1;

macro_rules! impl_hkdf_with_hmac {
    ($name:tt, $hmac:ty) => {
        #[derive(Clone)]
        pub struct $name {
            prk: [u8; Self::TAG_LEN],
        }

        impl $name {
            pub const BLOCK_LEN: usize = <$hmac>::BLOCK_LEN;
            pub const TAG_LEN: usize = <$hmac>::TAG_LEN;
            #[inline(always)]
            pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
                // HKDF-Extract(salt, IKM) -> PRK
                // PRK = HMAC-Hash(salt, IKM)
                let prk = if salt.is_empty() {
                    let salt = [0u8; Self::TAG_LEN];
                    <$hmac>::oneshot(&salt, ikm)
                } else {
                    <$hmac>::oneshot(salt, ikm)
                };

                Self { prk }
            }
            #[inline(always)]
            pub fn prk(&self) -> &[u8; Self::TAG_LEN] {
                &self.prk
            }
            #[inline(always)]
            pub fn from_prk(prk_in: &[u8]) -> Self {
                assert_eq!(prk_in.len(), Self::TAG_LEN);

                let mut prk = [0u8; Self::TAG_LEN];
                prk.copy_from_slice(prk_in);

                Self { prk }
            }
            #[inline(always)]
            pub fn expand(&self, info: &[u8], okm: &mut [u8]) {
                self.expand_multi_info(&[info], okm)
            }
            #[inline]
            pub fn expand_multi_info(&self, info_components: &[&[u8]], okm: &mut [u8]) {
                assert!(okm.len() <= Self::TAG_LEN * 255);
                // HKDF-Expand(PRK, info, L) -> OKM
                //
                // N = ceil(L/HashLen)
                // T = T(1) | T(2) | T(3) | ... | T(N)
                // OKM = first L octets of T
                //
                // where:
                // T(0) = empty string (zero length)
                // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
                // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
                // T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
                // ...
                //
                // (where the constant concatenated to the end of each T(n) is a
                // single octet.)
                let n = okm.len() / Self::TAG_LEN;
                let r = okm.len() % Self::TAG_LEN;

                if r > 0 {
                    assert!(n < core::u8::MAX as usize);
                } else {
                    assert!(n <= core::u8::MAX as usize);
                }

                let mut hmac = <$hmac>::new(&self.prk);
                for info in info_components.iter() {
                    hmac.update(info);
                }
                hmac.update(&[1]);

                let mut t = hmac.finalize();
                let len = core::cmp::min(okm.len(), t.len());
                okm[0..len].copy_from_slice(&t[..len]);

                for i in 1u8..n as u8 {
                    let mut hmac = <$hmac>::new(&self.prk);
                    hmac.update(&t);
                    for info in info_components.iter() {
                        hmac.update(info);
                    }
                    hmac.update(&[i + 1]);

                    t = hmac.finalize();

                    let offset = i as usize * Self::TAG_LEN;
                    okm[offset..offset + Self::TAG_LEN].copy_from_slice(&t);
                }

                // Last block
                if n > 0 && r > 0 {
                    let mut hmac = <$hmac>::new(&self.prk);
                    hmac.update(&t);
                    for info in info_components.iter() {
                        hmac.update(info);
                    }
                    hmac.update(&[n as u8 + 1]);

                    t = hmac.finalize();

                    let last_okm = &mut okm[n * Self::TAG_LEN..];
                    let len = core::cmp::min(last_okm.len(), Self::TAG_LEN);

                    last_okm[..len].copy_from_slice(&t[..len]);
                }
            }
            pub fn oneshot(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
                let hkdf = Self::new(salt, ikm);
                hkdf.expand(info, okm);
            }
        }
    };
}

impl_hkdf_with_hmac!(HkdfSha1, HmacSha1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha1() {
        let salt = b"0000000000";
        let ikm = b"1234567890";
        let info = b"aaaaaaaaaaaa";

        let mut okm = [0u8; 20];
        HkdfSha1::oneshot(salt, ikm, info, &mut okm);

        let mut okm_data = [0u8; 20];
        {
            use ring::hkdf;
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt.as_ref());
            let prk = salt.extract(ikm);
            let binding = [info.as_ref()];
            let okm = prk.expand(&binding, hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY).unwrap();
            okm.fill(&mut okm_data).unwrap();
        }
        assert_eq!(okm, okm_data);
    }
}