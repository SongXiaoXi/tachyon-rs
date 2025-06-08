use criterion::*;
use tachyon::utils::{cpu_name, human_readable_size};
use tachyon::{_impl_bench_trait_for_criterion, _bench_main};

_impl_bench_trait_for_criterion!(Criterion);

#[inline(always)]
fn bench_aes_128_gcm_encrypt<T: BenchTrait>(c: &mut T, size: usize) {
    let key = [0u8; 16];
    let nonce = [0x00; 12];

    let aad = &[0u8; 0];
    let mut tag = [0u8; 16];

    let mut ciphertext = vec![0u8; size];

    let cipher = tachyon::crypto::gcm::AES128Gcm::from_slice(&key);
    let test_name = format!("{} aes-128-gcm encrypt {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        cipher.encrypt_slice_detached(&nonce, aad, &mut ciphertext, &mut tag);
        let _ = std::hint::black_box(tag);
    });
}

#[inline(always)]
fn bench_aes_128_gcm_encrypt_ring(c: &mut impl BenchTrait, size: usize) {
    use ring::aead;
    use ring::aead::Aad;
    use ring::aead::Nonce;
    use ring::aead::LessSafeKey;

    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let cipher = LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
    let aad = &[0u8; 0];
    let aad = Aad::from(aad);
    let mut ciphertext = vec![0u8; size];
    
    let test_name = format!("{} aes-128-gcm(ring) encrypt {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        let nonce = Nonce::try_assume_unique_for_key(&nonce).unwrap();
        let tag = cipher.seal_in_place_separate_tag(nonce, aad, &mut ciphertext).unwrap();
        let _ = std::hint::black_box(tag);
    });
}


fn bench_aes_128_gcm(c: &mut Criterion) {
    bench_aes_128_gcm_encrypt(c, 16);
    bench_aes_128_gcm_encrypt_ring(c, 16);
    bench_aes_128_gcm_encrypt(c, 64);
    bench_aes_128_gcm_encrypt_ring(c, 64);
    bench_aes_128_gcm_encrypt(c, 256);
    bench_aes_128_gcm_encrypt_ring(c, 256);
    bench_aes_128_gcm_encrypt(c, 1024);
    bench_aes_128_gcm_encrypt_ring(c, 1024);
    bench_aes_128_gcm_encrypt(c, 8192);
    bench_aes_128_gcm_encrypt_ring(c, 8192);
    bench_aes_128_gcm_encrypt(c, 65536);
    bench_aes_128_gcm_encrypt_ring(c, 65536);
}

criterion_group!(benches, bench_aes_128_gcm);
_bench_main!(
    benches,
    bench_aes_128_gcm_encrypt,
    bench_aes_128_gcm_encrypt_ring,
);