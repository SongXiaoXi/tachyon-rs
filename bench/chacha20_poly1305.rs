use criterion::*;
use tachyon::utils::{cpu_name, human_readable_size};
use tachyon::{_impl_bench_trait_for_criterion, _bench_main};

_impl_bench_trait_for_criterion!(Criterion);

#[inline(always)]
fn bench_chacha20_poly1305_encrypt(c: &mut impl BenchTrait, size: usize) {
    let key = [0u8; 32];
    let nonce = [0x00; 12];

    let aad = &[0u8; 0];
    let mut tag = [0u8; 16];

    let mut ciphertext = vec![0u8; size];

    let cipher = tachyon::crypto::chacha20_poly1305::Chacha20Poly1305::from_slice(&key);
    let test_name = format!("{} chacha20-poly1305 encrypt {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        cipher.encrypt_slice_detached(&nonce, aad, &mut ciphertext, &mut tag);
        let _ = std::hint::black_box(tag);
    });
}

fn bench_chacha20_poly1305_encrypt_ring(c: &mut impl BenchTrait, size: usize) {
    use ring::aead;
    use ring::aead::Aad;
    use ring::aead::Nonce;
    use ring::aead::LessSafeKey;

    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let cipher = LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap());
    let aad = &[0u8; 0];
    let aad = Aad::from(aad);
    let mut ciphertext = vec![0u8; size];
    
    let test_name = format!("{} chacha20-poly1305(ring) encrypt {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        let nonce = Nonce::try_assume_unique_for_key(&nonce).unwrap();
        let tag = cipher.seal_in_place_separate_tag(nonce, aad, &mut ciphertext).unwrap();
        let _ = std::hint::black_box(tag);
    });
}

fn bench_chacha20_poly1305(c: &mut Criterion) {
    bench_chacha20_poly1305_encrypt(c, 64);
    bench_chacha20_poly1305_encrypt_ring(c, 64);
    bench_chacha20_poly1305_encrypt(c, 256);
    bench_chacha20_poly1305_encrypt_ring(c, 256);
    bench_chacha20_poly1305_encrypt(c, 1024);
    bench_chacha20_poly1305_encrypt_ring(c, 1024);
    bench_chacha20_poly1305_encrypt(c, 8192);
    bench_chacha20_poly1305_encrypt_ring(c, 8192);
    bench_chacha20_poly1305_encrypt(c, 65536);
    bench_chacha20_poly1305_encrypt_ring(c, 65536);
}

criterion_group!(benches, bench_chacha20_poly1305);
_bench_main!(
    benches,
    bench_chacha20_poly1305_encrypt,
    bench_chacha20_poly1305_encrypt_ring,
);