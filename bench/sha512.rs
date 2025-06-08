use criterion::*;
use tachyon::utils::{cpu_name, human_readable_size};
use tachyon::{_impl_bench_trait_for_criterion, _bench_main};

_impl_bench_trait_for_criterion!(Criterion);

fn bench_sha512_hash(c: &mut impl BenchTrait, size: usize) {
    let data = vec![0u8; size];

    let mut sha512 = tachyon::crypto::hash::sha512::Sha512::new();
    let test_name = format!("{} sha512 hash {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        sha512.update(&data);
        std::hint::black_box(sha512.finalize());
    });
}

fn bench_sha512_hash_ring(c: &mut impl BenchTrait, size: usize) {
    use ring::digest;
    let data = vec![0u8; size];

    let test_name = format!("{} sha512(ring) hash {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        std::hint::black_box(digest::digest(&digest::SHA512, &data));
    });
}

fn bench_sha512(c: &mut Criterion) {
    bench_sha512_hash(c, 16);
    bench_sha512_hash_ring(c, 16);
    bench_sha512_hash(c, 64);
    bench_sha512_hash_ring(c, 64);
    bench_sha512_hash(c, 128);
    bench_sha512_hash_ring(c, 128);
    bench_sha512_hash(c, 256);
    bench_sha512_hash_ring(c, 256);
    bench_sha512_hash(c, 1024);
    bench_sha512_hash_ring(c, 1024);
    bench_sha512_hash(c, 8192);
    bench_sha512_hash_ring(c, 8192);
    bench_sha512_hash(c, 65536);
    bench_sha512_hash_ring(c, 65536);
}

criterion_group!(benches, bench_sha512);
_bench_main!(
    benches,
    bench_sha512_hash,
    bench_sha512_hash_ring,
);