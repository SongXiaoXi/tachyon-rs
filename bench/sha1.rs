use criterion::*;
use tachyon::utils::{cpu_name, human_readable_size};
use tachyon::{_impl_bench_trait_for_criterion, _bench_main};

_impl_bench_trait_for_criterion!(Criterion);

fn bench_sha1_hash(c: &mut impl BenchTrait, size: usize) {
    let data = vec![0u8; size];

    let mut sha1 = tachyon::crypto::hash::sha1::Sha1::new();
    let test_name = format!("{} sha1 hash {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        sha1.update(&data);
        std::hint::black_box(sha1.finalize());
    });
}

fn bench_sha1_hash_ring(c: &mut impl BenchTrait, size: usize) {
    use ring::digest;
    let data = vec![0u8; size];

    let test_name = format!("{} sha1(ring) hash {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        std::hint::black_box(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data));
    });
}

fn bench_sha1(c: &mut Criterion) {
    bench_sha1_hash(c, 16);
    bench_sha1_hash_ring(c, 16);
    bench_sha1_hash(c, 64);
    bench_sha1_hash_ring(c, 64);
    bench_sha1_hash(c, 256);
    bench_sha1_hash_ring(c, 256);
    bench_sha1_hash(c, 1024);
    bench_sha1_hash_ring(c, 1024);
    bench_sha1_hash(c, 8192);
    bench_sha1_hash_ring(c, 8192);
    bench_sha1_hash(c, 65536);
    bench_sha1_hash_ring(c, 65536);
}

criterion_group!(benches, bench_sha1);
_bench_main!(
    benches,
    bench_sha1_hash,
    bench_sha1_hash_ring,
);