use criterion::*;
use tachyon::utils::{cpu_name, human_readable_size};
use tachyon::{_impl_bench_trait_for_criterion, _bench_main};

_impl_bench_trait_for_criterion!(Criterion);

fn bench_md5_hash(c: &mut impl BenchTrait, size: usize) {
    let data = vec![0u8; size];

    let test_name = format!("{} md5 hash {}", cpu_name(), human_readable_size(size));
    c.bench(&test_name, #[inline(always)] || {
        std::hint::black_box(tachyon::crypto::hash::md5::compute(&data));
    });
}

fn bench_md5(c: &mut Criterion) {

    fn bench_crate_md5_hash(c: &mut Criterion, size: usize) {
        let data = vec![0u8; size];

        let test_name = format!("{} crate md5 hash {}", cpu_name(), human_readable_size(size));
        c.bench_function(&test_name, |b| b.iter(|| {
            black_box(md5::compute(&data));
        }));
    }

    bench_md5_hash(c, 16);
    bench_crate_md5_hash(c, 16);
    bench_md5_hash(c, 64);
    bench_crate_md5_hash(c, 64);
    bench_md5_hash(c, 256);
    bench_crate_md5_hash(c, 256);
    bench_md5_hash(c, 1024);
    bench_crate_md5_hash(c, 1024);
    bench_md5_hash(c, 8192);
    bench_crate_md5_hash(c, 8192);
    bench_md5_hash(c, 65536);
    bench_crate_md5_hash(c, 65536);
}

criterion_group!(benches, bench_md5);
// criterion_main!(benches);
_bench_main!(benches, bench_md5_hash);