
/// macro for benchmarking
#[macro_export]
macro_rules! _impl_bench_trait_for_criterion {
    ($name:ident) => {
        pub trait BenchTrait {
            fn bench<F>(&mut self, name: &str, f: F) where F: FnMut();
        }
        
        impl BenchTrait for std::ops::Range<usize> {
            #[inline(always)]
            fn bench<F>(&mut self, _name: &str, mut f: F) where F: FnMut() {
                for _ in self {
                    f();
                }
            }
        }
        
        impl BenchTrait for $name {
            #[inline(always)]
            fn bench<F>(&mut self, name: &str, mut f: F) where F: FnMut() {
                self.bench_function(name, |b| b.iter(|| {
                    f();
                }));
            }
        }
    };
}

#[macro_export]
macro_rules! _bench_main {
    ($name:ident, $fn:ident, $baseline:ident$(,)?) => {
        fn main() {
            if std::env::args().any(|arg| arg == "--bench") {
                $name();
                Criterion::default().configure_from_args().final_summary();
                return;
            }
            let mut range = 0..1000000;
            
            let args = std::env::args();
            if args.len() == 2 && args.last().as_deref() == Some("baseline") {
                $baseline(&mut range, 65536);
            } else {
                $fn(&mut range, 65536);
            }
            
        }
    };
    ($name:ident, $fn:ident$(,)?) => {
        fn main() {
            if std::env::args().any(|arg| arg == "--bench") {
                $name();
                Criterion::default().configure_from_args().final_summary();
                return;
            }
            let mut range = 0..1000000;
            
            let args = std::env::args();
            
            $fn(&mut range, 65536);
        }
    };
}