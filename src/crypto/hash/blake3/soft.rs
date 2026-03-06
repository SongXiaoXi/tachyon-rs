#![allow(unused_mut, dead_code)]

macro_rules! blake3_define_const {
    () => {
        pub const BLOCK_LEN: usize = 64;
        pub const DIGEST_LEN: usize = 32;
        pub const KEY_LEN: usize = 32;
        pub const CHUNK_LEN: usize = 1024;
    };
}

#[allow(unused_macros)]
macro_rules! blake3_test_case {
    () => { blake3_test_case!(@body); };
    (require_hw: $($arch:tt => ($($feat:tt),+)),+) => {
        blake3_test_case!(@body require_hw: $($arch => ($($feat),+)),+);
    };
    (@body $(require_hw: $($arch:tt => ($($feat:tt),+)),+)?) => {

        #[test]
        fn test_blake3_empty() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            let hash = Blake3::oneshot(b"");
            let expected = blake3::hash(b"");
            assert_eq!(hash, *expected.as_bytes());
        }

        #[test]
        fn test_blake3_short() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            let data = b"The quick brown fox jumps over the lazy dog";
            let hash = Blake3::oneshot(data);
            let expected = blake3::hash(data);
            assert_eq!(hash, *expected.as_bytes());
        }

        #[test]
        fn test_blake3_multi_chunk() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            let data = vec![0x42u8; 2048];
            let hash = Blake3::oneshot(&data);
            let expected = blake3::hash(&data);
            assert_eq!(hash, *expected.as_bytes());
        }

        #[test]
        fn test_blake3_incremental() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            let data = b"hello world, this is a test of blake3 incremental hashing!!";
            let mut hasher = Blake3::new();
            hasher.update(&data[..10]);
            hasher.update(&data[10..]);
            let mut digest = [0u8; 32];
            hasher.finalize(&mut digest);
            let expected = blake3::hash(data);
            assert_eq!(digest, *expected.as_bytes());
        }

        #[test]
        fn test_blake3_keyed() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            let key = [0xABu8; 32];
            let data = b"keyed hash test data";
            let mut hasher = Blake3::with_keyed(&key);
            hasher.update(data);
            let mut digest = [0u8; 32];
            hasher.finalize(&mut digest);
            let expected = blake3::keyed_hash(&key, data);
            assert_eq!(digest, *expected.as_bytes());
        }

        #[test]
        fn test_blake3_4way() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            let data = vec![0x55u8; 65536];
            let hash = Blake3::oneshot(&data);
            let expected = blake3::hash(&data);
            assert_eq!(hash, *expected.as_bytes());
        }

        #[test]
        fn test_blake3_4way_remainder() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            let data = vec![0xAAu8; 4097];
            let hash = Blake3::oneshot(&data);
            let expected = blake3::hash(&data);
            assert_eq!(hash, *expected.as_bytes());
        }

        /// Test exact SIMD-boundary sizes to exercise the >= condition
        /// and the "all consumed" finalize path.
        #[test]
        fn test_blake3_exact_boundaries() {
            $(if !crate::is_hw_feature_detected!($($arch => ($($feat),+)),+) { return; })?
            // Exact multiples of chunk size (1024) and SIMD batch sizes
            for &n in &[
                1024,       // 1 chunk
                2048,       // 2 chunks
                3072,       // 3 chunks
                4096,       // 4 chunks (4-way boundary)
                5120,       // 5 chunks
                6144,       // 6 chunks
                7168,       // 7 chunks
                8192,       // 8 chunks (8-way boundary)
                9216,       // 9 chunks
                12288,      // 12 chunks
                16384,      // 16 chunks (16-way boundary)
                20480,      // 20 chunks
                32768,      // 32 chunks (2×16-way)
                65536,      // 64 chunks (4×16-way)
                1025,       // 1 chunk + 1 byte
                4095,       // 4 chunks - 1 byte
                16385,      // 16 chunks + 1 byte
                65537,      // 64 chunks + 1 byte
                131072,     // 128 chunks
                262144,     // 256 chunks (256 KiB)
                524288,     // 512 chunks (512 KiB)
                1048576,    // 1024 chunks (1 MiB)
            ] {
                let data = vec![0xBBu8; n];
                let hash = Blake3::oneshot(&data);
                let expected = blake3::hash(&data);
                assert_eq!(hash, *expected.as_bytes(), "mismatch at size {}", n);
            }
        }
    };
}

/// Generate a complete `Blake3` struct and impl, parameterised by a block-level
/// `transform` function.  Each SIMD back-end defines its own `transform` and
/// then invokes this macro to get the full slice-level API.
///
/// Usage:
///   `blake3_impl!(transform);`                        — no parallelism
///   `blake3_impl!(transform, hash_8_chunks, 8, hash_4_chunks, 4);` — two-tier fast path
///   `blake3_impl!(transform, transform_inline, hash_4_chunks, 4; hash_inline: hash_4_chunks_inline; oneshot_feature: "ssse3")`
///   `blake3_impl!(transform, hash_8_chunks, 8, hash_4_chunks, 4; parent_batch: compress_parents_8, 8; oneshot_feature: "avx2")`
///   `blake3_impl!(transform, transform_inline, hash_16_chunks, 16, hash_8_chunks, 8, hash_4_chunks, 4; ... )`
macro_rules! blake3_impl {
    // Three-tier with inline transform + inline hash fns + parent batch + two-level inline parent batch + oneshot feature.
    ($transform:ident, $transform_inline:ident, $hash_wide:ident, $wide:expr, $hash_mid:ident, $mid:expr, $hash_narrow:ident, $narrow:expr; hash_inline: $hwi:ident, $hmi:ident, $hni:ident; parent_batch: $pb_fn:ident, $pb_size:expr; parent_batch_inline: $pb_il1_fn:ident, $pb_il1_size:expr, $pb_il2_fn:ident, $pb_il2_size:expr; oneshot_feature: $feat:literal) => {
        blake3_impl!(@inner $transform, $transform_inline, [($hash_wide, $hwi, $wide), ($hash_mid, $hmi, $mid), ($hash_narrow, $hni, $narrow)]; parent_batch: $pb_fn, $pb_size; parent_batch_inline: $pb_il1_fn, $pb_il1_size, $pb_il2_fn, $pb_il2_size; oneshot_feature: $feat);
    };
    // Two-tier fast path with SIMD parent batch + target-featured oneshot.
    ($transform:ident, $hash_wide:ident, $wide:expr, $hash_narrow:ident, $narrow:expr; parent_batch: $pb_fn:ident, $pb_size:expr; oneshot_feature: $feat:literal) => {
        blake3_impl!(@inner $transform, $transform, [($hash_wide, $hash_wide, $wide), ($hash_narrow, $hash_narrow, $narrow)]; parent_batch: $pb_fn, $pb_size; oneshot_feature: $feat);
    };
    // Two-tier fast path: try wider SIMD first, then narrower.
    ($transform:ident, $hash_wide:ident, $wide:expr, $hash_narrow:ident, $narrow:expr) => {
        blake3_impl!(@inner $transform, $transform, [($hash_wide, $hash_wide, $wide), ($hash_narrow, $hash_narrow, $narrow)]);
    };
    // Single-tier with inline transform + inline hash fn + inline parent batch + oneshot feature.
    ($transform:ident, $transform_inline:ident, $hash_n_chunks:ident, $nway:expr; hash_inline: $hni:ident; parent_batch_inline: $pb_il1_fn:ident, $pb_il1_size:expr, $pb_il2_fn:ident, $pb_il2_size:expr; oneshot_feature: $feat:literal) => {
        blake3_impl!(@inner $transform, $transform_inline, [($hash_n_chunks, $hni, $nway)]; parent_batch_inline: $pb_il1_fn, $pb_il1_size, $pb_il2_fn, $pb_il2_size; oneshot_feature: $feat);
    };
    // Single-tier fast path with inline transform + inline hash fn + oneshot feature.
    ($transform:ident, $transform_inline:ident, $hash_n_chunks:ident, $nway:expr; hash_inline: $hni:ident; oneshot_feature: $feat:literal) => {
        blake3_impl!(@inner $transform, $transform_inline, [($hash_n_chunks, $hni, $nway)]; oneshot_feature: $feat);
    };
    // No parallelism.
    ($transform:ident) => {
        blake3_impl!(@inner $transform, $transform, []);
    };
    (@inner $transform:ident, $transform_inline:ident, [$(($hash_fn:ident, $hash_il:ident, $nway:expr)),*] $(; parent_batch: $pb_fn:ident, $pb_size:expr)? $(; parent_batch_inline: $pb_il1_fn:ident, $pb_il1_size:expr, $pb_il2_fn:ident, $pb_il2_size:expr)? $(; oneshot_feature: $feat:literal)?) => {
        #[derive(Clone, Copy)]
        pub struct Blake3 {
            key: [u32; 8],
            flags: u32,

            buffer: [u8; 64],
            offset: usize,

            chunk_block_counter: usize,
            chunk_counter: u64,
            chunk_chaining_value: [u32; 8],
            chunk_len: usize,

            stack: [[u32; 8]; 54],
            stack_len: usize,

            // Saved inputs of the last parent merge in push_cv.
            // Needed when all chunks are consumed by SIMD (>= boundary)
            // and stack_len == 1 (power-of-2 chunk count): finalize
            // re-compresses this block with ROOT flag.
            last_parent_block: [u32; 16],
        }

        #[allow(unused_unsafe)]
        #[allow(unused_variables)]
        impl Blake3 {
            blake3_define_const!();

            /// Inputs below this many bytes are routed to the lightweight
            /// `oneshot_few_body` instead of the large SIMD-tier `oneshot_multi_body`.
            /// Value: the smallest SIMD tier needs this many chunks; below
            /// that, SIMD tiers never fire so we avoid the code-bloat cost.
            const FEW_THRESHOLD: usize = {
                // Compute the minimum tier size from the tier list.
                // With no tiers (soft fallback) this defaults to 2 (at least
                // 2 chunks needed for the few-chunks path to activate).
                let mut min_nway = usize::MAX;
                $(
                    if $nway < min_nway { min_nway = $nway; }
                )*
                if min_nway == usize::MAX { min_nway = 2; }
                min_nway * Self::CHUNK_LEN
            };

            const BLOCK_ZERO: [u8; 64] = [0u8; 64];

            pub fn new() -> Self {
                Self::new_(super::IV, 0)
            }

            pub fn with_keyed(key: &[u8]) -> Self {
                debug_assert_eq!(key.len(), Self::KEY_LEN);
                let key = unsafe { &*(key.as_ptr() as *const [u8; 32]) };
                Self::new_(super::u32x8_from_le_bytes(key), super::KEYED_HASH)
            }

            pub fn new_derive_key<S: AsRef<[u8]>>(context: S) -> Self {
                let context = context.as_ref();
                let mut hasher = Self::new_(super::IV, super::DERIVE_KEY_CONTEXT);
                hasher.update(context);
                let mut context_key = [0u8; Self::KEY_LEN];
                hasher.finalize(&mut context_key);
                let key_words = super::u32x8_from_le_bytes(&context_key);
                Self::new_(key_words, super::DERIVE_KEY_MATERIAL)
            }

            #[inline]
            fn new_(key: [u32; 8], flags: u32) -> Self {
                Self {
                    key,
                    flags,
                    buffer: Self::BLOCK_ZERO,
                    offset: 0,
                    chunk_block_counter: 0,
                    chunk_counter: 0,
                    chunk_chaining_value: key,
                    chunk_len: 0,
                    stack: [[0u32; 8]; 54],
                    stack_len: 0,
                    last_parent_block: [0u32; 16],
                }
            }

            #[inline(always)]
            fn push_cv(&mut self, new_cv: [u32; 8]) {
                let mut cv = new_cv;
                let mut total_chunks = self.chunk_counter;
                while total_chunks & 1 == 0 {
                    self.stack_len -= 1;
                    let left = unsafe { *self.stack.get_unchecked(self.stack_len) };
                    let mut bw = [0u32; 16];
                    bw[0..8].copy_from_slice(&left);
                    bw[8..16].copy_from_slice(&cv);
                    self.last_parent_block = bw;
                    let out = $transform(
                        &self.key, &bw, Self::BLOCK_LEN, 0,
                        self.flags | super::PARENT,
                    );
                    cv.copy_from_slice(&out[..8]);
                    total_chunks >>= 1;
                }
                unsafe { *self.stack.get_unchecked_mut(self.stack_len) = cv; }
                self.stack_len += 1;
            }

            pub fn update(&mut self, data: &[u8]) {
                let mut i = 0usize;
                while i < data.len() {
                    // N-way parallel chunk fast path(s) — widest first.
                    // Uses >= so exact multiples are processed by SIMD;
                    // finalize handles the "all consumed" edge case.
                    $(
                    if data.len() - i >= $nway * Self::CHUNK_LEN
                        && self.offset == 0
                        && self.chunk_block_counter == 0
                    {
                        let cvs = $hash_fn(
                            unsafe { &*(data.as_ptr().add(i) as *const [u8; $nway * 1024]) },
                            &self.key,
                            self.chunk_counter, self.flags,
                        );
                        for cv in &cvs {
                            self.chunk_counter += 1;
                            self.push_cv(*cv);
                        }
                        i += $nway * Self::CHUNK_LEN;
                        continue;
                    }
                    )*
                    // Fast single-chunk loop: process remaining complete chunks
                    // directly via transform (no buffer-copy overhead), leaving
                    // exactly 1 chunk for the serial path + finalize.
                    if data.len() - i > Self::CHUNK_LEN
                        && self.offset == 0
                        && self.chunk_block_counter == 0
                    {
                        let chunk_ptr = unsafe {
                            data.as_ptr().add(i) as *const [u8; 64]
                        };
                        let mut cv = self.chunk_chaining_value;
                        for blk in 0u32..16 {
                            let block = unsafe { &*chunk_ptr.add(blk as usize) };
                            let words = super::u32x16_from_le_bytes(block);
                            let bf = match blk {
                                0  => self.flags | super::CHUNK_START,
                                15 => self.flags | super::CHUNK_END,
                                _  => self.flags,
                            };
                            let state = $transform(
                                &cv, &words, Self::BLOCK_LEN,
                                self.chunk_counter, bf,
                            );
                            cv.copy_from_slice(&state[..8]);
                        }
                        self.chunk_counter += 1;
                        self.chunk_chaining_value = self.key;
                        self.push_cv(cv);
                        i += Self::CHUNK_LEN;
                        continue;
                    }
                    // Buffer is full – compress it.
                    if self.offset == Self::BLOCK_LEN {
                        const LEN: usize = 1024 - 64;
                        if self.chunk_len == LEN {
                            // Last block of a chunk.
                            let block_words = super::u32x16_from_le_bytes(&self.buffer);
                            let flags = if self.chunk_block_counter == 0 {
                                self.flags | super::CHUNK_START | super::CHUNK_END
                            } else {
                                self.flags | super::CHUNK_END
                            };

                            let state = $transform(
                                &self.chunk_chaining_value,
                                &block_words,
                                Self::BLOCK_LEN,
                                self.chunk_counter,
                                flags,
                            );
                            let mut new_cv = [0u32; 8];
                            new_cv.copy_from_slice(&state[..8]);

                            self.chunk_counter += 1;
                            self.chunk_chaining_value = self.key;
                            self.chunk_len = 0;
                            self.chunk_block_counter = 0;
                            self.offset = 0;
                            self.buffer = Self::BLOCK_ZERO;

                            self.push_cv(new_cv);
                        } else {
                            // Mid-chunk block.
                            let flags = if self.chunk_block_counter == 0 {
                                self.flags | super::CHUNK_START
                            } else {
                                self.flags
                            };
                            let words = super::u32x16_from_le_bytes(&self.buffer);
                            let state = $transform(
                                &self.chunk_chaining_value,
                                &words,
                                Self::BLOCK_LEN,
                                self.chunk_counter,
                                flags,
                            );
                            self.chunk_chaining_value.copy_from_slice(&state[..8]);
                            self.chunk_len += Self::BLOCK_LEN;
                            self.chunk_block_counter += 1;
                            self.offset = 0;
                            self.buffer = Self::BLOCK_ZERO;
                        }
                    }

                    let want = Self::BLOCK_LEN - self.offset;
                    let have = data.len() - i;
                    let take = want.min(have);
                    self.buffer[self.offset..self.offset + take]
                        .copy_from_slice(&data[i..i + take]);
                    self.offset += take;
                    i += take;
                }
            }

            pub fn finalize(self, digest: &mut [u8]) {
                // All data consumed by SIMD / fast-chunk paths?
                // (offset == 0 && counter > 0 means no tail block was left
                //  for finalize — the >= condition processed everything.)
                if self.chunk_counter > 0
                    && self.offset == 0
                    && self.chunk_block_counter == 0
                {
                    if self.stack_len == 1 {
                        // Power-of-2 chunk count: the single stack entry was
                        // produced by push_cv merging everything.  Re-compress
                        // the saved parent block with ROOT flag.
                        let root_flags = self.flags | super::PARENT | super::ROOT;
                        let mut counter = 0u64;
                        for out_block in digest.chunks_mut(Self::BLOCK_LEN) {
                            let state = $transform(
                                &self.key, &self.last_parent_block,
                                Self::BLOCK_LEN, counter, root_flags,
                            );
                            let stream = super::u32x16_to_le_bytes(&state);
                            let olen = out_block.len();
                            out_block.copy_from_slice(&stream[..olen]);
                            counter += 1;
                        }
                        return;
                    }
                    // stack_len >= 2: fold right-to-left, ROOT on last merge.
                    let mut right = unsafe {
                        *self.stack.get_unchecked(self.stack_len - 1)
                    };
                    for idx in (0..self.stack_len - 1).rev() {
                        let left = unsafe { *self.stack.get_unchecked(idx) };
                        let mut bw = [0u32; 16];
                        bw[0..8].copy_from_slice(&left);
                        bw[8..16].copy_from_slice(&right);
                        if idx == 0 {
                            // Root merge.
                            let root_flags = self.flags | super::PARENT | super::ROOT;
                            let mut counter = 0u64;
                            for out_block in digest.chunks_mut(Self::BLOCK_LEN) {
                                let state = $transform(
                                    &self.key, &bw, Self::BLOCK_LEN,
                                    counter, root_flags,
                                );
                                let stream = super::u32x16_to_le_bytes(&state);
                                let olen = out_block.len();
                                out_block.copy_from_slice(&stream[..olen]);
                                counter += 1;
                            }
                            return;
                        }
                        let state = $transform(
                            &self.key, &bw, Self::BLOCK_LEN, 0,
                            self.flags | super::PARENT,
                        );
                        right.copy_from_slice(&state[..8]);
                    }
                    unreachable!();
                }

                let block_words = super::u32x16_from_le_bytes(&self.buffer);
                let flags = if self.chunk_block_counter == 0 {
                    self.flags | super::CHUNK_START | super::CHUNK_END
                } else {
                    self.flags | super::CHUNK_END
                };

                // Current node (the tail of the last chunk).
                let mut key_words = self.chunk_chaining_value;
                let mut bw = block_words;
                let mut bl = self.offset;
                let mut ctr = self.chunk_counter;
                let mut fl = flags;

                // Walk up the Merkle tree.
                let mut index = self.stack_len;
                while index > 0 {
                    index -= 1;
                    let left_child = unsafe { *self.stack.get_unchecked(index) };

                    let cv_state = $transform(&key_words, &bw, bl, ctr, fl);
                    let mut right_cv = [0u32; 8];
                    right_cv.copy_from_slice(&cv_state[..8]);

                    let mut parent_bw = [0u32; 16];
                    parent_bw[0..8].copy_from_slice(&left_child);
                    parent_bw[8..16].copy_from_slice(&right_cv);

                    key_words = self.key;
                    bw = parent_bw;
                    bl = Self::BLOCK_LEN;
                    ctr = 0;
                    fl = self.flags | super::PARENT;
                }

                // Root output (supports XOF – arbitrary-length output).
                let root_flags = fl | super::ROOT;
                let mut counter = 0u64;
                for out_block in digest.chunks_mut(Self::BLOCK_LEN) {
                    let state = $transform(&key_words, &bw, bl, counter, root_flags);
                    let stream = super::u32x16_to_le_bytes(&state);
                    let olen = out_block.len();
                    out_block.copy_from_slice(&stream[..olen]);
                    counter += 1;
                }
            }

            pub fn oneshot<S: AsRef<[u8]>>(data: S) -> [u8; Self::DIGEST_LEN] {
                let data = data.as_ref();

                #[allow(unreachable_code)]
                {
                    $(
                    let _ = $feat;
                    return if data.len() <= Self::CHUNK_LEN {
                        unsafe { Self::oneshot_single_featured(data) }
                    } else if data.len() < Self::FEW_THRESHOLD {
                        unsafe { Self::oneshot_few_featured(data) }
                    } else {
                        unsafe { Self::oneshot_multi_featured(data) }
                    };
                    )?
                    if data.len() <= Self::CHUNK_LEN {
                        Self::oneshot_single_impl(data)
                    } else if data.len() < Self::FEW_THRESHOLD {
                        Self::oneshot_few_impl(data)
                    } else {
                        Self::oneshot_multi_impl(data)
                    }
                }
            }

            $(
            #[target_feature(enable = $feat)]
            #[inline(never)]
            unsafe fn oneshot_single_featured(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                Self::oneshot_single_body(data)
            }

            #[target_feature(enable = $feat)]
            #[inline(never)]
            unsafe fn oneshot_few_featured(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                Self::oneshot_few_body::<true>(data)
            }

            #[target_feature(enable = $feat)]
            #[inline(never)]
            unsafe fn oneshot_multi_featured(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                Self::oneshot_multi_body::<true>(data)
            }
            )?

            #[inline(never)]
            fn oneshot_single_impl(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                Self::oneshot_single_body(data)
            }

            #[inline(never)]
            fn oneshot_few_impl(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                Self::oneshot_few_body::<false>(data)
            }

            #[inline(never)]
            fn oneshot_multi_impl(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                Self::oneshot_multi_body::<false>(data)
            }

            /// Fast single-chunk path: process blocks directly, no hasher
            /// struct, no buffer copies, no heap allocation.
            #[inline(always)]
            fn oneshot_single_body(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                let mut digest = [0u8; Self::DIGEST_LEN];
                let n_blocks = ((data.len() + 63) / 64).max(1);
                let mut cv = super::IV;
                for blk in 0..n_blocks {
                    let start = blk * 64;
                    let end = (start + 64).min(data.len());
                    let len = end - start;
                    // On little-endian x86, [u8; 64] and [u32; 16] have the
                    // same layout.  For full blocks, cast directly from the
                    // input buffer avoiding an intermediate copy.
                    let mut pad_buf = [0u8; 64];
                    let words: &[u32; 16] = if len == 64 {
                        unsafe { &*(data.as_ptr().add(start) as *const [u32; 16]) }
                    } else {
                        pad_buf[..len].copy_from_slice(&data[start..end]);
                        unsafe { &*(&pad_buf as *const [u8; 64] as *const [u32; 16]) }
                    };
                    let mut bf = 0u32;
                    if blk == 0 { bf |= super::CHUNK_START; }
                    if blk == n_blocks - 1 {
                        bf |= super::CHUNK_END | super::ROOT;
                        let state = unsafe { $transform_inline(&cv, words, len, 0, bf) };
                        let stream = super::u32x16_to_le_bytes(&state);
                        digest.copy_from_slice(&stream[..Self::DIGEST_LEN]);
                    } else {
                        let state = unsafe { $transform_inline(&cv, words, 64, 0, bf) };
                        cv.copy_from_slice(&state[..8]);
                    }
                }
                digest
            }

            /// Lightweight few-chunks path for 2+ chunks below the minimum
            /// SIMD tier.  Uses SIMD partial-batch padding when all chunks
            /// are full: pads remaining chunks to the narrowest tier size
            /// and calls the SIMD hash function, using only real CVs.
            /// Falls back to serial transform for tail/mixed input.
            #[inline(always)]
            fn oneshot_few_body<const FEATURED: bool>(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                let key = super::IV;
                let n_full = data.len() / Self::CHUNK_LEN;
                let tail_len = data.len() % Self::CHUNK_LEN;
                let n_chunks = n_full + (tail_len > 0) as usize;

                let mut cvs = [[0u32; 8]; 16];
                let mut cv_count = 0usize;

                // Narrowest SIMD tier size (compile-time constant).
                // 0 = no SIMD tiers (soft fallback).
                const _NARROWEST: usize = {
                    let mut m = 0usize;
                    $(
                        if m == 0 || $nway < m { m = $nway; }
                    )*
                    m
                };

                // ── SIMD partial-batch: pad full chunks to narrowest tier ──
                // When all chunks are full (no partial tail), pad to the
                // narrowest SIMD tier and use vectorised hashing.
                // `$nway == _NARROWEST` ensures only ONE tier fires
                // (LLVM dead-code-eliminates the rest).
                // Single padded array sized to narrowest tier, outside $()*
                // to avoid multiple large stack allocations in debug mode.
                #[allow(unused_assignments, unused_mut, unreachable_code)]
                if tail_len == 0 && n_full >= 2 && _NARROWEST > 0 {
                    let mut padded = [0u8; _NARROWEST * Self::CHUNK_LEN];
                    padded[..data.len()].copy_from_slice(data);
                    $(
                    if $nway == _NARROWEST {
                        let input_ref = unsafe { &*(padded.as_ptr() as *const [u8; $nway * 1024]) };
                        let batch = if FEATURED {
                            unsafe { $hash_il(
                                input_ref, &key, 0, 0,
                            ) }
                        } else {
                            $hash_fn(
                                input_ref, &key, 0, 0,
                            )
                        };
                        for i in 0..n_full {
                            cvs[i] = batch[i];
                        }
                        cv_count = n_full;
                    }
                    )*
                } else {
                    // ── Serial fallback (tail chunk or no SIMD tiers) ──
                    let mut chunk_counter = 0u64;
                    let mut pos = 0usize;

                    for _ in 0..n_full {
                        let base = unsafe { data.as_ptr().add(pos) };
                        let mut cv = key;
                        for blk in 0u32..16 {
                            let words = unsafe {
                                &*(base.add(blk as usize * 64) as *const [u32; 16])
                            };
                            let bf = match blk {
                                0  => super::CHUNK_START,
                                15 => super::CHUNK_END,
                                _  => 0,
                            };
                            let state = unsafe { $transform_inline(
                                &cv, words, Self::BLOCK_LEN, chunk_counter, bf,
                            ) };
                            cv.copy_from_slice(&state[..8]);
                        }
                        cvs[cv_count] = cv;
                        cv_count += 1;
                        chunk_counter += 1;
                        pos += Self::CHUNK_LEN;
                    }

                    // Partial tail chunk.
                    if tail_len > 0 {
                        let n_blocks = (tail_len + 63) / 64;
                        let mut cv = key;
                        for blk in 0..n_blocks {
                            let start = pos + blk * 64;
                            let end = data.len().min(start + 64);
                            let len = end - start;
                            let mut pad_buf = [0u8; 64];
                            let words: &[u32; 16] = if len == 64 {
                                unsafe { &*(data.as_ptr().add(start) as *const [u32; 16]) }
                            } else {
                                pad_buf[..len].copy_from_slice(&data[start..end]);
                                unsafe { &*(&pad_buf as *const [u8; 64] as *const [u32; 16]) }
                            };
                            let mut bf = 0u32;
                            if blk == 0 { bf |= super::CHUNK_START; }
                            if blk == n_blocks - 1 { bf |= super::CHUNK_END; }
                            let state = unsafe { $transform_inline(
                                &cv, words, len, chunk_counter, bf,
                            ) };
                            cv.copy_from_slice(&state[..8]);
                        }
                        cvs[cv_count] = cv;
                        cv_count += 1;
                    }
                }

                // ── Tree merge (small fixed-size array, simple loop) ──
                let mut n = cv_count;
                while n > 2 {
                    let mut read = 0usize;
                    let mut write = 0usize;
                    let pflags = super::PARENT;
                    while read + 2 <= n {
                        let mut bw = [0u32; 16];
                        bw[..8].copy_from_slice(&cvs[read]);
                        bw[8..].copy_from_slice(&cvs[read + 1]);
                        let state = unsafe { $transform_inline(
                            &key, &bw, Self::BLOCK_LEN, 0, pflags,
                        ) };
                        cvs[write].copy_from_slice(&state[..8]);
                        read += 2;
                        write += 1;
                    }
                    if read < n {
                        cvs[write] = cvs[read];
                        write += 1;
                    }
                    n = write;
                }

                // Root merge (n == 2).
                debug_assert_eq!(n, 2);
                let mut bw = [0u32; 16];
                bw[..8].copy_from_slice(&cvs[0]);
                bw[8..].copy_from_slice(&cvs[1]);
                let root_flags = super::PARENT | super::ROOT;
                let state = unsafe { $transform_inline(
                    &key, &bw, Self::BLOCK_LEN, 0, root_flags,
                ) };
                let stream = super::u32x16_to_le_bytes(&state);
                let mut digest = [0u8; Self::DIGEST_LEN];
                digest.copy_from_slice(&stream[..Self::DIGEST_LEN]);
                digest
            }

            #[inline(always)]
            fn oneshot_multi_body<const FEATURED: bool>(data: &[u8]) -> [u8; Self::DIGEST_LEN] {
                // ── Multi-chunk path ──
                let mut digest = [0u8; Self::DIGEST_LEN];
                let key = super::IV;
                let flags = 0u32;
                let n_full = data.len() / Self::CHUNK_LEN;
                let tail_len = data.len() % Self::CHUNK_LEN;

                // ── Phase 1: compute ALL chunk CVs into a flat array ──
                let n_chunks = n_full + (tail_len > 0) as usize;
                // Stack buffer for ≤ 256 chunks (256 KiB); heap for larger.
                const STACK_CVS: usize = 256;
                let mut cvs_stack =
                    core::mem::MaybeUninit::<[[u32; 8]; STACK_CVS]>::uninit();
                let mut cvs_heap = if n_chunks > STACK_CVS {
                    Vec::<[u32; 8]>::with_capacity(n_chunks)
                } else {
                    Vec::new() // zero-capacity, no allocation
                };
                // SAFETY: stack buffer or heap buffer is large enough; all
                // entries 0..cv_count are written before read.
                let cvs_ptr: *mut [u32; 8] = if n_chunks <= STACK_CVS {
                    cvs_stack.as_mut_ptr() as *mut [u32; 8]
                } else {
                    cvs_heap.as_mut_ptr()
                };
                let mut cv_count = 0usize;
                let mut pos = 0usize;
                let mut chunk_counter = 0u64;
                let full_end = n_full * Self::CHUNK_LEN;

                // SIMD tiers (widest first, >= condition).
                // When FEATURED=true, use $hash_il (inline).
                // When FEATURED=false, use $hash_fn (safe wrappers).
                $(
                while full_end - pos >= $nway * Self::CHUNK_LEN {
                    let input_ref = unsafe { &*(data.as_ptr().add(pos) as *const [u8; $nway * 1024]) };
                    let batch = if FEATURED {
                        unsafe { $hash_il(
                            input_ref, &key, chunk_counter, flags,
                        ) }
                    } else {
                        $hash_fn(
                            input_ref, &key, chunk_counter, flags,
                        )
                    };
                    for cv in &batch {
                        unsafe { *cvs_ptr.add(cv_count) = *cv; }
                        cv_count += 1;
                        chunk_counter += 1;
                    }
                    pos += $nway * Self::CHUNK_LEN;
                }
                )*

                // Remaining full chunks (single-chunk fast path).
                while pos + Self::CHUNK_LEN <= full_end {
                    let base = unsafe { data.as_ptr().add(pos) };
                    let mut cv = key;
                    for blk in 0u32..16 {
                        // Zero-copy pointer cast on little-endian x86/ARM:
                        // [u8; 64] and [u32; 16] have the same layout.
                        let words = unsafe {
                            &*(base.add(blk as usize * 64) as *const [u32; 16])
                        };
                        let bf = match blk {
                            0  => flags | super::CHUNK_START,
                            15 => flags | super::CHUNK_END,
                            _  => flags,
                        };
                        let state = unsafe { $transform_inline(
                            &cv, words, Self::BLOCK_LEN,
                            chunk_counter, bf,
                        ) };
                        cv.copy_from_slice(&state[..8]);
                    }
                    unsafe { *cvs_ptr.add(cv_count) = cv; }
                    cv_count += 1;
                    chunk_counter += 1;
                    pos += Self::CHUNK_LEN;
                }

                // Partial tail chunk.
                if tail_len > 0 {
                    let n_blocks = (tail_len + 63) / 64;
                    let mut cv = key;
                    for blk in 0..n_blocks {
                        let start = pos + blk * 64;
                        let end = data.len().min(start + 64);
                        let len = end - start;
                        let mut block_buf = [0u8; 64];
                        block_buf[..len].copy_from_slice(&data[start..end]);
                        let words = super::u32x16_from_le_bytes(&block_buf);
                        let mut bf = flags;
                        if blk == 0 { bf |= super::CHUNK_START; }
                        if blk == n_blocks - 1 { bf |= super::CHUNK_END; }
                        let state = unsafe { $transform_inline(
                            &cv, &words, len, chunk_counter, bf,
                        ) };
                        cv.copy_from_slice(&state[..8]);
                    }
                    unsafe { *cvs_ptr.add(cv_count) = cv; }
                    cv_count += 1;
                }

                // ── Phase 2: balanced layer-by-layer tree merge ──
                let mut n = cv_count;

                // Reduce until exactly 2 CVs remain.
                while n > 2 {
                    let mut read = 0usize;
                    let mut write = 0usize;
                    let pflags = flags | super::PARENT;

                    // SIMD parent batch (active when parent_batch provided).
                    $(
                    while read + 2 * $pb_size <= n {
                        let batch = $pb_fn(
                            unsafe { cvs_ptr.add(read) as *const [u32; 8] },
                            &key, pflags,
                        );
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                batch.as_ptr(),
                                cvs_ptr.add(write),
                                $pb_size,
                            );
                        }
                        read += 2 * $pb_size;
                        write += $pb_size;
                    }
                    )?

                    // Two-level inline parent batch (FEATURED only):
                    // wider level first (e.g. 8-way), then narrower (e.g. 4-way).
                    $(
                    if FEATURED {
                        while read + 2 * $pb_il1_size <= n {
                            let batch = unsafe { $pb_il1_fn(
                                cvs_ptr.add(read) as *const [u32; 8],
                                &key, pflags,
                            ) };
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    batch.as_ptr(),
                                    cvs_ptr.add(write),
                                    $pb_il1_size,
                                );
                            }
                            read += 2 * $pb_il1_size;
                            write += $pb_il1_size;
                        }
                        while read + 2 * $pb_il2_size <= n {
                            let batch = unsafe { $pb_il2_fn(
                                cvs_ptr.add(read) as *const [u32; 8],
                                &key, pflags,
                            ) };
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    batch.as_ptr(),
                                    cvs_ptr.add(write),
                                    $pb_il2_size,
                                );
                            }
                            read += 2 * $pb_il2_size;
                            write += $pb_il2_size;
                        }
                    }
                    )?

                    // Serial fallback for remaining pairs.
                    while read + 2 <= n {
                        let l = unsafe { *cvs_ptr.add(read) };
                        let r = unsafe { *cvs_ptr.add(read + 1) };
                        let mut bw = [0u32; 16];
                        bw[..8].copy_from_slice(&l);
                        bw[8..].copy_from_slice(&r);
                        let state = unsafe { $transform_inline(
                            &key, &bw, Self::BLOCK_LEN, 0, pflags,
                        ) };
                        let mut cv = [0u32; 8];
                        cv.copy_from_slice(&state[..8]);
                        unsafe { *cvs_ptr.add(write) = cv; }
                        read += 2;
                        write += 1;
                    }

                    if read < n {
                        if write != read {
                            unsafe {
                                *cvs_ptr.add(write) = *cvs_ptr.add(read);
                            }
                        }
                        write += 1;
                    }

                    n = write;
                }

                // Root merge (n == 2).
                debug_assert_eq!(n, 2);
                {
                    let mut bw = [0u32; 16];
                    let l = unsafe { *cvs_ptr.add(0) };
                    let r = unsafe { *cvs_ptr.add(1) };
                    bw[..8].copy_from_slice(&l);
                    bw[8..].copy_from_slice(&r);
                    let root_flags = flags | super::PARENT | super::ROOT;
                    let mut counter = 0u64;
                    for out_block in digest.chunks_mut(Self::BLOCK_LEN) {
                        let state = unsafe { $transform_inline(
                            &key, &bw, Self::BLOCK_LEN,
                            counter, root_flags,
                        ) };
                        let stream = super::u32x16_to_le_bytes(&state);
                        let olen = out_block.len();
                        out_block.copy_from_slice(&stream[..olen]);
                        counter += 1;
                    }
                    return digest;
                }
            }
        }
    };
}

macro_rules! G {
    ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
        $a = $a.wrapping_add($b).wrapping_add($mx);
        $d = ($d ^ $a).rotate_right(16);

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(12);

        $a = $a.wrapping_add($b).wrapping_add($my);
        $d = ($d ^ $a).rotate_right(8);

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(7);
    };
}

macro_rules! ROUND {
    ($state:tt, $m:tt) => {
        G!($state[0], $state[4], $state[8], $state[12], $m[0], $m[1]);
        G!($state[1], $state[5], $state[9], $state[13], $m[2], $m[3]);
        G!($state[2], $state[6], $state[10], $state[14], $m[4], $m[5]);
        G!($state[3], $state[7], $state[11], $state[15], $m[6], $m[7]);
        G!($state[0], $state[5], $state[10], $state[15], $m[8], $m[9]);
        G!($state[1], $state[6], $state[11], $state[12], $m[10], $m[11]);
        G!($state[2], $state[7], $state[8], $state[13], $m[12], $m[13]);
        G!($state[3], $state[4], $state[9], $state[14], $m[14], $m[15]);
    };
}

macro_rules! ROUND_AND_SHUFFLE {
    ($state:tt, $m:tt, $m_copy:tt) => {
        ROUND!($state, $m);
        $m_copy[0] = $m[2];  $m_copy[1] = $m[6];  $m_copy[2] = $m[3];  $m_copy[3] = $m[10];
        $m_copy[4] = $m[7];  $m_copy[5] = $m[0];  $m_copy[6] = $m[4];  $m_copy[7] = $m[13];
        $m_copy[8] = $m[1];  $m_copy[9] = $m[11]; $m_copy[10] = $m[12]; $m_copy[11] = $m[5];
        $m_copy[12] = $m[9]; $m_copy[13] = $m[14]; $m_copy[14] = $m[15]; $m_copy[15] = $m[8];
    };
}

macro_rules! ROUNDS {
    ($state:tt, $m:tt, $m_copy:tt) => {
        ROUND_AND_SHUFFLE!($state, $m, $m_copy);
        ROUND_AND_SHUFFLE!($state, $m_copy, $m);
        ROUND_AND_SHUFFLE!($state, $m, $m_copy);
        ROUND_AND_SHUFFLE!($state, $m_copy, $m);
        ROUND_AND_SHUFFLE!($state, $m, $m_copy);
        ROUND_AND_SHUFFLE!($state, $m_copy, $m);
        ROUND!($state, $m);
    };
}

#[inline(always)]
fn transform(
    chaining_value: &[u32; 8],
    block: &[u32; 16],
    block_len: usize,
    counter: u64,
    flags: u32,
) -> [u32; 16] {
    let mut m = *block;
    let mut v = [0u32; 16];
    let mut m_copy = [0u32; 16];

    v[..8].copy_from_slice(&chaining_value[..]);
    v[8] = super::IV[0];
    v[9] = super::IV[1];
    v[10] = super::IV[2];
    v[11] = super::IV[3];
    v[12] = counter as u32;
    v[13] = (counter >> 32) as u32;
    v[14] = block_len as u32;
    v[15] = flags;

    ROUNDS!(v, m, m_copy);

    v[0] ^= v[8];   v[8]  ^= chaining_value[0];
    v[1] ^= v[9];   v[9]  ^= chaining_value[1];
    v[2] ^= v[10];  v[10] ^= chaining_value[2];
    v[3] ^= v[11];  v[11] ^= chaining_value[3];
    v[4] ^= v[12];  v[12] ^= chaining_value[4];
    v[5] ^= v[13];  v[13] ^= chaining_value[5];
    v[6] ^= v[14];  v[14] ^= chaining_value[6];
    v[7] ^= v[15];  v[15] ^= chaining_value[7];

    v
}

blake3_impl!(transform);

#[cfg(test)]
mod tests {
    use super::Blake3;

    blake3_test_case!();
}
