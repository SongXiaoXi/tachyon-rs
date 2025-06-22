extern crate rustc_version;
use rustc_version::{version_meta, Channel};

fn main() {
    let mut is_unstable = false;
    let version_meta = version_meta().unwrap();
    match version_meta.channel {
        Channel::Stable => (),
        Channel::Nightly | Channel::Dev | Channel::Beta => {
            println!("cargo:rustc-cfg=feature=\"nightly\"");
            println!("cargo:rustc-cfg=nightly_feature");
            is_unstable = true;
        }
    }
    // avx512 is only available in Rust 1.89 and later
    if is_unstable || (version_meta.semver.major >= 1 && version_meta.semver.minor >= 89) {
        println!("cargo:rustc-cfg=avx512_feature");
    }
    cfg_aliases::cfg_aliases! {
        ghash_block_x6: {any(target_arch = "x86", target_arch = "x86_64", all(target_vendor = "apple", target_arch = "aarch64"))},
    }
}