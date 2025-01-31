extern crate rustc_version;
use rustc_version::{version_meta, Channel};

fn main() {
    match version_meta().unwrap().channel {
        Channel::Stable => (),
        Channel::Nightly | Channel::Dev | Channel::Beta => {
            println!("cargo:rustc-cfg=feature=\"nightly\"");
        }
    }
}