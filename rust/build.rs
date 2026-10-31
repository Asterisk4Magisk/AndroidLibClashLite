// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

fn main() {
    println!("cargo:rerun-if-changed=upstream.json");
    let pin: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("upstream.json").unwrap()).unwrap();
    let version = pin["version"].as_str().expect("meow version");
    let revision = pin["revision"].as_str().expect("meow revision");
    println!(
        "cargo:rustc-env=LIBCLASH_CORE_VERSION=meow v{version} ({:.12})",
        revision
    );
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rerun-if-env-changed=LIBCLASH_SYSTEM_DNS_DEX");
        let dex = std::env::var("LIBCLASH_SYSTEM_DNS_DEX")
            .expect("Build with scripts/build_rust.py to embed the Android DNS helper");
        println!("cargo:rerun-if-changed={dex}");
        std::fs::copy(
            dex,
            std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("system-dns-helper.dex"),
        )
        .unwrap();
        // BoringSSL/quiche use libc++_static; its exception/runtime symbols
        // live in the NDK's separate libc++abi archive.
        println!("cargo:rustc-link-arg=-lc++abi");
        println!("cargo:rustc-link-arg=-Wl,--no-undefined");
    }
}
