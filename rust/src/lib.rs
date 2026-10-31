// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

mod autoswitch;
mod cli;
mod compat;
mod compatibility;
mod control;
mod engine;
mod jni_api;
mod listeners;
mod logging;
#[cfg(test)]
mod network_tests;
mod platform;
mod profile;
mod systemdns;
#[cfg(test)]
mod tests;
#[cfg(unix)]
mod tun2socks;

use std::sync::Arc;

pub const CORE_VERSION: &str = env!("LIBCLASH_CORE_VERSION");

static RUNTIME: parking_lot::Mutex<Option<Arc<tokio::runtime::Runtime>>> =
    parking_lot::Mutex::new(None);

fn get_runtime() -> Arc<tokio::runtime::Runtime> {
    Arc::clone(RUNTIME.lock().get_or_insert_with(|| {
        Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("libclash-rs")
                .thread_stack_size(2 * 1024 * 1024)
                .build()
                .expect("create libclash-rs runtime"),
        )
    }))
}

fn drop_runtime() {
    // Public JNI operations are serialized; no request can retain a runtime here.
    let runtime = RUNTIME.lock().take();
    drop(runtime);
}
