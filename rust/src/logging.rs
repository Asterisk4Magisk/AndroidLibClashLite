// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use meow_api::log_stream::{parse_log_level, LogBroadcastLayer, LogLevel, LogMessage};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU8, Ordering},
        OnceLock,
    },
};
use tokio::sync::broadcast;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};

static LOGS: Mutex<VecDeque<serde_json::Value>> = Mutex::new(VecDeque::new());
// The broadcast layer sees every event so `/logs?level=` keeps working; the
// captured logcat stream follows `log-level` like the Go backend does.
static CAPTURE_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

pub fn channel() -> broadcast::Sender<LogMessage> {
    static CHANNEL: OnceLock<broadcast::Sender<LogMessage>> = OnceLock::new();
    CHANNEL
        .get_or_init(|| {
            let (tx, _) = broadcast::channel(256);
            let (filter, reload) =
                tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("info"));
            let subscriber = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_filter(filter),
                )
                .with(LogBroadcastLayer { tx: tx.clone() }.with_filter(broadcast_filter()));
            // A foreign subscriber may already own the process. Keep the core usable.
            if subscriber.try_init().is_ok() {
                meow_api::log_stream::install_log_reloader(move |level| {
                    CAPTURE_LEVEL.store(parse_log_level(level) as u8, Ordering::Relaxed);
                    let level = match level {
                        "warning" => "warn",
                        "silent" => "off",
                        v => v,
                    };
                    reload
                        .reload(tracing_subscriber::EnvFilter::new(level))
                        .map_err(|e| e.to_string())
                });
            }
            tx
        })
        .clone()
}

// The jni crate traces every JNI call, including the log polling itself, which
// would flood the stream; keep only its warnings and errors.
fn broadcast_filter() -> Targets {
    Targets::new()
        .with_default(LevelFilter::TRACE)
        .with_target("jni", LevelFilter::WARN)
}

pub fn capture() {
    LOGS.lock().clear();
    let mut rx = channel().subscribe();
    crate::get_runtime().spawn(async move {
        loop {
            match rx.recv().await {
                Ok(message) => {
                    if !captures(message.level, CAPTURE_LEVEL.load(Ordering::Relaxed)) {
                        continue;
                    }
                    if let Ok(value) = serde_json::to_value(message) {
                        let mut logs = LOGS.lock();
                        if logs.len() == 256 {
                            logs.pop_front();
                        }
                        logs.push_back(value);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });
}

fn captures(level: LogLevel, threshold: u8) -> bool {
    level as u8 >= threshold
}

pub fn read() -> String {
    serde_json::to_string(&LOGS.lock().drain(..).collect::<Vec<_>>()).unwrap()
}

pub fn bridge_log(message: &str) {
    tracing::info!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_follows_log_level() {
        let threshold = |level| parse_log_level(level) as u8;
        assert!(!captures(LogLevel::Debug, threshold("info")));
        assert!(captures(LogLevel::Info, threshold("info")));
        assert!(captures(LogLevel::Debug, threshold("debug")));
        assert!(!captures(LogLevel::Info, threshold("warning")));
        assert!(captures(LogLevel::Warning, threshold("warn")));
        assert!(!captures(LogLevel::Error, threshold("silent")));
    }

    #[test]
    fn broadcast_drops_jni_traces() {
        use tracing::Level;
        let filter = broadcast_filter();
        assert!(!filter.would_enable("jni::wrapper::jnienv", &Level::TRACE));
        assert!(filter.would_enable("jni::wrapper::jnienv", &Level::ERROR));
        assert!(filter.would_enable("meow_tunnel::tunnel", &Level::TRACE));
        assert!(filter.would_enable("rsjni::jni_api", &Level::TRACE));
    }
}
