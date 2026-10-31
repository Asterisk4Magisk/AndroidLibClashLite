// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use meow_api::log_stream::{LogBroadcastLayer, LogMessage};
use parking_lot::Mutex;
use std::{collections::VecDeque, sync::OnceLock};
use tokio::sync::broadcast;
use tracing_subscriber::{filter::LevelFilter, prelude::*};

static LOGS: Mutex<VecDeque<serde_json::Value>> = Mutex::new(VecDeque::new());

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
                .with(LogBroadcastLayer { tx: tx.clone() }.with_filter(LevelFilter::TRACE));
            // A foreign subscriber may already own the process. Keep the core usable.
            if subscriber.try_init().is_ok() {
                meow_api::log_stream::install_log_reloader(move |level| {
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

pub fn capture() {
    LOGS.lock().clear();
    let mut rx = channel().subscribe();
    crate::get_runtime().spawn(async move {
        loop {
            match rx.recv().await {
                Ok(message) => {
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

pub fn read() -> String {
    serde_json::to_string(&LOGS.lock().drain(..).collect::<Vec<_>>()).unwrap()
}

pub fn bridge_log(message: &str) {
    tracing::info!("{message}");
}
