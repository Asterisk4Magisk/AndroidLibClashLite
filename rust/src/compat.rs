// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//! Stateless profile work runs outside the engine mutation lock.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{collections::HashMap, path::Path, sync::LazyLock};
use tokio::sync::watch;

static FETCHES: LazyLock<parking_lot::Mutex<HashMap<i64, watch::Sender<bool>>>> =
    LazyLock::new(Default::default);
pub fn command(operation: &str, input: &str) -> Result<String> {
    let args: Value = serde_json::from_str(input)?;
    let text = |key: &str| args[key].as_str().unwrap_or("");
    let value = match operation {
        "diagnostics" => serde_json::to_value(
            crate::profile::decode_with_diagnostics(&STANDARD.decode(text("content"))?)?.1,
        )?,
        "formatProxies" => {
            crate::compatibility::format_proxies(text("pattern"), args["proxies"].clone())
        }
        "tunOptions" => {
            for (key, accepted) in [
                ("stack", &["", "system", "lwip"][..]),
                ("controller", &["", "cubic"][..]),
            ] {
                if !accepted.iter().any(|v| text(key).eq_ignore_ascii_case(v)) {
                    tracing::warn!(field = key, "TUN option is ignored; using the existing lwIP stack and congestion behavior");
                }
            }
            Value::Null
        }
        "prepare" => crate::profile::prepare(
            &STANDARD.decode(text("content"))?,
            Path::new(text("base")),
            Path::new(text("home")),
            text("persist"),
            text("session"),
        )?,
        "decrypt" => json!(String::from_utf8(crate::profile::decrypt(
            text("content").as_bytes(),
            text("keys")
        )?)?),
        "validKeys" => json!(crate::profile::valid_keys(text("keys"))),
        "setKeys" => {
            crate::profile::set_keys(text("keys"));
            Value::Null
        }
        "launcher" => json!(launcher()?),
        "memory" => json!(resident_memory()),
        "beginFetch" => {
            let id = args["id"].as_i64().context("fetch id")?;
            let mut tasks = FETCHES.lock();
            anyhow::ensure!(!tasks.contains_key(&id), "duplicate fetch task ID");
            tasks.insert(id, watch::channel(false).0);
            Value::Null
        }
        "cancelFetch" => {
            if let Some(task) = FETCHES
                .lock()
                .get(&args["id"].as_i64().context("fetch id")?)
            {
                task.send_replace(true);
            }
            Value::Null
        }
        "endFetch" => {
            FETCHES
                .lock()
                .remove(&args["id"].as_i64().context("fetch id")?);
            Value::Null
        }
        "http" => {
            let mut cancel = FETCHES
                .lock()
                .get(&args["id"].as_i64().context("fetch id")?)
                .context("fetch task not registered")?
                .subscribe();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                tokio::select! {
                    _ = cancel.wait_for(|v| *v) => anyhow::bail!("context canceled"),
                    result = tokio::time::timeout(std::time::Duration::from_secs(60), fetch(&args)) => result.context("subscription request timed out")?,
                }
            })?
        }
        _ => anyhow::bail!("unknown compatibility operation: {operation}"),
    };
    Ok(value.to_string())
}

async fn fetch(args: &Value) -> Result<Value> {
    let mut url = url::Url::parse(args["url"].as_str().context("subscription URL")?)?;
    let hwid = args["hwid"].as_str().unwrap_or("");
    anyhow::ensure!(
        hwid.is_empty()
            || ((10..=64).contains(&hwid.len())
                && hwid
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'=' | b'-'))),
        "HWID_INVALID"
    );
    let mut headers = Vec::new();
    if !hwid.is_empty() {
        headers.push(("X-Hwid".into(), hwid.into()));
    }
    if let Some(ua) = args["userAgent"].as_str().filter(|v| !v.is_empty()) {
        headers.push(("User-Agent".into(), ua.into()));
    }
    if !url.username().is_empty() {
        let username = percent_encoding::percent_decode_str(url.username()).decode_utf8()?;
        let password =
            percent_encoding::percent_decode_str(url.password().unwrap_or("")).decode_utf8()?;
        let credentials = format!("{username}:{password}");
        headers.push((
            "Authorization".into(),
            format!("Basic {}", STANDARD.encode(credentials)),
        ));
        let _ = url.set_username("");
        let _ = url.set_password(None);
    }
    let proxy =
        if args["proxy"].is_object() && !args["proxy"]["host"].as_str().unwrap_or("").is_empty() {
            let mut spec = HashMap::new();
            for (key, value) in [
                ("name", json!("subscription")),
                ("type", json!("socks5")),
                ("server", args["proxy"]["host"].clone()),
                ("port", args["proxy"]["port"].clone()),
                ("username", args["proxy"]["username"].clone()),
                ("password", args["proxy"]["password"].clone()),
            ] {
                if !value.is_null() {
                    spec.insert(key.to_owned(), value);
                }
            }
            Some(meow_config::proxy_parser::parse_proxy(&spec, true).map_err(anyhow::Error::msg)?)
        } else {
            None
        };
    let response =
        meow_config::internal_http::fetch_subscription(url.as_str(), proxy.as_ref(), &headers)
            .await?;
    let mut headers = serde_json::Map::new();
    for name in [
        "subscription-userinfo",
        "profile-update-interval",
        "content-disposition",
    ] {
        if let Some(value) = response.header(name) {
            headers.insert(name.into(), json!(value));
        }
    }
    Ok(json!({"body":STANDARD.encode(&response.body), "headers":headers}))
}

fn resident_memory() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
        .unwrap_or(0)
        * 1024
}
pub fn launcher() -> Result<String> {
    #[cfg(unix)]
    {
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        anyhow::ensure!(
            unsafe { libc::dladdr(launcher as *const () as *const libc::c_void, &mut info) } != 0,
            "cannot locate native library"
        );
        let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_str()?;
        let path = Path::new(path)
            .parent()
            .context("native library directory")?
            .join("libmeow.so");
        anyhow::ensure!(
            path.is_file(),
            "libmeow.so must be extracted beside librsjni.so"
        );
        Ok(path.to_string_lossy().into_owned())
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("Android launcher required")
    }
}
