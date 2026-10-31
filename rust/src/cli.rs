// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{bail, Context, Result};
use std::{ffi::CStr, path::PathBuf};

fn run(args: Vec<String>) -> Result<i32> {
    let _operation = crate::engine::OPERATION.lock();
    let mut home = std::env::current_dir()?;
    let mut config = PathBuf::from("config.yaml");
    let mut test = false;
    let mut base = None;
    let mut args = args.into_iter().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-v" | "--version" => {
                println!("{}", crate::CORE_VERSION);
                return Ok(0);
            }
            "-h" | "--help" => {
                println!("meow Android: libmeow.so [-d HOME] [-f CONFIG] [-t]\n-v, --version  Print version\n-t            Validate configuration offline");
                return Ok(0);
            }
            "-d" | "--directory" => {
                home = PathBuf::from(args.next().context("-d requires a directory")?)
            }
            "-f" | "--config" => config = PathBuf::from(args.next().context("-f requires a file")?),
            "-b" | "--base-directory" => {
                base = Some(args.next().context("-b requires a directory")?)
            }
            "-t" | "--test" => test = true,
            _ => bail!("unsupported meow Android argument: {arg}"),
        }
    }
    if !home.is_absolute() {
        home = std::env::current_dir()?.join(home);
    }
    if !config.is_absolute() {
        config = home.join(config);
    }
    if let Ok(keys) = std::env::var("CLASH_AGE_SECRET_KEY") {
        crate::profile::set_keys(&keys);
    }
    let bytes = std::fs::read(&config).context("read config file")?;
    let home = home.to_string_lossy().to_string();
    if test {
        crate::engine::validate(&home, base.as_deref().unwrap_or(&home), &bytes)?;
        println!("Configuration test passed");
        return Ok(0);
    }
    // Install signal listeners before startup can expose listeners or a ready API.
    let wait = crate::get_runtime().block_on(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok::<_, anyhow::Error>((
                signal(SignalKind::interrupt())?,
                signal(SignalKind::terminate())?,
            ))
        }
        #[cfg(not(unix))]
        Ok::<_, anyhow::Error>(())
    })?;
    #[cfg(target_os = "android")]
    let mut system_dns = crate::systemdns::root::Watcher::start(std::path::Path::new(&home))?;
    let result = crate::engine::start(
        &home,
        &home,
        &bytes,
        Some(config.to_string_lossy().to_string()),
    );
    if let Err(error) = result {
        #[cfg(target_os = "android")]
        if let Some(watcher) = &mut system_dns {
            watcher.stop();
        }
        crate::engine::stop();
        return Err(error);
    }
    crate::get_runtime().block_on(async {
        #[cfg(unix)]
        {
            let (mut interrupt, mut terminate) = wait;
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        }
        #[cfg(not(unix))]
        {
            let _ = wait;
            let _ = tokio::signal::ctrl_c().await;
        }
    });
    let status = 0;
    #[cfg(target_os = "android")]
    let status = if let Some(watcher) = &mut system_dns {
        watcher.stop();
        if watcher.failed() {
            70
        } else {
            status
        }
    } else {
        status
    };
    crate::engine::stop();
    Ok(status)
}

/// Standalone process only. JNI callers must use the Java lifecycle API.
#[no_mangle]
pub unsafe extern "C" fn AndroidMeowCLI_v1(
    argc: libc::c_int,
    argv: *const *const libc::c_char,
) -> libc::c_int {
    let result = std::panic::catch_unwind(|| {
        if argc < 1 || argv.is_null() {
            bail!("invalid CLI argv");
        }
        let args = std::slice::from_raw_parts(argv, argc as usize)
            .iter()
            .map(|arg| {
                if arg.is_null() {
                    bail!("null CLI argument");
                }
                Ok(CStr::from_ptr(*arg).to_string_lossy().into_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        run(args)
    });
    match result {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            eprintln!("meow: {error:#}");
            1
        }
        Err(_) => {
            eprintln!("meow: native operation panicked");
            70
        }
    }
}
