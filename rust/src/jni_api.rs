// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::Result;
use jni::{
    objects::{JByteArray, JClass, JObject, JString},
    sys::{jboolean, jint, jstring},
    JNIEnv,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn boundary<T: Default>(env: &mut JNIEnv, call: impl FnOnce(&mut JNIEnv) -> Result<T>) -> T {
    let _operation = crate::engine::OPERATION.lock();
    checked(env, call)
}
fn checked<T: Default>(env: &mut JNIEnv, call: impl FnOnce(&mut JNIEnv) -> Result<T>) -> T {
    match catch_unwind(AssertUnwindSafe(|| call(env))) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            let _ = env.exception_clear();
            let _ = env.throw_new("java/lang/IllegalStateException", format!("{error:#}"));
            T::default()
        }
        Err(_) => {
            let _ = env.exception_clear();
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "libclash-rs native operation panicked",
            );
            T::default()
        }
    }
}

fn string(env: &mut JNIEnv, value: &JString) -> Result<String> {
    Ok(env.get_string(value)?.into())
}
fn output(env: &mut JNIEnv, value: String) -> Result<jstring> {
    Ok(env.new_string(value)?.into_raw())
}

#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_notifyDnsChanged(
    mut env: JNIEnv,
    _: JClass,
    servers: JString,
) {
    boundary(&mut env, |env| {
        crate::systemdns::notify(&string(env, &servers)?)
    });
}

#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_coreVersion(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    boundary(&mut env, |env| output(env, crate::CORE_VERSION.into()))
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_capabilities(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    boundary(&mut env, |env| output(env, crate::engine::capabilities()))
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_startFromBytes(
    mut env: JNIEnv,
    _: JClass,
    home: JString,
    base: JString,
    content: JByteArray,
    platform: JObject,
) {
    boundary(&mut env, |env| {
        anyhow::ensure!(!crate::engine::is_running(), "meow is already running");
        let home = string(env, &home)?;
        let base = string(env, &base)?;
        let bytes = env.convert_byte_array(&content)?;
        crate::platform::install(env, &platform)?;
        let result = crate::engine::start(&home, &base, &bytes, None);
        if result.is_err() {
            crate::engine::stop();
        }
        result
    });
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_stop(mut env: JNIEnv, _: JClass) {
    boundary(&mut env, |_| {
        crate::engine::stop();
        Ok(())
    });
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_loadFromBytes(
    mut env: JNIEnv,
    _: JClass,
    home: JString,
    base: JString,
    bytes: JByteArray,
    platform: JObject,
) {
    boundary(&mut env, |env| {
        let home = string(env, &home)?;
        let base = string(env, &base)?;
        let bytes = env.convert_byte_array(&bytes)?;
        crate::engine::reload(&home, &base, &bytes, || {
            crate::platform::install(env, &platform)
        })
    });
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_isRunning(
    mut env: JNIEnv,
    _: JClass,
) -> jboolean {
    boundary(&mut env, |_| Ok(u8::from(crate::engine::is_running())))
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_stopTun(mut env: JNIEnv, _: JClass) {
    boundary(&mut env, |_| {
        #[cfg(unix)]
        crate::tun2socks::stop();
        Ok(())
    });
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_request(
    mut env: JNIEnv,
    _: JClass,
    method: JString,
    path: JString,
    body: JString,
) -> jstring {
    boundary(&mut env, |env| {
        let method = string(env, &method)?;
        let path = string(env, &path)?;
        let body = string(env, &body)?;
        output(env, crate::engine::request(&method, &path, &body)?)
    })
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_traffic(mut env: JNIEnv, _: JClass) -> jstring {
    boundary(&mut env, |env| output(env, crate::engine::traffic()?))
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_readLogs(mut env: JNIEnv, _: JClass) -> jstring {
    boundary(&mut env, |env| output(env, crate::logging::read()))
}
#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_validate(
    mut env: JNIEnv,
    _: JClass,
    home: JString,
    base: JString,
    content: JByteArray,
) {
    checked(&mut env, |env| {
        let home = string(env, &home)?;
        let base = string(env, &base)?;
        let bytes = env.convert_byte_array(&content)?;
        let bytes = serde_yaml::to_string(&crate::profile::decode(&bytes)?)?;
        std::fs::create_dir_all(&base)?;
        let mut file = tempfile::NamedTempFile::new_in(&base)?;
        std::io::Write::write_all(&mut file, bytes.as_bytes())?;
        let output = std::process::Command::new(crate::compat::launcher()?)
            .args(["-t", "-d", &home, "-b", &base, "-f"])
            .arg(file.path())
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    });
}

#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_command(
    mut env: JNIEnv,
    _: JClass,
    operation: JString,
    args: JString,
) -> jstring {
    checked(&mut env, |env| {
        let operation = string(env, &operation)?;
        let args = string(env, &args)?;
        output(env, crate::compat::command(&operation, &args)?)
    })
}

#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_setPlatform(
    mut env: JNIEnv,
    _: JClass,
    platform: JObject,
) {
    boundary(&mut env, |env| {
        crate::platform::install(env, &platform)?;
        if let Some(tunnel) = crate::engine::tunnel() {
            tunnel.flush_for_outbound_interface_change(meow_tunnel::TrackedTcp::Cancel, []);
        }
        Ok(())
    });
}

#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_startTunWithDns(
    mut env: JNIEnv,
    _: JClass,
    fd: jint,
    dns: JString,
) {
    boundary(&mut env, |env| {
        anyhow::ensure!(
            crate::engine::is_running() && crate::platform::is_installed(),
            "running core and VPN callbacks required"
        );
        let dns = string(env, &dns)?;
        #[cfg(unix)]
        return crate::tun2socks::start(fd, &dns).map_err(anyhow::Error::msg);
        #[cfg(not(unix))]
        anyhow::bail!("TUN fd embedding is Android/Unix only: {fd}, {dns}")
    });
}

#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_queryAutoSwitch(
    mut env: JNIEnv,
    _: JClass,
) -> jstring {
    boundary(&mut env, |env| {
        output(env, crate::engine::query_auto_switch()?)
    })
}

#[no_mangle]
pub extern "system" fn Java_libclash_NativeBridge_patchAutoSwitch(
    mut env: JNIEnv,
    _: JClass,
    settings: JString,
) {
    boundary(&mut env, |env| {
        let settings = string(env, &settings)?;
        crate::engine::patch_auto_switch(&settings)
    });
}
