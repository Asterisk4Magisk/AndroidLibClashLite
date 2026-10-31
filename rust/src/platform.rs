// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{Context, Result};
use jni::{
    objects::{GlobalRef, JObject, JValue},
    JNIEnv, JavaVM,
};
use parking_lot::RwLock;
use std::{net::SocketAddr, sync::Arc};

struct Callbacks {
    vm: JavaVM,
    object: GlobalRef,
}
static CALLBACKS: RwLock<Option<Arc<Callbacks>>> = RwLock::new(None);

pub fn install(env: &mut JNIEnv, object: &JObject) -> Result<()> {
    if object.is_null() {
        anyhow::bail!("Platform callbacks are required for JNI embedding");
    }
    meow_common::process_lookup::enable_inbound_process_info();
    let callbacks = Arc::new(Callbacks {
        vm: env.get_java_vm()?,
        object: env.new_global_ref(object)?,
    });
    #[cfg(target_os = "android")]
    meow_common::set_socket_protector(callbacks.clone());
    *CALLBACKS.write() = Some(callbacks);
    Ok(())
}

pub fn clear() {
    #[cfg(target_os = "android")]
    meow_common::clear_socket_protector();
    *CALLBACKS.write() = None;
}

pub fn is_installed() -> bool {
    CALLBACKS.read().is_some()
}

#[cfg(target_os = "android")]
impl meow_common::SocketProtector for Callbacks {
    fn protect(&self, fd: std::os::fd::RawFd) -> std::io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(std::io::Error::other)?;
        let result = env
            .call_method(&self.object, "protectSocket", "(I)Z", &[JValue::Int(fd)])
            .and_then(|v| v.z());
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(std::io::Error::other("protectSocket returned false")),
            Err(_) => {
                let _ = env.exception_clear();
                Err(std::io::Error::other("protectSocket callback failed"))
            }
        }
    }
}

pub struct Owner {
    pub uid: u32,
    pub package: Option<Arc<str>>,
}
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

pub async fn lookup(protocol: i32, source: SocketAddr, destination: SocketAddr) -> Option<Owner> {
    let callbacks = CALLBACKS.read().clone()?;
    tokio::task::spawn_blocking(move || callbacks.owner(protocol, source, destination).ok())
        .await
        .ok()
        .flatten()
}

impl Callbacks {
    fn owner(&self, protocol: i32, source: SocketAddr, destination: SocketAddr) -> Result<Owner> {
        let mut env = self.vm.attach_current_thread()?;
        let result = env.with_local_frame(8, |env| -> Result<Owner> {
            let source = JObject::from(env.new_string(source.to_string())?);
            let destination = JObject::from(env.new_string(destination.to_string())?);
            let uid = env
                .call_method(
                    &self.object,
                    "querySocketUid",
                    "(ILjava/lang/String;Ljava/lang/String;)I",
                    &[
                        JValue::Int(protocol),
                        JValue::Object(&source),
                        JValue::Object(&destination),
                    ],
                )?
                .i()?;
            let numeric_uid = u32::try_from(uid).context("connection owner unknown")?;
            let package = env
                .call_method(
                    &self.object,
                    "packageForUid",
                    "(I)Ljava/lang/String;",
                    &[JValue::Int(uid)],
                )?
                .l()?;
            let package = if package.is_null() {
                None
            } else {
                let value: String = env.get_string(&package.into())?.into();
                if value.is_empty() {
                    None
                } else {
                    Some(Arc::from(value))
                }
            };
            Ok(Owner {
                uid: numeric_uid,
                package,
            })
        });
        if result.is_err() {
            let _ = env.exception_clear();
        }
        result
    }
}
