// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{Context, Result};
use jni::{
    objects::{GlobalRef, JObject, JValue},
    JNIEnv, JavaVM,
};
use parking_lot::RwLock;
use std::{net::SocketAddr, sync::Arc};

#[cfg(unix)]
mod packages;
#[cfg(unix)]
mod socket_owner;

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

#[cfg(unix)]
pub async fn lookup_bridge(
    protocol: i32,
    source: SocketAddr,
    destination: SocketAddr,
    uid: Option<u32>,
) -> Option<Owner> {
    if is_installed() {
        return lookup(protocol, source, destination).await;
    }
    if let Some(uid) = uid {
        let package = if unsafe { libc::geteuid() } == 0 {
            tokio::task::spawn_blocking(move || packages::lookup(uid))
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        return Some(Owner { uid, package });
    }
    if unsafe { libc::geteuid() } != 0 || !is_local_source(source.ip()) {
        return None;
    }
    tokio::task::spawn_blocking(move || {
        let uid = socket_owner::lookup(protocol == IPPROTO_UDP, source, destination)?;
        Some(Owner {
            uid,
            package: packages::lookup(uid),
        })
    })
    .await
    .ok()
    .flatten()
}

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

// A forwarded hotspot client cannot own a wildcard UDP socket on this device.
#[cfg(unix)]
fn is_local_source(source: std::net::IpAddr) -> bool {
    let source = source.to_canonical();
    if source.is_loopback() {
        return true;
    }
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return false;
    }
    let mut current = head;
    let mut found = false;
    while !current.is_null() {
        let interface = unsafe { &*current };
        if !interface.ifa_addr.is_null() {
            let address = unsafe { &*interface.ifa_addr };
            let ip = match address.sa_family as i32 {
                libc::AF_INET => {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in) };
                    Some(std::net::IpAddr::from(
                        address.sin_addr.s_addr.to_ne_bytes(),
                    ))
                }
                libc::AF_INET6 => {
                    let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in6) };
                    Some(std::net::IpAddr::from(address.sin6_addr.s6_addr))
                }
                _ => None,
            };
            if ip.is_some_and(|ip| ip.to_canonical() == source) {
                found = true;
                break;
            }
        }
        current = interface.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    found
}
