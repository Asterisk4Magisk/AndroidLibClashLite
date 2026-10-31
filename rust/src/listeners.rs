// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{Context, Result};
use meow_config::{ListenerSpec, NamedListener};
use meow_listener::{MixedListener, SnifferRuntime};
use meow_tunnel::Tunnel;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub fn supported(spec: &ListenerSpec) -> Option<&'static str> {
    match spec {
        ListenerSpec::Mixed | ListenerSpec::Http | ListenerSpec::Socks5 => None,
        ListenerSpec::TProxy { firewall, .. } => {
            if !cfg!(target_os = "android") {
                Some("Android TPROXY")
            } else if crate::platform::is_installed() {
                Some("TPROXY is standalone ROOT-only; JNI uses startTun")
            } else if *firewall {
                Some("TPROXY requires firewall: false; the supervisor owns rules")
            } else {
                None
            }
        }
        ListenerSpec::Shadowsocks(_) => Some("Shadowsocks inbound"),
    }
}

pub async fn start(
    listener: &mut NamedListener,
    tunnel: &Tunnel,
    sniffer: &Arc<SnifferRuntime>,
    auth: &Arc<meow_common::AuthConfig>,
) -> Result<()> {
    let ip: IpAddr = match listener.listen.as_str() {
        "*" | "" => "0.0.0.0".parse().unwrap(),
        address => address.parse().context("listener address")?,
    };
    #[cfg(target_os = "android")]
    if let ListenerSpec::TProxy {
        sni,
        udp,
        udp_timeout,
        ..
    } = &listener.spec
    {
        // Separate v4/v6 sockets preserve the actual address family in UDP
        // ancillary data and in transparent reply sockets.
        let addresses = if ip == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) {
            vec![IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), ip]
        } else {
            vec![ip]
        };
        for ip in addresses {
            let socket = transparent_tcp(SocketAddr::new(ip, listener.port))?;
            let bound = socket.local_addr()?;
            listener.port = bound.port();
            let server = meow_listener::TProxyListener::new(
                tunnel.clone(),
                bound,
                *sni,
                None,
                listener.name.clone(),
            )
            .with_sniffer(sniffer.clone())
            .with_max_connections(listener.max_connections)
            .with_firewall(false)
            .with_udp(*udp, std::time::Duration::from_secs(*udp_timeout))
            .prepare(bound)
            .await
            .map_err(|e| anyhow::anyhow!("TPROXY prepare: {e}"))?;
            tokio::spawn(async move {
                if let Err(e) = server.run_on(socket).await {
                    tracing::error!("TPROXY listener stopped: {e}");
                }
            });
        }
        return Ok(());
    }
    let socket = tokio::net::TcpListener::bind(SocketAddr::new(ip, listener.port)).await?;
    let bound = socket.local_addr()?;
    listener.port = bound.port();
    let server = MixedListener::new(tunnel.clone(), bound, listener.name.clone())
        .with_sniffer(sniffer.clone())
        .with_auth(auth.clone())
        .with_max_connections(listener.max_connections);
    tokio::spawn(async move {
        if let Err(e) = server.run_on(socket).await {
            tracing::error!("proxy listener stopped: {e}");
        }
    });
    Ok(())
}

#[cfg(target_os = "android")]
fn transparent_tcp(addr: SocketAddr) -> Result<tokio::net::TcpListener> {
    use std::os::fd::AsRawFd;
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    let option = |level, name| -> std::io::Result<()> {
        let one: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of_val(&one) as _,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    if addr.is_ipv4() {
        option(libc::SOL_IP, 19)?;
    } else {
        option(libc::SOL_IPV6, libc::IPV6_V6ONLY)?;
        option(libc::SOL_IPV6, 75)?;
    }
    socket.bind(addr)?;
    Ok(socket.listen(1024)?)
}
