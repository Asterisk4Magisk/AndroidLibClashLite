// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//! Authenticated PROXY v2 input for the application's local traffic bridges.
use anyhow::{bail, Result};
use bytes::{Bytes, BytesMut};
use meow_common::{ConnType, Metadata, Network};
use meow_tunnel::Tunnel;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

mod codec;

use codec::{encode_into, parse, Header};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, UdpSocket},
    sync::mpsc,
};

pub fn tokens(bytes: &[u8]) -> Result<HashMap<String, String>> {
    let (value, _) = crate::profile::decode_core(bytes)?;
    let mut result = HashMap::new();
    if let Some(entries) = value.get("listeners").and_then(|v| v.as_sequence()) {
        for entry in entries {
            if entry.get("name").and_then(|v| v.as_str()) != Some("asterisk-bridge") {
                continue;
            }
            let token = entry
                .get("users")
                .and_then(|v| v.as_sequence())
                .and_then(|users| {
                    users.iter().find(|u| {
                        u.get("username").and_then(|v| v.as_str()) == Some("__asterisk_flow_v1")
                    })
                })
                .and_then(|u| u.get("password"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("bridge credential missing"))?;
            if token.len() != 32 {
                bail!("invalid bridge credential")
            }
            result.insert("asterisk-bridge".into(), token.into());
        }
    }
    Ok(result)
}

pub async fn start(tunnel: Tunnel, address: SocketAddr, token: String) -> Result<()> {
    let tcp = TcpListener::bind(address).await?;
    let udp = Arc::new(UdpSocket::bind(address).await?);
    let tcp_tunnel = tunnel.clone();
    let tcp_token = token.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            let tunnel = tcp_tunnel.clone();
            let token = tcp_token.clone();
            tokio::spawn(async move {
                let read = async {
                    let mut b = [0u8; 92];
                    stream.read_exact(&mut b[..16]).await?;
                    let n = u16::from_be_bytes([b[14], b[15]]) as usize;
                    if n != 52 && n != 76 {
                        bail!("invalid flow length")
                    }
                    stream.read_exact(&mut b[16..16 + n]).await?;
                    parse(&b[..16 + n], &token, false)
                };
                let Ok(Ok((h, _))) = tokio::time::timeout(Duration::from_secs(10), read).await
                else {
                    return;
                };
                let mut metadata = Metadata {
                    process_info_complete: true,
                    network: Network::Tcp,
                    conn_type: ConnType::Tun,
                    in_name: "asterisk-bridge".into(),
                    in_port: address.port(),
                    src_ip: Some(h.source.ip()),
                    src_port: h.source.port(),
                    dst_ip: Some(h.destination.ip()),
                    dst_port: h.destination.port(),
                    ..Default::default()
                };
                if crate::platform::needs_owner(tunnel.inner()) {
                    crate::tun2socks::apply_owner(
                        &mut metadata,
                        crate::platform::lookup_bridge(
                            crate::platform::IPPROTO_TCP,
                            h.source,
                            h.destination,
                            h.uid,
                        )
                        .await,
                    );
                }
                meow_tunnel::tcp::handle_tcp(tunnel.inner(), Box::new(stream), metadata).await;
            });
        }
    });
    let flows: FlowTable = Default::default();
    tokio::spawn(async move {
        let mut packet = vec![0; 65535];
        let mut payloads = BytesMut::with_capacity(65535);
        while let Ok((size, peer)) = udp.recv_from(&mut packet).await {
            let Ok((header, n)) = parse(&packet[..size], &token, true) else {
                continue;
            };
            // Share receive storage across queued datagrams; copy outside the table lock.
            payloads.extend_from_slice(&packet[n..size]);
            let payload = payloads.split().freeze();
            let key = (header, peer);
            let mut table = flows.lock();
            let sender = table.entry(key).or_insert_with(|| {
                let (sender, packets) = mpsc::channel(64);
                tokio::spawn(serve_udp(
                    key,
                    address,
                    packets,
                    sender.clone(),
                    flows.clone(),
                    udp.clone(),
                    token.clone(),
                ));
                sender
            });
            let _ = sender.try_send(payload);
        }
    });
    Ok(())
}

type FlowKey = (Header, SocketAddr);
type FlowTable = Arc<parking_lot::Mutex<HashMap<FlowKey, mpsc::Sender<Bytes>>>>;

async fn serve_udp(
    key: FlowKey,
    address: SocketAddr,
    mut packets: mpsc::Receiver<Bytes>,
    sender: mpsc::Sender<Bytes>,
    flows: FlowTable,
    udp: Arc<UdpSocket>,
    token: String,
) {
    let (header, peer) = key;
    let (replies, mut received) = mpsc::channel::<crate::tun2socks::UdpMsg>(256);
    let readers: crate::tun2socks::ReplyReaders = Default::default();
    let idle = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(idle);
    // Reuse the reply envelope instead of allocating a header and growing it
    // for every datagram. The receive queue owns its single payload copy.
    let mut response = Vec::new();
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some(payload) = packet else {
                    break
                };
                crate::tun2socks::dispatch_udp(
                    &payload,
                    header.source,
                    header.destination,
                    &replies,
                    &readers,
                    header.uid,
                    Some(address),
                )
                .await;
            }
            reply = received.recv() => {
                let Some((payload, source, destination)) = reply else {
                    break
                };
                let reply = Header {
                    source,
                    destination,
                    udp: true,
                    uid: header.uid
                };
                if encode_into(reply, &token, &mut response).is_ok() {
                    response.extend_from_slice(&payload);
                    let _ = udp.send_to(&response, peer).await;
                }
            }
            _ = &mut idle => break,
        }
        idle.as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(60));
    }
    let mut table = flows.lock();
    if table
        .get(&key)
        .is_some_and(|current| current.same_channel(&sender))
    {
        table.remove(&key);
    }
}
