// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct DnsPeer {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl DnsPeer {
    fn new(bind: &str, last_octet: u8) -> Self {
        let socket = UdpSocket::bind(bind).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let (done, queries) = (stop.clone(), count.clone());
        let worker = std::thread::spawn(move || {
            let mut buffer = [0; 2048];
            while !done.load(Ordering::Relaxed) {
                if let Ok((length, from)) = socket.recv_from(&mut buffer) {
                    queries.fetch_add(1, Ordering::Relaxed);
                    let mut end = 12;
                    while buffer[end] != 0 {
                        end += 1 + buffer[end] as usize;
                    }
                    end += 5;
                    assert!(end <= length);
                    let is_a = buffer[end - 4..end - 2] == [0, 1];
                    let mut reply = buffer[..end].to_vec();
                    reply[2..4].copy_from_slice(&[0x81, 0x80]);
                    reply[6..12].copy_from_slice(&[0, u8::from(is_a), 0, 0, 0, 0]);
                    if is_a {
                        reply.extend_from_slice(&[
                            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, last_octet,
                        ]);
                    }
                    socket.send_to(&reply, from).unwrap();
                }
            }
        });
        Self {
            address,
            stop,
            count,
            worker: Some(worker),
        }
    }
}
impl Drop for DnsPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn dns_query() -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(b"\x06lookup\x04test\0\0\x01\0\x01");
    bytes
}

#[cfg(unix)]
fn wire_packet(v6: bool, protocol: u8, mut transport: Vec<u8>) -> Vec<u8> {
    let (source, destination) = if v6 {
        (
            "fd00::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            "fd00::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        )
    } else {
        (vec![172, 19, 0, 1], vec![172, 19, 0, 2])
    };
    let length = transport.len() as u16;
    let mut pseudo = source.clone();
    pseudo.extend_from_slice(&destination);
    if v6 {
        pseudo.extend_from_slice(&u32::from(length).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, protocol]);
    } else {
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(&length.to_be_bytes());
    }
    pseudo.extend_from_slice(&transport);
    let checksum = |bytes: &[u8]| {
        let mut sum: u32 = bytes
            .chunks(2)
            .map(|b| (u32::from(b[0]) << 8) | u32::from(*b.get(1).unwrap_or(&0)))
            .sum();
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    };
    let offset = if protocol == 17 { 6 } else { 16 };
    let sum = checksum(&pseudo);
    transport[offset..offset + 2].copy_from_slice(&sum.to_be_bytes());
    let mut ip = if v6 {
        let mut b = vec![0x60, 0, 0, 0];
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(&[protocol, 64]);
        b
    } else {
        let mut b = vec![0x45, 0];
        b.extend_from_slice(&(length + 20).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        b
    };
    ip.extend_from_slice(&source);
    ip.extend_from_slice(&destination);
    if !v6 {
        let sum = checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    ip.extend_from_slice(&transport);
    ip
}

#[cfg(unix)]
#[test]
fn tun_dns_tcp_udp_v4_v6_and_disabled_hijack() {
    struct Stop;
    impl Drop for Stop {
        fn drop(&mut self) {
            crate::engine::stop();
        }
    }
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    let _operation = crate::engine::OPERATION.lock();
    let _stop = Stop;
    let peer = DnsPeer::new("127.0.0.1:0", 45);
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().to_str().unwrap();
    let config=format!("log-level: silent\ndns: {{enable: true, nameserver: ['udp://{}']}}\nrules: ['MATCH,REJECT']\n",peer.address);
    crate::engine::start(home, home, config.as_bytes(), None).unwrap();
    for hijack in ["0.0.0.0", ""] {
        let (tun, client) = UnixDatagram::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        crate::tun2socks::start(tun.as_raw_fd(), hijack).unwrap();
        for v6 in [false, true] {
            let query = dns_query();
            let mut udp = vec![0x9c, 0x40, 0, 53];
            udp.extend_from_slice(&((query.len() + 8) as u16).to_be_bytes());
            udp.extend_from_slice(&[0, 0]);
            udp.extend_from_slice(&query);
            client.send(&wire_packet(v6, 17, udp)).unwrap();
            let mut buffer = [0; 4096];
            if hijack.is_empty() {
                while let Ok(size) = client.recv(&mut buffer) {
                    let ip = if buffer[0] >> 4 == 6 {
                        40
                    } else {
                        usize::from(buffer[0] & 15) * 4
                    };
                    let protocol = buffer[if ip == 40 { 6 } else { 9 }];
                    assert!(
                        !(protocol == 17 && size >= ip + 8 && buffer[ip..ip + 2] == [0, 53]),
                        "DNS bypassed disabled hijack: {:x?}",
                        &buffer[..size]
                    );
                }
                continue;
            }
            let size = client.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[size - 4..size], &[192, 0, 2, 45]);
            let tcp = |sequence: u32, ack: u32, flags: u8, payload: &[u8]| {
                let mut bytes = vec![0x9c, 0x41, 0, 53];
                bytes.extend_from_slice(&sequence.to_be_bytes());
                bytes.extend_from_slice(&ack.to_be_bytes());
                bytes.extend_from_slice(&[0x50, flags, 0x7f, 0xff, 0, 0, 0, 0]);
                bytes.extend_from_slice(payload);
                wire_packet(v6, 6, bytes)
            };
            client.send(&tcp(10, 0, 2, &[])).unwrap();
            let size = client.recv(&mut buffer).unwrap();
            let ip = if v6 { 40 } else { 20 };
            assert!(size >= ip + 20);
            assert_eq!(buffer[ip + 13] & 0x12, 0x12, "SYN ACK");
            let remote_seq = u32::from_be_bytes(buffer[ip + 4..ip + 8].try_into().unwrap()) + 1;
            client.send(&tcp(11, remote_seq, 0x10, &[])).unwrap();
            let mut request = (query.len() as u16).to_be_bytes().to_vec();
            request.extend_from_slice(&query);
            client.send(&tcp(11, remote_seq, 0x18, &request)).unwrap();
            let mut response = Vec::new();
            loop {
                let size = client.recv(&mut buffer).unwrap();
                let header = ip + usize::from(buffer[ip + 12] >> 4) * 4;
                if size > header {
                    response.extend_from_slice(&buffer[header..size]);
                }
                if response.len() >= 2
                    && response.len()
                        >= usize::from(u16::from_be_bytes([response[0], response[1]])) + 2
                {
                    break;
                }
            }
            assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 45]);
            client
                .send(&tcp(11 + request.len() as u32, remote_seq, 0x14, &[]))
                .unwrap();
        }
        crate::tun2socks::stop();
    }
    crate::engine::stop();
}

#[test]
fn dns_outbound_tcp_udp_and_live_resolver_reload() {
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _operation = crate::engine::OPERATION.lock();
    let first = DnsPeer::new("127.0.0.1:0", 31);
    let second = DnsPeer::new("[::1]:0", 32);
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().to_str().unwrap();
    let config = |address| {
        format!("log-level: silent\ndns: {{enable: true, nameserver: ['udp://{address}']}}\nproxies: [{{name: dns-out, type: dns}}]\nrules: ['DST-PORT,53,dns-out', 'MATCH,REJECT']\n")
    };
    crate::engine::start(home, home, config(first.address).as_bytes(), None).unwrap();
    let proxy = crate::engine::tunnel()
        .unwrap()
        .inner()
        .route()
        .proxies
        .get("dns-out")
        .unwrap()
        .clone();
    for octet in [31, 32] {
        if octet == 32 {
            let payload = base64::engine::general_purpose::STANDARD.encode(config(second.address));
            let response = crate::engine::request(
                "PUT",
                "/configs",
                &serde_json::json!({"payload":payload}).to_string(),
            )
            .unwrap();
            assert!(response.contains("\"status\":204"), "{response}");
        }
        // Deliberately use the OLD adapter after hot reload: it must follow the live slot.
        crate::get_runtime().block_on(async {
            let metadata = meow_common::Metadata::default();
            let mut tcp = proxy.dial_tcp(&metadata).await.unwrap();
            let query = dns_query();
            for _ in 0..2 {
                tcp.write_u16(query.len() as u16).await.unwrap();
                tcp.write_all(&query).await.unwrap();
                let length = tcp.read_u16().await.unwrap();
                let mut response = vec![0; length as usize];
                tcp.read_exact(&mut response).await.unwrap();
                assert_eq!(&response[response.len() - 4..], &[192, 0, 2, octet]);
            }
            let udp = proxy.dial_udp(&metadata).await.unwrap();
            for destination in ["8.8.8.8:53", "[2001:4860:4860::8888]:53"] {
                let address = destination.parse().unwrap();
                udp.write_packet(&query, &address).await.unwrap();
                let mut response = [0; 2048];
                let (length, from) = udp.read_packet(&mut response).await.unwrap();
                assert_eq!(from, address);
                assert_eq!(&response[length - 4..length], &[192, 0, 2, octet]);
            }
            udp.close().unwrap();
            assert!(udp.read_packet(&mut [0; 2048]).await.is_err());
        });
    }
    crate::engine::stop();
}

#[cfg(target_os = "android")]
#[test]
fn android_root_uid_lookup_and_tproxy_default() {
    use meow_common::process_lookup;
    let _operation = crate::engine::OPERATION.lock();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let owner =
        process_lookup::find_process(meow_common::Network::Tcp, client.local_addr().unwrap())
            .unwrap();
    assert_eq!(owner.uid, Some(unsafe { libc::geteuid() }));
    assert!(process_lookup::uid_info_available());
    let (raw, _) =
        crate::engine::parse(b"listeners: [{name: tp, type: tproxy, port: 18081, udp: true}]")
            .unwrap();
    let named = meow_config::resolve_named_listeners(&raw).unwrap();
    assert!(matches!(
        named[0].spec,
        meow_config::ListenerSpec::TProxy {
            firewall: false,
            ..
        }
    ));
}

#[test]
fn system_dns_switches_family_clears_cache_and_survives_reload() {
    use base64::Engine;
    let _operation = crate::engine::OPERATION.lock();
    let first = DnsPeer::new("127.0.0.1:0", 10);
    let second = DnsPeer::new("[::1]:0", 20);
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().to_str().unwrap();
    let config = b"log-level: silent\nlogbook: {enable: false}\ndns:\n  enable: true\n  nameserver: [system]\n  default-nameserver: [system]\n  proxy-server-nameserver: [system]\n  nameserver-policy: {'+.policy.test': system}\nrules: ['MATCH,DIRECT']\n";
    meow_dns::system_dns::update(vec![first.address]);
    crate::engine::start(home, home, config, None).unwrap();
    let lookup = |host| {
        crate::get_runtime().block_on(async {
            crate::engine::tunnel()
                .unwrap()
                .resolver()
                .lookup_ipv4(host)
                .await
        })
    };
    assert_eq!(lookup("cache.test"), Some("192.0.2.10".parse().unwrap()));
    let initial = first.count.load(Ordering::Relaxed);
    assert_eq!(lookup("cache.test"), Some("192.0.2.10".parse().unwrap()));
    assert_eq!(first.count.load(Ordering::Relaxed), initial);
    meow_dns::system_dns::update(vec![second.address]);
    assert_eq!(lookup("cache.test"), Some("192.0.2.20".parse().unwrap()));
    assert_eq!(
        lookup("node.policy.test"),
        Some("192.0.2.20".parse().unwrap())
    );
    let payload = base64::engine::general_purpose::STANDARD.encode(config);
    let result = crate::engine::request(
        "PUT",
        "/configs",
        &serde_json::json!({"payload":payload}).to_string(),
    )
    .unwrap();
    assert!(result.contains("\"status\":204"), "{result}");
    assert_eq!(
        lookup("after-reload.test"),
        Some("192.0.2.20".parse().unwrap())
    );
    meow_dns::system_dns::update(vec![]);
    assert_eq!(lookup("cache.test"), None);
    assert_eq!(first.count.load(Ordering::Relaxed), initial);
    crate::engine::stop();
}

#[cfg(target_os = "android")]
#[test]
#[ignore = "Run rust/tools/test_tproxy.sh in an isolated root network namespace"]
fn android_tproxy_dual_stack_roundtrip_and_restart() {
    let _operation = crate::engine::OPERATION.lock();
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().to_str().unwrap();
    let config = b"tproxy-port: 18081\nmode: rule\nlog-level: silent\nlogbook: {enable: false}\nproxies: [{name: echo, type: socks5, server: 127.0.0.1, port: 18082, udp: true}]\nrules: ['MATCH,echo']\n";
    for _ in 0..2 {
        let server = socks_echo();
        crate::engine::start(home, home, config, None).unwrap();
        for remote in ["198.18.0.1:18080", "[2001:db8:2::1]:18080"] {
            let target: std::net::SocketAddr = remote.parse().unwrap();
            let runtime = crate::get_runtime();
            let _guard = runtime.enter();
            let client = if target.is_ipv4() {
                tokio::net::TcpSocket::new_v4().unwrap()
            } else {
                tokio::net::TcpSocket::new_v6().unwrap()
            };
            let stream = runtime
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(5), client.connect(target))
                        .await
                        .unwrap()
                        .unwrap()
                })
                .into_std()
                .unwrap();
            stream.set_nonblocking(false).unwrap();
            let mut client: TcpStream = stream;
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client.write_all(b"meow").unwrap();
            let mut reply = [0; 4];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"meow");
            drop(client);
            let client = UdpSocket::bind(if target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client.connect(target).unwrap();
            client.send(b"meow").unwrap();
            let mut reply = [0; 4];
            assert_eq!(client.recv(&mut reply).unwrap(), 4);
            assert_eq!(&reply, b"meow");
        }
        crate::engine::stop();
        server.join().unwrap();
        for bind in ["0.0.0.0:18081", "[::]:18081"] {
            drop(TcpListener::bind(bind).unwrap());
            drop(UdpSocket::bind(bind).unwrap());
        }
    }
}

#[cfg(target_os = "android")]
fn socks_echo() -> std::thread::JoinHandle<()> {
    let listener = TcpListener::bind("127.0.0.1:18082").unwrap();
    std::thread::spawn(move || {
        let mut associations = Vec::new();
        for _ in 0..4 {
            let (mut control, _) = listener.accept().unwrap();
            control
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut hello = [0; 2];
            control.read_exact(&mut hello).unwrap();
            assert_eq!(hello[0], 5);
            let mut methods = vec![0; hello[1] as usize];
            control.read_exact(&mut methods).unwrap();
            control.write_all(&[5, 0]).unwrap();
            let mut header = [0; 4];
            control.read_exact(&mut header).unwrap();
            let length = match header[3] {
                1 => 4,
                4 => 16,
                other => panic!("unexpected address type {other}"),
            };
            let mut destination = vec![0; length + 2];
            control.read_exact(&mut destination).unwrap();
            if header[1] == 1 {
                assert_eq!(&destination[length..], &18080u16.to_be_bytes());
                control
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .unwrap();
                let mut payload = [0; 4];
                control.read_exact(&mut payload).unwrap();
                control.write_all(&payload).unwrap();
            } else {
                assert_eq!(header[1], 3);
                let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
                udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                reply.extend_from_slice(&udp.local_addr().unwrap().port().to_be_bytes());
                control.write_all(&reply).unwrap();
                associations.push(std::thread::spawn(move || {
                    let mut packet = [0; 2048];
                    let (size, client) = udp.recv_from(&mut packet).unwrap();
                    assert_eq!(&packet[size - 4..size], b"meow");
                    assert_eq!(&packet[size - 6..size - 4], &18080u16.to_be_bytes());
                    udp.send_to(&packet[..size], client).unwrap();
                    // Keep the UDP association alive until the core closes it.
                    let mut byte = [0];
                    assert_eq!(control.read(&mut byte).unwrap(), 0);
                }));
            }
        }
        for worker in associations {
            worker.join().unwrap();
        }
    })
}
