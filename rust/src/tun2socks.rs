// Adapted from meow-android, Copyright (c) 2026 Max Lv. MIT.
// See ../licenses/meow-android.txt. Local changes: owned FD, startup readiness,
// joined shutdown, live resolver slot, and the vendored single-owner meow-lwip.
//! tun2socks using lwip netstack: reads raw IP packets from the Android
//! TUN fd, routes TCP through a userspace TCP/IP stack (lwip), and
//! dispatches every accepted flow in-process via
//! `meow_tunnel::tcp::handle_tcp` — same pattern as meow-ios.
//!
//! DNS is handled in-process: configured TCP/UDP port 53 targets are intercepted and
//! every query goes to `DnsServer::handle_query` — A/AAAA for fake-IP
//! synthesis, other qtypes forwarded over the same upstreams. No loopback
//! DNS server socket exists.

use crate::engine;
use crate::logging;
use crate::platform as owner;
use futures::{SinkExt, StreamExt};
use meow_common::{ConnType, Metadata, Network, ProxyConn};
use meow_dns::DnsServer;
use meow_tunnel::udp::UdpSession;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::c_void;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::JoinHandle;
use tracing::warn;

type UdpMsg = (Vec<u8>, SocketAddr, SocketAddr);
type AnyIpPktFrame = Vec<u8>;
type FlowTasks = Arc<Mutex<Vec<JoinHandle<()>>>>;
type NatKey = (SocketAddr, SocketAddr);
/// The NAT session each running reply reader serves, by NAT key. Holding the
/// session (not just the key) lets a replacement session get its own reader
/// while the evicted one's reader is still winding down.
type ReplyReaders = Arc<Mutex<HashMap<NatKey, Arc<UdpSession>>>>;

static TUN2SOCKS_ACTIVE: AtomicBool = AtomicBool::new(false);
static TUN2SOCKS_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
// Wakes the TUN reader, which sleeps until the fd is readable and so would
// not notice the flag above on an idle VPN.
static TUN2SOCKS_STOP_NOTIFY: Notify = Notify::const_new();
// Handle of the running session's top-level task, so `stop()` can wait for
// it to finish touching the TUN fd before the owned duplicate is closed.
static TUN2SOCKS_TASK: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);
static TUN_FD: Mutex<Option<OwnedFd>> = Mutex::new(None);
static TUN_DNS: Mutex<String> = Mutex::new(String::new());

pub fn retain_for_reload() -> io::Result<Option<(OwnedFd, String)>> {
    let guard = TUN_FD.lock();
    let Some(fd) = guard.as_ref() else {
        return Ok(None);
    };
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some((
        unsafe { OwnedFd::from_raw_fd(duplicate) },
        TUN_DNS.lock().clone(),
    )))
}

const DNS_BURST_CAP: usize = 256;
const DNS_TASK_TIMEOUT: Duration = Duration::from_secs(5);
static DNS_CAP_LOG_LAST_MS: AtomicU64 = AtomicU64::new(0);

/// How often a UDP reply reader checks whether its session is still live.
/// A DIRECT session's read never ends on its own, so this bounds how long a
/// reader outlives a swept (or flushed) session.
const UDP_REPLY_CHECK_INTERVAL: Duration = Duration::from_secs(5);

fn warn_capped(slot: &AtomicU64, msg: &str) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = slot.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) >= 1000
        && slot
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        warn!("{}", msg);
    }
}

pub fn start(fd: i32, dns: &str) -> Result<(), String> {
    if TUN2SOCKS_ACTIVE.load(Ordering::SeqCst) {
        return Err("TUN is already running".into());
    }
    let dns_targets: Vec<std::net::IpAddr> = dns
        .split(',')
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            v.trim()
                .parse()
                .map_err(|_| format!("invalid DNS hijack address: {v}"))
        })
        .collect::<Result<_, _>>()?;
    // Reap any previous task before reusing lwIP's process-global C state.
    stop();
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    *TUN_FD.lock() = Some(owned);
    *TUN_DNS.lock() = dns.to_owned();
    TUN2SOCKS_STOP_REQUESTED.store(false, Ordering::SeqCst);
    TUN2SOCKS_ACTIVE.store(true, Ordering::SeqCst);
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let handle = crate::get_runtime().spawn(async move {
        let mut ready = Some(ready_tx);
        let result = run_tun2socks(duplicate, dns_targets, &mut ready).await;
        if let Some(tx) = ready {
            let _ = tx.send(Err(result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| "TUN exited before readiness".into())));
        }
        if let Err(error) = result {
            tracing::error!("TUN stopped: {error}");
        }
        TUN2SOCKS_ACTIVE.store(false, Ordering::SeqCst);
    });
    *TUN2SOCKS_TASK.lock() = Some(handle);
    match ready_rx.recv().map_err(|e| e.to_string()).and_then(|r| r) {
        Ok(()) => Ok(()),
        Err(error) => {
            stop();
            Err(error)
        }
    }
}

/// Join every reader/writer/flow and lwIP itself before closing the owned FD.
pub fn stop() {
    TUN2SOCKS_STOP_REQUESTED.store(true, Ordering::SeqCst);
    TUN2SOCKS_STOP_NOTIFY.notify_waiters();
    let handle = TUN2SOCKS_TASK.lock().take();
    if let Some(handle) = handle {
        crate::get_runtime().block_on(async {
            let _ = handle.await;
        });
    }
    TUN_FD.lock().take();
    TUN2SOCKS_ACTIVE.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Main tun2socks loop
// ---------------------------------------------------------------------------

async fn run_tun2socks(
    fd: RawFd,
    dns_targets: Vec<std::net::IpAddr>,
    ready: &mut Option<std::sync::mpsc::SyncSender<Result<(), String>>>,
) -> io::Result<()> {
    // start owns this duplicate; stop joins this task and its reader before
    // closing it. No other code closes or replaces this descriptor.
    let tun = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE)? };
    logging::bridge_log("tun2socks: building lwip netstack");

    let (mut stack, mut tcp_listener, udp_socket) =
        lwip::NetStack::with_buffer_size(1024, 256).map_err(|e| io::Error::other(e.to_string()))?;
    let mut core_done = stack.core_done();
    if let Some(tx) = ready.take() {
        let _ = tx.send(Ok(()));
    }

    let (udp_write, mut udp_read) = udp_socket.split();

    let (udp_reply_tx, mut udp_reply_rx) = mpsc::channel::<UdpMsg>(256);
    let reply_readers: ReplyReaders = Arc::new(Mutex::new(HashMap::new()));

    let (stack_ingress_tx, mut stack_ingress_rx) = mpsc::channel::<AnyIpPktFrame>(256);
    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let dns_sem = Arc::new(Semaphore::new(DNS_BURST_CAP));
    let flow_tasks: FlowTasks = Arc::new(Mutex::new(Vec::new()));

    let egress_tx_lwip = egress_tx.clone();
    let udp_reply_tx_lwip = udp_reply_tx.clone();
    let reply_readers_lwip = reply_readers.clone();
    let flow_tasks_lwip = flow_tasks.clone();
    // lwip's Rust listener/socket wrappers are backed by C callbacks that
    // mutate Rust queues and wakers through raw pointers. Keep all wrapper
    // polling and UDP writes on one task; detached tasks only own accepted
    // streams or proxy-side work.

    let lwip_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                pkt = stack_ingress_rx.recv() => {
                    match pkt {
                        Some(frame) => {
                            if let Err(e) = stack.send(frame).await {
                                logging::bridge_log(&format!("stack send error: {}", e));
                                break;
                            }
                        }
                        None => break,
                    }
                }
                pkt = stack.next() => {
                    match pkt {
                        Some(Ok(frame)) => { let _ = egress_tx_lwip.send(frame); }
                        Some(Err(e)) => {
                            logging::bridge_log(&format!("stack recv error: {}", e));
                            break;
                        }
                        None => break,
                    }
                }
                accepted = tcp_listener.next() => {
                    match accepted {
                        Some((stream, local_addr, remote_addr)) => {
                            let hijack = hijack_dns(&dns_targets, remote_addr.ip(), remote_addr.port());
                            let handle = tokio::spawn(async move {
                                if hijack {
                                    if let Some(tunnel) = engine::tunnel() {
                                        let _ = meow_config::dns_outbound::serve_tcp(stream, tunnel.resolver_slot()).await;
                                    }
                                } else {
                                    dispatch_tcp(stream, local_addr, remote_addr).await;
                                }
                            });
                            track_flow_task(&flow_tasks_lwip, handle);
                        }
                        None => break,
                    }
                }
                udp_pkt = udp_read.next() => {
                    match udp_pkt {
                        Some((payload, src, dst)) => {
                            let reply_tx = udp_reply_tx_lwip.clone();
                            let readers = reply_readers_lwip.clone();
                            let hijack = hijack_dns(&dns_targets, dst.ip(), dst.port());
                            let semaphore = dns_sem.clone();
                            let handle = tokio::spawn(async move {
                                if hijack {
                                    let Ok(_permit) = semaphore.try_acquire_owned() else {
                                        warn_capped(&DNS_CAP_LOG_LAST_MS, "tun2socks: DNS burst cap reached");
                                        return;
                                    };
                                    if let Some(tunnel) = engine::tunnel() {
                                        if let Ok(Ok(response)) = tokio::time::timeout(DNS_TASK_TIMEOUT,
                                            DnsServer::handle_query(&payload, &tunnel.resolver())).await {
                                            let _ = reply_tx.send((response, dst, src)).await;
                                        }
                                    }
                                } else {
                                    dispatch_udp(payload, src, dst, reply_tx, readers).await;
                                }
                            });
                            track_flow_task(&flow_tasks_lwip, handle);
                        }
                        None => break,
                    }
                }
                msg = udp_reply_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            if let Err(e) = udp_write.send_to(&msg.0, &msg.1, &msg.2) {
                                logging::bridge_log(&format!("tun2socks: UDP reply send error: {}", e));
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    let tun_writer_handle = tokio::spawn(async move {
        while let Some(pkt) = egress_rx.recv().await {
            let mut retries = 0u32;
            loop {
                let written = unsafe { libc::write(fd, pkt.as_ptr() as *const c_void, pkt.len()) };
                if written >= 0 {
                    break;
                }
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EAGAIN && retries < 3 {
                    retries += 1;
                    tokio::task::yield_now().await;
                    continue;
                }
                break;
            }
        }
    });

    // TUN reader: feeds raw IP packets into lwIP. It sleeps in
    // epoll until the fd is readable: an idle VPN must not keep waking the
    // CPU, as polling the fd every 200 µs did (~750 wakeups a second).
    let tun_reader_handle = tokio::spawn(async move {
        // Taken before the flag is read: notify_waiters() reaches a Notified
        // from the moment it exists, so a stop() in between is not lost.
        let stopped = TUN2SOCKS_STOP_NOTIFY.notified();
        tokio::pin!(stopped);
        if TUN2SOCKS_STOP_REQUESTED.load(Ordering::SeqCst) {
            return;
        }
        // Dropped when this task ends, which stop() waits for, so the fd
        // leaves epoll before the owned duplicate is closed.

        let mut read_buf = vec![0u8; 65535];

        loop {
            let mut ready = tokio::select! {
                _ = &mut stopped => break,
                ready = tun.readable() => match ready {
                    Ok(ready) => ready,
                    Err(e) => {
                        logging::bridge_log(&format!("tun2socks: TUN poll error: {}", e));
                        break;
                    }
                },
            };

            loop {
                let n =
                    unsafe { libc::read(fd, read_buf.as_mut_ptr() as *mut c_void, read_buf.len()) };
                if n <= 0 {
                    // EAGAIN: drained. Any other failure also waits for the
                    // next packet rather than retrying at once, which would
                    // spin.
                    ready.clear_ready();
                    break;
                }
                let n = n as usize;
                let ip_data = &read_buf[..n];

                let frame: AnyIpPktFrame = ip_data.to_vec();
                match stack_ingress_tx.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(frame)) => {
                        let _ = stack_ingress_tx.send(frame).await;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
        }
    });

    let _ = tun_reader_handle.await;

    abort_flow_tasks(&flow_tasks).await;
    drop(udp_reply_tx);
    let _ = lwip_handle.await;
    abort_flow_tasks(&flow_tasks).await;
    tun_writer_handle.abort();
    let _ = tun_writer_handle.await;

    let _ = core_done.wait_for(|done| *done).await;
    logging::bridge_log("tun2socks: exiting");
    Ok(())
}

fn track_flow_task(flow_tasks: &FlowTasks, handle: JoinHandle<()>) {
    let mut tasks = flow_tasks.lock();
    tasks.retain(|task| !task.is_finished());
    tasks.push(handle);
}

async fn abort_flow_tasks(flow_tasks: &FlowTasks) {
    let tasks = {
        let mut tasks = flow_tasks.lock();
        tasks.drain(..).collect::<Vec<_>>()
    };
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}

// ---------------------------------------------------------------------------
// TCP dispatch
// ---------------------------------------------------------------------------

async fn dispatch_tcp(stream: lwip::TcpStream, src_addr: SocketAddr, dst_addr: SocketAddr) {
    let tunnel = match engine::tunnel() {
        Some(t) => t,
        None => {
            warn!(
                "tun2socks: TCP {} -> {} dropped: engine not running",
                src_addr, dst_addr
            );
            return;
        }
    };

    tracing::debug!("tun2socks: dispatch {} -> {}", src_addr, dst_addr);

    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip: Some(dst_addr.ip()),
        dst_port: dst_addr.port(),
        ..Default::default()
    };
    apply_owner(
        &mut metadata,
        owner::lookup(owner::IPPROTO_TCP, src_addr, dst_addr).await,
    );

    let proxy_conn: Box<dyn ProxyConn> = Box::new(NetstackConn(stream));
    let inner = tunnel.inner().clone();
    meow_tunnel::tcp::handle_tcp(&inner, proxy_conn, metadata).await;
    tracing::debug!("tun2socks: flow done {} -> {}", src_addr, dst_addr);
}

/// Tag a flow with the app that opened it (see [`owner`]): the uid feeds
/// UID rules, the package name PROCESS-NAME rules and the connections list.
fn apply_owner(metadata: &mut Metadata, owner: Option<owner::Owner>) {
    let Some(owner) = owner else {
        return;
    };
    metadata.uid = Some(owner.uid);
    if let Some(package) = owner.package {
        metadata.process = (&*package).into();
    }
}

struct NetstackConn(lwip::TcpStream);

impl AsyncRead for NetstackConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NetstackConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl ProxyConn for NetstackConn {}

// ---------------------------------------------------------------------------
// UDP dispatch
// ---------------------------------------------------------------------------

async fn dispatch_udp(
    payload: Vec<u8>,
    src: SocketAddr,
    dst: SocketAddr,
    reply_tx: mpsc::Sender<UdpMsg>,
    reply_readers: ReplyReaders,
) {
    let Some(tunnel) = engine::tunnel() else {
        return;
    };
    let inner = tunnel.inner();

    let mut metadata = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Inner,
        src_ip: Some(src.ip()),
        src_port: src.port(),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        ..Default::default()
    };

    // Derive the NAT key exactly as `handle_udp` does, so the session it
    // creates is the one found below. An unmapped fake-IP is dropped (#618),
    // and a fake-IP rewritten back to its hostname still needs a real
    // address even when no rule asks for one.
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        return;
    }
    inner.pre_resolve(&mut metadata).await;
    if metadata.dst_ip.is_none() && !metadata.host.is_empty() {
        metadata.dst_ip = inner.resolver().resolve_ip_real(&metadata.host).await;
    }
    let Some(resolved_ip) = metadata.dst_ip else {
        return;
    };
    let key = (src, SocketAddr::new(resolved_ip, metadata.dst_port));

    // Rules run once per flow, on the packet that opens its session; the
    // packets after it skip the owner lookup's binder round trip.
    if !inner.nat_table.contains_key(&key) {
        apply_owner(
            &mut metadata,
            owner::lookup(owner::IPPROTO_UDP, src, dst).await,
        );
    }

    meow_tunnel::udp::handle_udp(inner, &payload, src, metadata).await;

    let Some(session) = inner.nat_table.get(&key).map(|r| Arc::clone(r.value())) else {
        return;
    };
    {
        let mut readers = reply_readers.lock();
        if readers
            .get(&key)
            .is_some_and(|served| Arc::ptr_eq(served, &session))
        {
            return;
        }
        readers.insert(key, Arc::clone(&session));
    }

    spawn_udp_reply_reader(
        key,
        session,
        src,
        dst,
        reply_tx,
        reply_readers,
        Arc::clone(inner),
    );
}

fn spawn_udp_reply_reader(
    key: NatKey,
    session: Arc<UdpSession>,
    app_src: SocketAddr,
    app_dst: SocketAddr,
    reply_tx: mpsc::Sender<UdpMsg>,
    reply_readers: ReplyReaders,
    tunnel_inner: Arc<meow_tunnel::tunnel::TunnelInner>,
) {
    tokio::spawn(async move {
        let relay = relay_udp_replies(&session, app_src, app_dst, &reply_tx);
        tokio::pin!(relay);
        // The read is polled in place rather than raced against a timeout:
        // cancelling a read mid-datagram would desync a stream-framed
        // (Trojan, VLESS, …) packet conn.
        let mut check = tokio::time::interval(UDP_REPLY_CHECK_INTERVAL);
        check.tick().await;
        loop {
            tokio::select! {
                () = &mut relay => break,
                _ = check.tick() => {
                    // Stop once the session left the NAT table (swept, failed
                    // a write, flushed) or went idle both ways.
                    let live = tunnel_inner
                        .nat_table
                        .get(&key)
                        .is_some_and(|s| Arc::ptr_eq(s.value(), &session));
                    if !live || session.idle_for() >= meow_tunnel::udp::DEFAULT_UDP_IDLE {
                        break;
                    }
                }
            }
        }
        // Compare-and-remove: a newer session under the same key keeps its
        // NAT entry and its own reader.
        tunnel_inner
            .nat_table
            .remove_if(&key, |_, s| Arc::ptr_eq(s, &session));
        let mut readers = reply_readers.lock();
        if readers
            .get(&key)
            .is_some_and(|served| Arc::ptr_eq(served, &session))
        {
            readers.remove(&key);
        }
    });
}

// Keep a single in-place read for stream-framed adapters. A full-size buffer
// avoids both silent truncation and buffer-too-small errors on legal replies.
async fn relay_udp_replies(
    session: &UdpSession,
    app_src: SocketAddr,
    app_dst: SocketAddr,
    reply_tx: &mpsc::Sender<UdpMsg>,
) {
    let mut buf = vec![0u8; 65535];
    while let Ok((n, _from)) = session.conn.read_packet(&mut buf).await {
        // Replies are activity too: refresh the NAT sweeper's idle clock.
        session.touch();
        let msg: UdpMsg = (buf[..n].to_vec(), app_dst, app_src);
        if reply_tx.try_send(msg).is_err() {
            break;
        }
    }
}

fn hijack_dns(targets: &[std::net::IpAddr], destination: std::net::IpAddr, port: u16) -> bool {
    port == 53
        && targets
            .iter()
            .any(|ip| ip.is_unspecified() || *ip == destination)
}
