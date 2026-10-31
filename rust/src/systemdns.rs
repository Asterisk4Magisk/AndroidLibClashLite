// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

fn endpoint(value: &str) -> Result<SocketAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    // Android LinkProperties may return an IPv6 zone as an interface name.
    if let Some((host, port)) = value.strip_prefix('[').and_then(|v| v.split_once("]:")) {
        if let Some((ip, zone)) = host.rsplit_once('%') {
            let scope = match zone.parse::<u32>() {
                Ok(scope) => scope,
                Err(_) => {
                    #[cfg(unix)]
                    {
                        let name = std::ffi::CString::new(zone)?;
                        let scope = unsafe { libc::if_nametoindex(name.as_ptr()) };
                        anyhow::ensure!(scope != 0, "unknown DNS interface");
                        scope
                    }
                    #[cfg(not(unix))]
                    {
                        bail!("DNS interface scopes require Unix");
                    }
                }
            };
            return Ok(SocketAddr::V6(SocketAddrV6::new(
                ip.parse()?,
                port.parse()?,
                0,
                scope,
            )));
        }
    }
    bail!("DNS server must be an IP:port endpoint")
}

fn validate(values: &[String]) -> Result<Vec<SocketAddr>> {
    anyhow::ensure!(values.len() <= 32, "too many system DNS servers");
    let mut addresses = Vec::new();
    for value in values {
        let address = endpoint(value)?;
        let ip = address.ip();
        anyhow::ensure!(
            address.port() != 0
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            "invalid physical-network DNS server"
        );
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

pub fn notify(csv: &str) -> Result<()> {
    let values: Vec<String> = csv
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect();
    meow_dns::system_dns::update(validate(&values)?);
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    servers: Vec<String>,
}

fn snapshot(frame: &[u8]) -> Result<Vec<SocketAddr>> {
    let snapshot: Snapshot = serde_json::from_slice(frame)?;
    anyhow::ensure!(snapshot.version == 1, "unsupported DNS snapshot version");
    let addresses = validate(&snapshot.servers)?;
    anyhow::ensure!(
        addresses.iter().all(|a| a.port() == 53),
        "helper DNS port must be 53"
    );
    Ok(addresses)
}

#[cfg(target_os = "android")]
pub mod root {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        os::{
            fd::AsRawFd,
            unix::{
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
                net::UnixStream,
                process::CommandExt,
            },
        },
        path::Path,
        process::{Child, Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::JoinHandle,
        time::{Duration, Instant},
    };
    const DEX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/system-dns-helper.dex"));
    const MAX_FRAME: u64 = 8192;

    fn helper_file(home: &Path) -> Result<std::path::PathBuf> {
        std::fs::create_dir_all(home)?;
        let path = home.join("system-dns-helper.dex");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            let meta = file.metadata()?;
            anyhow::ensure!(meta.is_file(), "system DNS helper is not a regular file");
            let mut content = Vec::new();
            if meta.uid() == 0 && meta.len() == DEX.len() as u64 {
                file.read_to_end(&mut content)?;
                if content == DEX {
                    file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
                    return Ok(path);
                }
            }
        }
        let mut temporary = tempfile::NamedTempFile::new_in(home)?;
        temporary.write_all(DEX)?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o400))?;
        temporary.as_file().sync_all()?;
        temporary.persist(&path)?;
        Ok(path)
    }

    fn read(reader: &mut BufReader<UnixStream>) -> Result<Vec<SocketAddr>> {
        let mut frame = Vec::new();
        reader.take(MAX_FRAME + 1).read_until(b'\n', &mut frame)?;
        anyhow::ensure!(
            frame.len() as u64 <= MAX_FRAME && frame.last() == Some(&b'\n'),
            "system DNS channel closed or oversized frame"
        );
        snapshot(&frame)
    }

    fn reap(child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
        }
        let _ = child.wait();
    }

    pub struct Watcher {
        control: UnixStream,
        stopping: Arc<AtomicBool>,
        failed: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }
    impl Watcher {
        pub fn start(home: &Path) -> Result<Option<Self>> {
            if unsafe { libc::geteuid() } != 0 {
                return Ok(None);
            }
            let path = helper_file(home)?;
            let (parent, child_socket) = UnixStream::pair()?;
            let inherited = child_socket.as_raw_fd();
            let mut command = Command::new("/system/bin/app_process");
            command
                .arg(format!("-Djava.class.path={}", path.display()))
                .args([
                    "/",
                    "--nice-name=libmeow-system-dns",
                    "libclash.systemdns.SystemDnsHelper",
                    "3",
                ])
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(
                    child_socket.try_clone()?,
                )))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .process_group(0);
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(inherited, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn().context("start system DNS helper")?;
            drop(command);
            drop(child_socket);
            let control = parent.try_clone()?;
            parent.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut reader = BufReader::new(parent);
            let initial = match read(&mut reader) {
                Ok(value) => value,
                Err(e) => {
                    let _ = control.shutdown(std::net::Shutdown::Both);
                    reap(&mut child);
                    return Err(e.context("system DNS initial snapshot"));
                }
            };
            meow_dns::system_dns::update(initial.clone());
            reader.get_ref().set_read_timeout(None)?;
            let stopping = Arc::new(AtomicBool::new(false));
            let failed = Arc::new(AtomicBool::new(false));
            let (stop, fail) = (stopping.clone(), failed.clone());
            let worker = std::thread::spawn(move || {
                let mut previous = initial;
                loop {
                    match read(&mut reader) {
                        Ok(next) => {
                            if next != previous {
                                previous = next.clone();
                                meow_dns::system_dns::update(next);
                            }
                        }
                        Err(e) => {
                            if !stop.load(Ordering::Acquire) {
                                meow_dns::system_dns::update(Vec::new());
                                fail.store(true, Ordering::Release);
                                tracing::error!("system DNS channel failed: {e:#}");
                                unsafe {
                                    libc::kill(libc::getpid(), libc::SIGTERM);
                                }
                            }
                            break;
                        }
                    }
                }
                let _ = reader.get_ref().shutdown(std::net::Shutdown::Both);
                reap(&mut child);
            });
            Ok(Some(Self {
                control,
                stopping,
                failed,
                worker: Some(worker),
            }))
        }
        pub fn failed(&self) -> bool {
            self.failed.load(Ordering::Acquire)
        }
        pub fn stop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            let _ = self.control.shutdown(std::net::Shutdown::Both);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
    impl Drop for Watcher {
        fn drop(&mut self) {
            self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_protocol_and_scopes() {
        let servers = snapshot(
            br#"{"version":1,"servers":["192.0.2.1:53","192.0.2.1:53","[2001:db8::1]:53"]}"#,
        )
        .unwrap();
        assert_eq!(servers.len(), 2);
        assert!(snapshot(br#"{"version":1,"servers":[]}"#)
            .unwrap()
            .is_empty());
        for frame in [
            r#"{"version":2,"servers":[]}"#,
            r#"{"version":1,"servers":["127.0.0.1:53"]}"#,
            r#"{"version":1,"servers":["192.0.2.1:54"]}"#,
            r#"{"version":1,"servers":null}"#,
        ] {
            assert!(snapshot(frame.as_bytes()).is_err());
        }
        assert_eq!(
            endpoint("[fe80::1%3]:53").unwrap(),
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 3))
        );
    }
}
