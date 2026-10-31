// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use crate::engine;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "libclash-rs-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        engine::stop();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(port: u16) -> String {
    format!("mode: rule\nlog-level: silent\nlogbook: {{enable: false}}\nlisteners:\n  - name: local\n    type: mixed\n    listen: 127.0.0.1\n    port: {port}\nrules: ['MATCH,DIRECT']\n")
}

fn api(method: &str, path: &str, body: &str) -> serde_json::Value {
    serde_json::from_str(&engine::request(method, path, body).unwrap()).unwrap()
}

#[test]
fn embedded_control_data_and_restart() {
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let original = b"original configuration stays unchanged";
    std::fs::write(path.join("config.yaml"), original).unwrap();
    for _ in 0..2 {
        engine::start(home, home, config(port).as_bytes(), None).unwrap();
        assert!(engine::is_running());
        assert!(engine::start(home, home, config(port).as_bytes(), None).is_err());
        assert_eq!(api("GET", "/version", "")["status"], 200);
        assert_eq!(
            api("PATCH", "/configs", r#"{"mode":"direct"}"#)["status"],
            204
        );
        let response = api("GET", "/configs", "");
        let body: serde_json::Value =
            serde_json::from_str(response["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["mode"], "direct");

        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = echo.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).unwrap();
            stream.write_all(&payload).unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut auth = [0; 2];
        client.read_exact(&mut auth).unwrap();
        assert_eq!(auth, [5, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&connect).unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(b"meow").unwrap();
        let mut payload = [0; 4];
        client.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"meow");
        server.join().unwrap();
        drop(client);

        assert!(engine::request("GET", "/traffic", "").is_err());
        assert_eq!(std::fs::read(path.join("config.yaml")).unwrap(), original);
        engine::stop();
        assert!(!engine::is_running());
        let rebound = TcpListener::bind(("127.0.0.1", port)).unwrap();
        drop(rebound);
    }
}

#[test]
fn failed_start_and_offline_validation_leave_no_session() {
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    engine::validate(home, home, config(0).as_bytes()).unwrap();
    assert!(!engine::is_running());
    assert!(engine::validate(home, home, b"tun: {enable: true}").is_err());
    assert!(engine::validate(
        home,
        home,
        b"asterisk-auto-switch: {enable: true, groups: [G]}"
    )
    .is_ok());
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = config(occupied.local_addr().unwrap().port());
    assert!(engine::start(home, home, config.as_bytes(), None).is_err());
    assert!(!engine::is_running());
    assert!(crate::RUNTIME.lock().is_none());
}

#[cfg(unix)]
#[test]
fn tun_borrows_descriptor_and_can_restart() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    engine::start(home, home, config(0).as_bytes(), None).unwrap();
    for _ in 0..3 {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let source = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _peer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        crate::tun2socks::start(source.as_raw_fd(), "").unwrap();
        drop(source); // native keeps its duplicate
        engine::reload(home, home, config(0).as_bytes(), || Ok(())).unwrap();
        assert!(crate::tun2socks::retain_for_reload().unwrap().is_some());
        crate::tun2socks::stop();
        crate::tun2socks::stop();
    }
    assert!(crate::tun2socks::start(-1, "").is_err());
}

#[test]
fn listener_reload_and_failed_reload_restore_previous_session() {
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    engine::start(home, home, b"rules: ['MATCH,DIRECT']", None).unwrap();
    engine::patch_auto_switch(r#"{"interval":55}"#).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    engine::reload(home, home, config(port).as_bytes(), || Ok(())).unwrap();
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(engine::reload(
        home,
        home,
        config(occupied.local_addr().unwrap().port()).as_bytes(),
        || Ok(())
    )
    .is_err());
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert_eq!(api("GET", "/version", "")["status"], 200);
    let state: serde_json::Value =
        serde_json::from_str(&engine::query_auto_switch().unwrap()).unwrap();
    assert_eq!(state["source"], "control");
    assert_eq!(state["settings"]["interval"], 55);
}

#[test]
fn api_reload_requires_restart_without_partial_changes() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let original = config(port);
    engine::start(home, home, original.as_bytes(), None).unwrap();
    let capability: serde_json::Value = serde_json::from_str(
        api("GET", "/asterisk/capabilities", "")["body"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(capability["listenerHotReload"], false);
    for change in [
        config(0),
        format!("{original}authentication: ['user:password']\n"),
        format!("{original}secret: next\n"),
    ] {
        let body = serde_json::json!({"payload": STANDARD.encode(change.replace("mode: rule", "mode: global"))}).to_string();
        for route in ["/configs", "/configs?force=true"] {
            let response = api("PUT", route, &body);
            assert_eq!(response["status"], 409, "{response}");
            let detail: serde_json::Value =
                serde_json::from_str(response["body"].as_str().unwrap()).unwrap();
            assert_eq!(detail["code"], "RESTART_REQUIRED");
            assert!(!response.to_string().contains("user:password"));
            assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
            let state: serde_json::Value =
                serde_json::from_str(api("GET", "/configs", "")["body"].as_str().unwrap()).unwrap();
            assert_eq!(state["mode"], "rule");
        }
    }
    let body = serde_json::json!({"payload": STANDARD.encode(original.replace("mode: rule", "mode: direct"))}).to_string();
    assert_eq!(api("PUT", "/configs", &body)["status"], 204);
}

#[test]
fn close_all_connections_flushes_udp_nat_and_listener_flows() {
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    engine::start(home, home, config(0).as_bytes(), None).unwrap();
    let echo = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    echo.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let destination = echo.local_addr().unwrap();
    let source = "127.0.0.1:12345".parse().unwrap();
    let tunnel = engine::tunnel().unwrap();
    let watch = tunnel.inner().udp_flush_watch();
    crate::get_runtime().block_on(meow_tunnel::udp::handle_udp(
        tunnel.inner(),
        b"ping",
        source,
        meow_common::Metadata {
            network: meow_common::Network::Udp,
            src_ip: Some(source.ip()),
            src_port: source.port(),
            dst_ip: Some(destination.ip()),
            dst_port: destination.port(),
            ..Default::default()
        },
    ));
    let mut packet = [0; 16];
    assert_eq!(echo.recv_from(&mut packet).unwrap().0, 4);
    assert_eq!(tunnel.inner().nat_table.len(), 1);
    assert!(!watch.is_flushed());
    assert_eq!(api("DELETE", "/connections", "")["status"], 204);
    assert!(tunnel.inner().nat_table.is_empty());
    assert!(watch.is_flushed());
}

#[test]
fn ignored_core_options_do_not_block_startup() {
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    let yaml = b"rules: ['MATCH,DIRECT']\ngeodata-mode: true\ngeodata-loader: memconservative\ngeoip-matcher: succinct\nunified-delay: true\ndns: {enable: true, nameserver: ['system://'], direct-nameserver: ['https://private.test/dns'], respect-rules: true, prefer-h3: true}\ntun: {enable: false, stack: mips}\nclash-for-android: {ui-subtitle-pattern: '('}\n";
    let (_, diagnostics) = crate::profile::decode_with_diagnostics(yaml).unwrap();
    let report = serde_json::to_value(diagnostics).unwrap();
    assert_eq!(report.as_array().unwrap().len(), 9);
    assert!(!report.to_string().contains("private.test"));
    engine::validate(home, home, yaml).unwrap();
    engine::start(home, home, yaml, None).unwrap();
    assert_eq!(api("GET", "/version", "")["status"], 200);
    assert!(crate::profile::decode(b"dns: [").is_err());
}

#[test]
fn autoswitch_api_reload_save_and_new_session() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let _operation = engine::OPERATION.lock();
    let path = directory();
    let _cleanup = Cleanup(path.clone());
    let home = path.to_str().unwrap();
    let backing = path.join("config.yaml");
    let controller_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let profile = format!("{}\nsecret: test-secret\nexternal-controller: 127.0.0.1:{controller_port}\nasterisk-auto-switch: {{interval: 20}}\n", config(0));
    std::fs::write(&backing, &profile).unwrap();
    engine::start(
        home,
        home,
        profile.as_bytes(),
        Some(backing.to_str().unwrap().into()),
    )
    .unwrap();
    let query = || -> serde_json::Value {
        serde_json::from_str(&engine::query_auto_switch().unwrap()).unwrap()
    };
    assert_eq!(query()["source"], "config");
    assert_eq!(query()["settings"]["interval"], 20);
    let response = api("GET", "/asterisk/auto-switch", "");
    assert_eq!(response["status"], 200);
    for body in [
        r#"{"enable":true}"#,
        r#"{"preferred-filter":"("}"#,
        r#"{"expected-status":"abc"}"#,
    ] {
        assert_eq!(api("PATCH", "/asterisk/auto-switch", body)["status"], 400);
    }
    assert_eq!(
        api(
            "PATCH",
            "/asterisk/auto-switch",
            r#"{"interval":60,"expected-delay":150}"#
        )["status"],
        204
    );
    // The extension's HTTP route enforces the same secret as the upstream router.
    let mut unauthorized = TcpStream::connect(("127.0.0.1", controller_port)).unwrap();
    unauthorized
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    unauthorized
        .write_all(
            b"GET /asterisk/auto-switch HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut response = String::new();
    unauthorized.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    let reload = profile.replace("interval: 20", "interval: 40");
    let body = serde_json::json!({"payload": STANDARD.encode(&reload)}).to_string();
    assert_eq!(api("PUT", "/configs", &body)["status"], 204);
    assert_eq!(query()["source"], "control");
    assert_eq!(query()["settings"]["interval"], 60);
    assert_eq!(query()["settings"]["expected-delay"], 150);
    let bad = serde_json::json!({"payload": STANDARD.encode("tun: {enable: true}")}).to_string();
    assert_eq!(api("PUT", "/configs", &bad)["status"], 400);
    assert_eq!(api("POST", "/api/config/save", "")["status"], 200);
    let saved = std::fs::read(&backing).unwrap();
    let yaml: serde_yaml::Value = serde_yaml::from_slice(&saved).unwrap();
    assert_eq!(yaml["asterisk-auto-switch"]["interval"].as_i64(), Some(40));
    assert!(path.join("config.yaml.bak").is_file());
    engine::stop();
    engine::start(home, home, &saved, Some(backing.to_str().unwrap().into())).unwrap();
    assert_eq!(query()["source"], "config");
    assert_eq!(query()["settings"]["interval"], 40);
    engine::patch_auto_switch(r#"{"interval":55}"#).unwrap();
    assert_eq!(query()["settings"]["interval"], 55);
}
