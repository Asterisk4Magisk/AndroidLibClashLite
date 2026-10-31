// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use super::*;
use checker::Checker;
use meow_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn,
};
use meow_proxy::group::selector::SelectorGroup;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Node {
    name: String,
    address: SocketAddr,
    healthy: AtomicBool,
    delay: AtomicU64,
    calls: AtomicUsize,
    health: ProxyHealth,
}
#[async_trait::async_trait]
impl ProxyAdapter for Node {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Socks5
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
    async fn dial_tcp(&self, _: &Metadata) -> meow_common::Result<Box<dyn ProxyConn>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.healthy.load(Ordering::SeqCst) {
            return Err(meow_common::MeowError::Proxy("node down".into()));
        }
        tokio::time::sleep(Duration::from_millis(self.delay.load(Ordering::SeqCst))).await;
        Ok(Box::new(
            tokio::net::TcpStream::connect(self.address).await?,
        ))
    }
    async fn dial_udp(&self, _: &Metadata) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        Err(meow_common::MeowError::NotSupported("test node".into()))
    }
}
impl Proxy for Node {
    fn alive(&self) -> bool {
        self.health.alive()
    }
    fn alive_for_url(&self, _: &str) -> bool {
        self.alive()
    }
    fn last_delay(&self) -> u16 {
        self.health.last_delay()
    }
    fn last_delay_for_url(&self, _: &str) -> u16 {
        self.last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.health.delay_history()
    }
}

struct Fixture {
    service: Arc<Service>,
    group: Arc<SelectorGroup>,
    nodes: HashMap<String, Arc<Node>>,
    settings: Settings,
    _home: tempfile::TempDir,
}
impl Fixture {
    fn new(nodes: &[(&str, bool)]) -> Self {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().to_str().unwrap();
        crate::engine::start(
            path,
            path,
            b"log-level: silent\nlogbook: {enable: false}\nrules: ['MATCH,DIRECT']",
            None,
        )
        .unwrap();
        crate::get_runtime().block_on(async {
            let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = server.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0; 1024];
                        let _ = stream.read(&mut buf).await;
                        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    });
                }
            });
            let mut map: HashMap<String, Arc<Node>> = HashMap::new();
            let mut members = Vec::new();
            for (name, healthy) in nodes {
                let node = Arc::new(Node { name: (*name).into(), address, healthy: AtomicBool::new(*healthy),
                    delay: AtomicU64::new(0), calls: AtomicUsize::new(0), health: ProxyHealth::new() });
                members.push(node.clone() as Arc<dyn Proxy>);
                map.insert((*name).into(), node);
            }
            let group = Arc::new(SelectorGroup::new("G", members));
            let tunnel = crate::engine::tunnel().unwrap();
            let mut proxies = HashMap::new();
            proxies.insert("G".into(), group.clone() as Arc<dyn Proxy>);
            for (name, proxy) in &map { proxies.insert(name.as_str().into(), proxy.clone() as Arc<dyn Proxy>); }
            tunnel.update_proxies(proxies, Default::default());
            let service = Service::new(tunnel);
            let settings = Settings { enable: true, groups: vec!["G".into()], url: format!("http://{address}"),
                timeout: 1000, ..Default::default() }.normalized();
            service.state.lock().settings = settings.clone();
            Self { service, group, nodes: map, settings, _home: home }
        })
    }
    fn checker(&self) -> Checker {
        Checker::new(self.service.clone(), self.settings.clone())
    }
    fn healthy(&self, name: &str, healthy: bool) {
        self.nodes[name].healthy.store(healthy, Ordering::SeqCst);
    }
    fn delay(&self, name: &str, ms: u64) {
        self.nodes[name].delay.store(ms, Ordering::SeqCst);
    }
    fn calls(&self, name: &str) -> usize {
        self.nodes[name].calls.load(Ordering::SeqCst)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        crate::get_runtime().block_on(self.service.stop());
        crate::engine::stop();
    }
}

#[test]
fn settings_and_mihomo_status_syntax() {
    let settings = Settings {
        groups: vec![" G ".into(), "".into(), "G".into()],
        failure_threshold: 99,
        interval: 1,
        timeout: -1,
        ..Default::default()
    }
    .normalized();
    assert_eq!(settings.groups, ["G"]);
    assert_eq!(
        (
            settings.failure_threshold,
            settings.interval,
            settings.timeout,
            settings.concurrency
        ),
        (10, 10, 1000, 5)
    );
    assert!(Settings {
        enable: true,
        ..Default::default()
    }
    .validate()
    .is_err());
    assert!(Settings {
        expected_delay: 100000,
        ..Default::default()
    }
    .validate()
    .is_err());
    for (spec, expected) in [
        ("", "0-65535"),
        ("*", "0-65535"),
        ("200/204/400-399", "200,204,399-400"),
    ] {
        assert_eq!(
            Settings {
                expected_status: spec.into(),
                ..Default::default()
            }
            .status_ranges()
            .unwrap(),
            expected
        );
    }
    let filter = Settings {
        preferred_filter: r"(?i)(?<![A-Za-z])UK(?![A-Za-z])".into(),
        ..Default::default()
    }
    .filter()
    .unwrap()
    .unwrap();
    for (name, matches) in [
        ("UK 01", true),
        ("🇬🇧 uk-2", true),
        ("Ukraine 01", false),
        ("Duke", false),
    ] {
        assert_eq!(filter.is_match(name).unwrap(), matches);
    }
}

#[test]
fn preferred_threshold_and_restore_after_three_successes() {
    let _operation = crate::engine::OPERATION.lock();
    let mut fixture = Fixture::new(&[("A", false), ("B", true), ("HK 01", true)]);
    fixture.settings.preferred_filter = "(?i)HK".into();
    fixture.settings.failure_threshold = 2;
    fixture.settings.restore = true;
    crate::get_runtime().block_on(async {
        let mut checker = fixture.checker();
        checker.round().await;
        assert_eq!(fixture.group.current().as_deref(), Some("A"));
        checker.round().await;
        assert_eq!(fixture.group.current().as_deref(), Some("HK 01"));
        assert_eq!(fixture.calls("B"), 0);
        assert_eq!(fixture.service.snapshot()["events"][0]["preferred"], true);
        fixture.healthy("HK 01", false);
        checker.round().await;
        checker.round().await;
        assert_eq!(fixture.group.current().as_deref(), Some("B"));
        assert_eq!(fixture.service.snapshot()["groups"][0]["origin"], "A");
        // A full Android load creates a new service; the pending restoration
        // and event history must follow it, without inheriting failure counts.
        let saved = fixture.service.suspend_for_reload().await;
        let replacement = Service::new(fixture.service.tunnel.clone());
        replacement.restore_reload_state(saved).await;
        assert!(!replacement.state.lock().events.is_empty());
        replacement.state.lock().settings = fixture.settings.clone();
        fixture.service = replacement;
        checker = fixture.checker();
        fixture.healthy("A", true);
        checker.round().await;
        fixture.healthy("A", false);
        checker.round().await; // broken streak
        fixture.healthy("A", true);
        for expected in 1..3 {
            checker.round().await;
            assert_eq!(fixture.group.current().as_deref(), Some("B"));
            assert_eq!(
                fixture.service.snapshot()["groups"][0]["originSuccesses"],
                expected
            );
        }
        checker.round().await;
        assert_eq!(fixture.group.current().as_deref(), Some("A"));
        assert_eq!(fixture.service.snapshot()["events"][0]["kind"], "restored");
    });
}

#[test]
fn fallback_backoff_and_bounded_history() {
    let _operation = crate::engine::OPERATION.lock();
    let mut fixture = Fixture::new(&[("A", false), ("B", false), ("HK 01", false)]);
    fixture.settings.preferred_filter = "HK".into();
    crate::get_runtime().block_on(async {
        let mut checker = fixture.checker();
        for attempts in [1, 1, 2, 2, 2, 3] {
            checker.round().await;
            assert_eq!(fixture.calls("B"), attempts);
            assert_eq!(fixture.group.current().as_deref(), Some("A"));
        }
        fixture.healthy("B", true);
        for _ in 0..5 {
            checker.round().await;
        }
        assert_eq!(fixture.group.current().as_deref(), Some("B"));
        let state = fixture.service.snapshot();
        assert_eq!(state["events"][0]["kind"], "switched");
        assert_eq!(state["events"][0]["tested"], 2);
        for i in 0..105 {
            fixture.service.record(Event {
                failures: i,
                ..Default::default()
            });
        }
        let state = fixture.service.snapshot();
        assert_eq!(state["events"].as_array().unwrap().len(), 100);
        assert_eq!(state["events"][0]["failures"], 104);
        assert_eq!(state["events"][99]["failures"], 5);
    });
}

#[test]
fn expected_delay_returns_early_without_corrupting_late_probes() {
    let _operation = crate::engine::OPERATION.lock();
    let mut fixture = Fixture::new(&[
        ("A", false),
        ("slow", true),
        ("fast", true),
        ("queued", true),
    ]);
    fixture.settings.expected_delay = 100;
    fixture.settings.concurrency = 2;
    fixture.delay("slow", 220);
    crate::get_runtime().block_on(async {
        let mut checker = fixture.checker();
        let start = std::time::Instant::now();
        checker.round().await;
        assert!(start.elapsed() < Duration::from_millis(180));
        assert_eq!(fixture.group.current().as_deref(), Some("fast"));
        assert_eq!(fixture.calls("queued"), 0);
        assert_eq!(fixture.service.snapshot()["events"][0]["tested"], 1);
        tokio::time::sleep(Duration::from_millis(280)).await;
        assert!(fixture.nodes["slow"].health.last_delay() >= 220);
        assert!(fixture.nodes["slow"].health.alive());
        assert_eq!(fixture.service.snapshot()["events"][0]["tested"], 1);
    });
}

#[test]
fn last_delay_order_and_zero_expected_delay() {
    let _operation = crate::engine::OPERATION.lock();
    let mut fixture = Fixture::new(&[("A", false), ("B", true), ("C", true)]);
    fixture.settings.expected_delay = 99999;
    fixture.settings.concurrency = 1;
    fixture.nodes["B"].health.record_delay(300);
    fixture.nodes["C"].health.record_delay(10);
    crate::get_runtime().block_on(async {
        fixture.checker().round().await;
        assert_eq!(fixture.group.current().as_deref(), Some("C"));
        assert_eq!(fixture.calls("B"), 0);
        fixture.group.select("A");
        fixture.settings.expected_delay = 0;
        fixture.delay("C", 80);
        fixture.checker().round().await;
        assert_eq!(fixture.group.current().as_deref(), Some("B"));
        assert_eq!(fixture.service.snapshot()["events"][0]["tested"], 2);
    });
}

#[test]
fn manual_selection_wins_and_cancels_restore() {
    let _operation = crate::engine::OPERATION.lock();
    let mut fixture = Fixture::new(&[("A", false), ("B", true), ("C", true)]);
    fixture.settings.restore = true;
    fixture.settings.expected_delay = 99999;
    fixture.settings.concurrency = 1;
    fixture.delay("B", 150);
    crate::get_runtime().block_on(async {
        let mut checker = fixture.checker();
        tokio::join!(checker.round(), async {
            while fixture.calls("B") == 0 {
                tokio::task::yield_now().await;
            }
            let _mutation = fixture.service.mutations.lock().await;
            fixture.group.select("C");
        });
        assert_eq!(fixture.group.current().as_deref(), Some("C"));
        assert_eq!(
            fixture.service.snapshot()["events"][0]["kind"],
            "selection-changed"
        );
        fixture.group.select("A");
        checker.round().await;
        assert_eq!(fixture.group.current().as_deref(), Some("B"));
        assert_eq!(fixture.service.snapshot()["groups"][0]["origin"], "A");
        fixture.group.select("C");
        fixture.healthy("A", true);
        for _ in 0..3 {
            checker.round().await;
        }
        assert_eq!(fixture.group.current().as_deref(), Some("C"));
        assert!(fixture.service.state.lock().restores.is_empty());
    });
}

#[test]
fn live_traffic_and_close_only_affected_connections() {
    let _operation = crate::engine::OPERATION.lock();
    let fixture = Fixture::new(&[("A", true), ("B", true)]);
    crate::get_runtime().block_on(async {
        let mut checker = fixture.checker();
        // meow exposes connection start times with second precision.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let statistics = fixture.service.tunnel.statistics();
        let id = statistics.track_connection(
            Default::default(),
            "MATCH".into(),
            "".into(),
            [Arc::from("A"), Arc::from("G")].into_iter().collect(),
        );
        statistics.record_download(&statistics.connection_counters(id).unwrap(), 128);
        let other = statistics.track_connection(
            Default::default(),
            "MATCH".into(),
            "".into(),
            [Arc::from("other")].into_iter().collect(),
        );
        checker.round().await;
        assert_eq!(fixture.calls("A"), 0);
        assert_eq!(fixture.service.snapshot()["groups"][0]["inUse"], true);
        fixture.healthy("A", false);
        checker.round().await; // old traffic cannot hide a failed new dial
        assert_eq!(fixture.group.current().as_deref(), Some("B"));
        assert!(statistics.connection_counters(id).is_none());
        assert!(statistics.connection_counters(other).is_some());
    });
}

#[test]
fn override_restart_and_stop_cancel_work() {
    let _operation = crate::engine::OPERATION.lock();
    let fixture = Fixture::new(&[("A", true), ("B", true)]);
    fixture.delay("A", 30000);
    fixture.nodes["A"].health.record_delay(20);
    crate::get_runtime().block_on(async {
        fixture.service.apply(fixture.settings.clone()).await;
        while fixture.calls("A") == 0 {
            tokio::task::yield_now().await;
        }
        let start = std::time::Instant::now();
        fixture
            .service
            .patch(Settings {
                interval: 60,
                expected_delay: 150,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(fixture.nodes["A"].health.last_delay(), 20);
        fixture
            .service
            .apply(Settings {
                interval: 20,
                ..Default::default()
            })
            .await;
        let state = fixture.service.snapshot();
        assert_eq!(state["source"], "control");
        assert_eq!(state["settings"]["interval"], 60);
        assert_eq!(state["settings"]["expected-delay"], 150);
        assert!(fixture
            .service
            .patch(Settings {
                enable: true,
                ..Default::default()
            })
            .await
            .is_err());
        fixture.service.stop().await;
        assert_eq!(fixture.service.snapshot()["phase"], "stopped");
    });
}
