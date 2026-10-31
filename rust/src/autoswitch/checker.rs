// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use super::{Event, GroupStatus, Restore, Service, Settings};
use fancy_regex::Regex;
use meow_common::{AdapterType, Proxy};
use meow_tunnel::{tunnel::RouteTable, Tunnel};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::task::JoinSet;

#[derive(Clone, Default)]
struct Failure {
    node: String,
    count: u16,
    backoff: u16,
    skip: u16,
}

pub(super) struct Checker {
    pub(super) service: Arc<Service>,
    settings: Settings,
    filter: Option<Regex>,
    expected: String,
    failures: HashMap<String, Failure>,
    checked_at: HashMap<String, i64>,
    started_at: i64,
    generation: Option<Arc<RouteTable>>,
    background: JoinSet<()>,
}

impl Checker {
    pub(super) fn new(service: Arc<Service>, settings: Settings) -> Self {
        let filter = settings.filter().unwrap_or_else(|error| {
            tracing::warn!("[AutoSwitch] invalid preferred-filter: {error}");
            None
        });
        let expected = settings.status_ranges().unwrap_or_else(|error| {
            tracing::warn!("[AutoSwitch] invalid expected-status: {error}");
            "0-65535".into()
        });
        Self {
            service,
            settings,
            filter,
            expected,
            failures: HashMap::new(),
            checked_at: HashMap::new(),
            started_at: super::now(),
            generation: None,
            background: JoinSet::new(),
        }
    }

    pub(super) async fn run(mut self) {
        loop {
            while self.background.try_join_next().is_some() {}
            self.service.phase("checking", 0);
            self.round().await;
            self.service
                .phase("waiting", super::now() + self.settings.interval * 1000);
            tokio::time::sleep(Duration::from_secs(self.settings.interval as u64)).await;
        }
    }

    pub(super) async fn round(&mut self) {
        let generation = self.service.tunnel.route_snapshot();
        if self
            .generation
            .as_ref()
            .is_some_and(|old| !Arc::ptr_eq(old, &generation))
        {
            self.failures.clear();
            self.checked_at.clear();
            self.started_at = super::now();
        }
        self.generation = Some(generation);
        for group in self.settings.groups.clone() {
            if !self.check_restore(&group).await {
                self.check_group(&group).await;
            }
        }
    }

    async fn check_group(&mut self, name: &str) {
        let route = self.service.tunnel.route_snapshot();
        let Some(group) = selector(&route, name) else {
            self.failures.remove(name);
            self.service.group(GroupStatus {
                name: name.into(),
                kind: "unavailable",
                ..Default::default()
            });
            return;
        };
        let selected = group.current().unwrap_or_default();
        let Some(proxy) = member(&group, &selected).filter(is_leaf) else {
            self.failures.remove(name);
            self.service.group(GroupStatus {
                name: name.into(),
                kind: "skipped",
                node: selected,
                ..Default::default()
            });
            return;
        };
        let since = self
            .checked_at
            .insert(name.into(), super::now())
            .unwrap_or(self.started_at);
        // Use meow's connection start time as exposed by its statistics API.
        if self
            .service
            .tunnel
            .statistics()
            .active_connections()
            .into_iter()
            .any(|c| {
                c.counters.download_bytes() > 0
                    && c.chains.first().is_some_and(|p| p.as_ref() == selected)
                    && c.chains.iter().any(|p| p.as_ref() == name)
                    && time::OffsetDateTime::parse(
                        &c.start,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .is_ok_and(|start| start.unix_timestamp_nanos() / 1_000_000 > i128::from(since))
            })
        {
            self.failures.remove(name);
            self.service.group(GroupStatus {
                name: name.into(),
                kind: "healthy",
                node: selected,
                in_use: true,
                ..Default::default()
            });
            return;
        }
        self.service.progress(name, "current", 1);
        if let Some(delay) = self.probe(&proxy).await {
            self.failures.remove(name);
            self.service.group(GroupStatus {
                name: name.into(),
                kind: "healthy",
                node: selected,
                delay,
                ..Default::default()
            });
            return;
        }
        let threshold = self.settings.failure_threshold as u16;
        let mut failure = self
            .failures
            .get(name)
            .filter(|f| f.node == selected)
            .cloned()
            .unwrap_or_else(|| Failure {
                node: selected.clone(),
                ..Default::default()
            });
        if failure.count < threshold {
            failure.count += 1;
            self.service.record(Event {
                group: name.into(),
                kind: "failed",
                node: selected.clone(),
                failures: failure.count,
                threshold,
                ..Default::default()
            });
        }
        self.service.group(GroupStatus {
            name: name.into(),
            kind: "failed",
            node: selected.clone(),
            failures: failure.count,
            ..Default::default()
        });
        if failure.count < threshold || failure.skip > 0 {
            failure.skip = failure.skip.saturating_sub(1);
            self.failures.insert(name.into(), failure);
            return;
        }
        let (replacement, mut summary) = self.replacement(name, &group, &selected, route).await;
        let Some((replacement, delay)) = replacement else {
            failure.backoff = (failure.backoff * 2).clamp(1, 8);
            failure.skip = failure.backoff;
            self.failures.insert(name.into(), failure);
            summary.group = name.into();
            summary.kind = "no-replacement";
            summary.node = selected;
            self.service.record(summary);
            return;
        };
        self.failures.remove(name);
        if !self.select(name, &group, &selected, &replacement).await {
            self.service.record(Event {
                group: name.into(),
                kind: "selection-changed",
                node: selected,
                target: replacement,
                ..Default::default()
            });
            return;
        }
        self.remember_origin(name, &selected, &replacement);
        summary.group = name.into();
        summary.kind = "switched";
        summary.node = selected;
        summary.target = replacement.clone();
        summary.delay = delay;
        self.service.record(summary);
        self.service.group(GroupStatus {
            name: name.into(),
            kind: "healthy",
            node: replacement,
            delay,
            ..Default::default()
        });
    }

    fn remember_origin(&self, name: &str, selected: &str, replacement: &str) {
        if !self.settings.restore {
            return;
        }
        let mut state = self.service.state.lock();
        let mut restore = state
            .restores
            .get(name)
            .filter(|r| r.target == selected)
            .cloned()
            .unwrap_or_else(|| Restore {
                origin: selected.into(),
                ..Default::default()
            });
        if restore.origin == replacement {
            state.restores.remove(name);
            return;
        }
        restore.target = replacement.into();
        restore.successes = 0;
        state.restores.insert(name.into(), restore);
    }

    async fn check_restore(&mut self, name: &str) -> bool {
        let Some(mut restore) = self.service.state.lock().restores.get(name).cloned() else {
            return false;
        };
        let route = self.service.tunnel.route_snapshot();
        let group =
            selector(&route, name).filter(|g| g.current().as_deref() == Some(&restore.target));
        let proxy = group
            .as_ref()
            .and_then(|g| member(g, &restore.origin))
            .filter(is_leaf);
        let (Some(group), Some(proxy)) = (group, proxy) else {
            self.service.state.lock().restores.remove(name);
            return false;
        };
        self.service.progress(name, "restore", 1);
        let result = self.probe(&proxy).await;
        restore.successes = if result.is_some() {
            restore.successes + 1
        } else {
            0
        };
        if restore.successes < 3 {
            self.service
                .state
                .lock()
                .restores
                .insert(name.into(), restore);
            return false;
        }
        self.service.state.lock().restores.remove(name);
        if !self
            .select(name, &group, &restore.target, &restore.origin)
            .await
        {
            self.service.record(Event {
                group: name.into(),
                kind: "selection-changed",
                node: restore.target,
                target: restore.origin,
                ..Default::default()
            });
            return false;
        }
        self.failures.remove(name);
        let delay = result.unwrap();
        self.service.record(Event {
            group: name.into(),
            kind: "restored",
            node: restore.target,
            target: restore.origin.clone(),
            delay,
            ..Default::default()
        });
        self.service.group(GroupStatus {
            name: name.into(),
            kind: "healthy",
            node: restore.origin,
            delay,
            ..Default::default()
        });
        true
    }

    async fn select(
        &self,
        name: &str,
        original_group: &Arc<dyn Proxy>,
        from: &str,
        to: &str,
    ) -> bool {
        let _mutation = self.service.mutations.lock().await;
        let _configuration = meow_api::routes::CONFIG_MUTATION.lock().await;
        let route = self.service.tunnel.route_snapshot();
        let Some(group) = selector(&route, name) else {
            return false;
        };
        if !Arc::ptr_eq(&group, original_group) || group.current().as_deref() != Some(from) {
            return false;
        }
        let Some(selection) = group.selection() else {
            return false;
        };
        // meow's Selector writes through its SelectorStore when selection succeeds.
        if selection.set(to).await.is_err() {
            return false;
        }
        close_connections_through(&self.service.tunnel, name, &route);
        true
    }

    async fn replacement(
        &mut self,
        name: &str,
        group: &Arc<dyn Proxy>,
        selected: &str,
        route: Arc<RouteTable>,
    ) -> (Option<(String, u16)>, Event) {
        let mut seen = HashSet::from([selected.to_owned()]);
        let (mut preferred, mut others) = (Vec::new(), Vec::new());
        for proxy in group.member_proxies().unwrap_or_default() {
            if !is_leaf(&proxy) || !seen.insert(proxy.name().to_owned()) {
                continue;
            }
            if self
                .filter
                .as_ref()
                .is_some_and(|r| r.is_match(proxy.name()).unwrap_or(false))
            {
                preferred.push(proxy);
            } else {
                others.push(proxy);
            }
        }
        let mut summary = Event::default();
        for (stage, proxies) in [("preferred", preferred), ("all", others)] {
            if proxies.is_empty() {
                continue;
            }
            self.service.progress(name, stage, proxies.len());
            let (best, tested, available) = self.test_all(proxies, route.clone()).await;
            summary.tested += tested;
            summary.available += available;
            summary.preferred = stage == "preferred";
            if best.is_some() {
                return (best, summary);
            }
        }
        (None, summary)
    }

    async fn probe(&self, proxy: &Arc<dyn Proxy>) -> Option<u16> {
        meow_proxy::health::probe_and_record(
            proxy,
            &self.settings.url,
            Some(&self.expected),
            Duration::from_millis(self.settings.timeout as u64),
        )
        .await
        .ok()
    }

    async fn test_all(
        &mut self,
        mut proxies: Vec<Arc<dyn Proxy>>,
        route: Arc<RouteTable>,
    ) -> (Option<(String, u16)>, usize, usize) {
        if self.settings.expected_delay > 0 {
            proxies.sort_by_cached_key(|p| match p.last_delay_for_url(&self.settings.url) {
                0 => u16::MAX,
                delay => delay,
            });
        }
        let mut pending = proxies.into_iter();
        let mut jobs = JoinSet::new();
        for proxy in pending.by_ref().take(self.settings.concurrency as usize) {
            self.spawn_probe(&mut jobs, proxy, route.clone());
        }
        let (mut best, mut tested, mut available): (Option<(String, u16)>, usize, usize) =
            (None, 0, 0);
        while let Some(result) = jobs.join_next().await {
            let Ok((name, delay)) = result else {
                continue;
            };
            tested += 1;
            self.service.advance();
            if let Some(delay) = delay {
                available += 1;
                if best
                    .as_ref()
                    .is_none_or(|(_, best_delay)| delay < *best_delay)
                {
                    best = Some((name, delay));
                }
                if self.settings.expected_delay > 0
                    && i64::from(delay) < self.settings.expected_delay
                {
                    // Stop queued work, but let in-flight probes finish with real
                    // health results. Restart/stop aborts this owned drain task.
                    self.background
                        .spawn(async move { while jobs.join_next().await.is_some() {} });
                    return (best, tested, available);
                }
            }
            if let Some(proxy) = pending.next() {
                self.spawn_probe(&mut jobs, proxy, route.clone());
            }
        }
        (best, tested, available)
    }

    fn spawn_probe(
        &self,
        jobs: &mut JoinSet<(String, Option<u16>)>,
        proxy: Arc<dyn Proxy>,
        route: Arc<RouteTable>,
    ) {
        let url = self.settings.url.clone();
        let expected = self.expected.clone();
        let timeout = Duration::from_millis(self.settings.timeout as u64);
        jobs.spawn(async move {
            let _generation = route;
            let result =
                meow_proxy::health::probe_and_record(&proxy, &url, Some(&expected), timeout)
                    .await
                    .ok();
            (proxy.name().into(), result)
        });
    }
}

fn selector(route: &RouteTable, name: &str) -> Option<Arc<dyn Proxy>> {
    route
        .proxies
        .get(name)
        .filter(|p| p.adapter_type() == AdapterType::Selector)
        .cloned()
}
fn member(group: &Arc<dyn Proxy>, name: &str) -> Option<Arc<dyn Proxy>> {
    group
        .member_proxies()?
        .into_iter()
        .find(|p| p.name() == name)
}
fn is_leaf(proxy: &Arc<dyn Proxy>) -> bool {
    proxy.members().is_none()
        && !matches!(
            proxy.adapter_type(),
            AdapterType::Direct
                | AdapterType::Reject
                | AdapterType::RejectDrop
                | AdapterType::Pass
                | AdapterType::PassRule
                | AdapterType::Compatible
        )
}

fn close_connections_through(tunnel: &Tunnel, group: &str, route: &RouteTable) {
    for connection in tunnel.statistics().active_connections() {
        if connection.chains.iter().any(|p| p.as_ref() == group) {
            tunnel.statistics().close_connection(connection.id);
        }
    }
    // meow's UDP NAT records the rule's outbound name, not per-flow chains.
    // Follow selected parents; a load-balance ancestor must refresh all its
    // sessions because the exact member used by each datagram is not exposed.
    let uses_group = |name: &str| {
        if name == group {
            return true;
        }
        let mut pending: Vec<_> = route.proxies.get(name).cloned().into_iter().collect();
        let mut seen = HashSet::new();
        while let Some(proxy) = pending.pop() {
            if proxy.name() == group {
                return true;
            }
            if !seen.insert(proxy.name().to_owned()) {
                continue;
            }
            let members = proxy.member_proxies().unwrap_or_default();
            if let Some(selected) = proxy.current() {
                pending.extend(members.into_iter().filter(|p| p.name() == selected));
            } else {
                pending.extend(members);
            }
        }
        false
    };
    let table = &tunnel.inner().nat_table;
    let sessions: Vec<_> = table
        .iter()
        .filter(|s| uses_group(&s.proxy_name))
        .map(|entry| (*entry.key(), entry.value().clone()))
        .collect();
    for (key, session) in sessions {
        if table
            .remove_if(&key, |_, active| Arc::ptr_eq(active, &session))
            .is_some()
        {
            let _ = session.conn.close();
        }
    }
}
