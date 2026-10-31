// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

mod checker;
mod options;
#[cfg(test)]
mod tests;
pub use options::Settings;

use meow_tunnel::Tunnel;
use parking_lot::Mutex;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::{sync::Mutex as AsyncMutex, task::JoinHandle};

fn empty(s: &String) -> bool {
    s.is_empty()
}
fn zero(n: &u16) -> bool {
    *n == 0
}
fn zero_size(n: &usize) -> bool {
    *n == 0
}
fn false_value(b: &bool) -> bool {
    !b
}
pub fn now() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

#[derive(Clone, Default, Serialize)]
pub struct Event {
    pub time: i64,
    pub group: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "empty")]
    pub node: String,
    #[serde(skip_serializing_if = "empty")]
    pub target: String,
    #[serde(skip_serializing_if = "zero")]
    pub delay: u16,
    #[serde(skip_serializing_if = "zero")]
    pub failures: u16,
    #[serde(skip_serializing_if = "zero")]
    pub threshold: u16,
    #[serde(skip_serializing_if = "zero_size")]
    pub tested: usize,
    #[serde(skip_serializing_if = "zero_size")]
    pub available: usize,
    #[serde(skip_serializing_if = "false_value")]
    pub preferred: bool,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupStatus {
    pub name: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "empty")]
    pub node: String,
    #[serde(skip_serializing_if = "zero")]
    pub delay: u16,
    #[serde(skip_serializing_if = "zero")]
    pub failures: u16,
    #[serde(skip_serializing_if = "false_value")]
    pub in_use: bool,
    #[serde(skip_serializing_if = "empty")]
    pub origin: String,
    #[serde(skip_serializing_if = "zero")]
    pub origin_successes: u16,
    pub checked_at: i64,
}

#[derive(Clone, Serialize)]
pub struct Progress {
    pub group: String,
    pub stage: &'static str,
    pub completed: usize,
    pub total: usize,
}

#[derive(Clone, Default)]
struct Restore {
    origin: String,
    target: String,
    successes: u16,
}

struct State {
    settings: Settings,
    source: &'static str,
    phase: &'static str,
    next_check_at: i64,
    progress: Option<Progress>,
    groups: HashMap<String, GroupStatus>,
    events: VecDeque<Event>,
    restores: HashMap<String, Restore>,
}

#[derive(Default)]
struct Lifecycle {
    configured: Settings,
    override_settings: Option<Settings>,
    task: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub(crate) struct ReloadState {
    override_settings: Option<Settings>,
    restores: HashMap<String, Restore>,
    events: VecDeque<Event>,
}

pub struct Service {
    tunnel: Tunnel,
    state: Mutex<State>,
    lifecycle: AsyncMutex<Lifecycle>,
    /// Shared with API mutations, so manual choices and reloads cannot race
    /// an automatic compare-and-set. Probes never hold this lock.
    pub mutations: AsyncMutex<()>,
}

impl Service {
    pub fn new(tunnel: Tunnel) -> Arc<Self> {
        Arc::new(Self {
            tunnel,
            state: Mutex::new(State {
                settings: Settings::default().normalized(),
                source: "config",
                phase: "stopped",
                next_check_at: 0,
                progress: None,
                groups: HashMap::new(),
                events: VecDeque::new(),
                restores: HashMap::new(),
            }),
            lifecycle: AsyncMutex::new(Lifecycle::default()),
            mutations: AsyncMutex::new(()),
        })
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let state = self.state.lock();
        let groups: Vec<_> = state
            .settings
            .groups
            .iter()
            .filter_map(|n| state.groups.get(n))
            .collect();
        let events: Vec<_> = state.events.iter().rev().collect();
        let mut value = serde_json::json!({"settings": state.settings, "source": state.source,
            "phase": state.phase, "groups": groups, "events": events});
        if state.next_check_at != 0 {
            value["nextCheckAt"] = state.next_check_at.into();
        }
        if let Some(progress) = &state.progress {
            value["progress"] = serde_json::to_value(progress).unwrap();
        }
        value
    }

    pub async fn configured(&self) -> Settings {
        self.lifecycle.lock().await.configured.clone()
    }

    pub(crate) async fn suspend_for_reload(&self) -> ReloadState {
        let mut life = self.lifecycle.lock().await;
        if let Some(task) = life.task.take() {
            task.abort();
            let _ = task.await;
        }
        let state = self.state.lock();
        ReloadState {
            override_settings: life.override_settings.clone(),
            restores: state.restores.clone(),
            events: state.events.clone(),
        }
    }

    // Seed a new service before apply starts any probes on the new tunnel.
    pub(crate) async fn restore_reload_state(&self, saved: ReloadState) {
        self.lifecycle.lock().await.override_settings = saved.override_settings;
        let mut state = self.state.lock();
        state.restores = saved.restores;
        state.events = saved.events;
    }

    pub async fn apply(self: &Arc<Self>, configured: Settings) {
        let mut life = self.lifecycle.lock().await;
        life.configured = configured;
        self.restart(&mut life).await;
    }

    pub async fn patch(self: &Arc<Self>, settings: Settings) -> anyhow::Result<()> {
        settings.validate()?;
        let mut life = self.lifecycle.lock().await;
        life.override_settings = Some(settings);
        self.restart(&mut life).await;
        Ok(())
    }

    async fn restart(self: &Arc<Self>, life: &mut Lifecycle) {
        if let Some(task) = life.task.take() {
            task.abort();
            let _ = task.await;
        }
        let settings = life
            .override_settings
            .as_ref()
            .unwrap_or(&life.configured)
            .clone()
            .normalized();
        {
            let mut state = self.state.lock();
            state.settings = settings.clone();
            state.source = if life.override_settings.is_some() {
                "control"
            } else {
                "config"
            };
            state.phase = "stopped";
            state.next_check_at = 0;
            state.progress = None;
            state.groups.clear();
            state.restores.retain(|name, _| {
                settings.enable && settings.restore && settings.groups.contains(name)
            });
        }
        if settings.enable && !settings.groups.is_empty() {
            let checker = checker::Checker::new(self.clone(), settings);
            life.task = Some(tokio::spawn(checker.run()));
        }
    }

    pub async fn stop(&self) {
        let mut life = self.lifecycle.lock().await;
        if let Some(task) = life.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.phase("stopped", 0);
    }

    fn phase(&self, phase: &'static str, next: i64) {
        let mut state = self.state.lock();
        state.phase = phase;
        state.next_check_at = next;
        state.progress = None;
    }
    fn progress(&self, group: &str, stage: &'static str, total: usize) {
        self.state.lock().progress = Some(Progress {
            group: group.into(),
            stage,
            completed: 0,
            total,
        });
    }
    fn advance(&self) {
        if let Some(progress) = &mut self.state.lock().progress {
            progress.completed += 1;
        }
    }
    fn group(&self, mut group: GroupStatus) {
        let mut state = self.state.lock();
        group.checked_at = now();
        if let Some(restore) = state.restores.get(&group.name) {
            group.origin.clone_from(&restore.origin);
            group.origin_successes = restore.successes;
        }
        state.groups.insert(group.name.clone(), group);
    }
    fn record(&self, mut event: Event) {
        event.time = now();
        tracing::info!(group = %event.group, kind = event.kind, node = %event.node,
            target = %event.target, "[AutoSwitch]");
        let mut state = self.state.lock();
        if state.events.len() == 100 {
            state.events.pop_front();
        }
        state.events.push_back(event);
    }
}
