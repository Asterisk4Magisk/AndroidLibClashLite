// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use meow_common::{Rule, RuleType, TunnelMode};
use parking_lot::RwLock;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Weak,
};

static MODE: AtomicU8 = AtomicU8::new(1);
type Rules = Vec<Box<dyn Rule>>;
static RULES: RwLock<Option<(Weak<Rules>, bool)>> = RwLock::new(None);

pub(super) fn configure(mode: &str) {
    MODE.store(
        match mode {
            "off" => 0,
            "always" => 2,
            _ => 1,
        },
        Ordering::Relaxed,
    );
}

pub(super) fn needed(inner: &meow_tunnel::tunnel::TunnelInner) -> bool {
    match MODE.load(Ordering::Relaxed) {
        0 => return false,
        2 => return true,
        _ => {}
    }
    if !matches!(*inner.mode.read(), TunnelMode::Rule) {
        return false;
    }
    let rules = Arc::clone(&inner.route.read().rules);
    if let Some((previous, needed)) = &*RULES.read() {
        if previous
            .upgrade()
            .is_some_and(|previous| Arc::ptr_eq(&previous, &rules))
        {
            return *needed;
        }
    }
    // Providers and compound rules may change their process requirements
    // without replacing the route. Conservatively enrich those flows.
    let needed = rules.iter().any(|rule| {
        matches!(
            rule.rule_type(),
            RuleType::ProcessName
                | RuleType::ProcessPath
                | RuleType::Uid
                | RuleType::RuleSet
                | RuleType::And
                | RuleType::Or
                | RuleType::Not
                | RuleType::SubRule
        )
    });
    *RULES.write() = Some((Arc::downgrade(&rules), needed));
    needed
}
