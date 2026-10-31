// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{bail, Result};
use fancy_regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "kebab-case")]
pub struct Settings {
    pub enable: bool,
    pub groups: Vec<String>,
    pub preferred_filter: String,
    pub failure_threshold: i64,
    pub expected_delay: i64,
    pub restore: bool,
    pub interval: i64,
    pub url: String,
    pub timeout: i64,
    pub expected_status: String,
    pub concurrency: i64,
}

impl Settings {
    pub fn normalized(mut self) -> Self {
        let mut seen = HashSet::new();
        self.groups = self
            .groups
            .into_iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty() && seen.insert(s.clone()))
            .collect();
        fn clamp(v: i64, default: i64, min: i64, max: i64) -> i64 {
            if v == 0 {
                default
            } else {
                v.clamp(min, max)
            }
        }
        self.failure_threshold = clamp(self.failure_threshold, 1, 1, 10);
        self.expected_delay = self.expected_delay.clamp(0, 99999);
        self.interval = clamp(self.interval, 30, 10, 3600);
        self.timeout = clamp(self.timeout, 5000, 1000, 30000);
        self.concurrency = clamp(self.concurrency, 5, 1, 32);
        self.url = self.url.trim().to_owned();
        if self.url.is_empty() {
            self.url = "https://www.gstatic.com/generate_204".into();
        }
        self
    }

    pub fn validate(&self) -> Result<()> {
        if !(0..=99999).contains(&self.expected_delay) {
            bail!("expected-delay must be between 0 and 99999 ms");
        }
        self.filter()?;
        self.status_ranges()?;
        if self.enable && self.clone().normalized().groups.is_empty() {
            bail!("at least one group is required");
        }
        Ok(())
    }

    pub fn filter(&self) -> Result<Option<Regex>> {
        if self.preferred_filter.is_empty() {
            return Ok(None);
        }
        // Supports the lookahead/lookbehind patterns used by META. Bound
        // backtracking on user-supplied expressions, as the Go checker does.
        Ok(Some(
            RegexBuilder::new(&self.preferred_filter)
                .backtrack_limit(100_000)
                .build()?,
        ))
    }

    /// Translate Mihomo's slash/comma ranges into meow's comma syntax.
    /// Mihomo's empty / '*' expression accepts any status, unlike meow's
    /// empty-expression default (2xx), so always pass explicit ranges.
    pub fn status_ranges(&self) -> Result<String> {
        let input = self.expected_status.trim();
        if input.is_empty() || input == "*" {
            return Ok("0-65535".into());
        }
        let parts: Vec<_> = input.split(['/', ',']).collect();
        if parts.len() > 28 {
            bail!("expected-status supports at most 28 ranges");
        }
        let mut ranges = Vec::new();
        for part in parts {
            if part.is_empty() {
                continue;
            }
            let part = part.trim();
            if part.is_empty() {
                ranges.push("0".into());
                continue;
            }
            let parse = |s: &str| -> Result<u16> { Ok(s.trim_matches(['[', ']', ' ']).parse()?) };
            if let Some((a, b)) = part.split_once('-') {
                let (a, b) = (parse(a)?, parse(b)?);
                ranges.push(format!("{}-{}", a.min(b), a.max(b)));
            } else {
                ranges.push(parse(part)?.to_string());
            }
        }
        Ok(if ranges.is_empty() {
            "0-65535".into()
        } else {
            ranges.join(",")
        })
    }
}
