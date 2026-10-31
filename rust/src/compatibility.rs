// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//! Diagnostics for accepted Mihomo options whose semantics meow does not implement.
use fancy_regex::Regex;
use serde::Serialize;
use serde_yaml::Value;

#[derive(Serialize)]
pub struct Diagnostic {
    code: &'static str,
    field: String,
    message: &'static str,
}

fn warning(out: &mut Vec<Diagnostic>, field: &str, message: &'static str) {
    out.push(Diagnostic {
        code: "IGNORED_OPTION",
        field: field.into(),
        message,
    });
}

pub fn normalize(value: &mut Value) -> Vec<Diagnostic> {
    let mut result = Vec::new();
    for (section, keys) in [
        (
            "",
            &[
                "geodata-mode",
                "geodata-loader",
                "geoip-matcher",
                "unified-delay",
                "tcp-concurrent",
            ][..],
        ),
        (
            "geodata",
            &["geodata-mode", "geodata-loader", "geoip-matcher"][..],
        ),
        (
            "dns",
            &[
                "direct-nameserver",
                "direct-nameserver-follow-policy",
                "respect-rules",
                "prefer-h3",
            ][..],
        ),
        (
            "tun",
            &[
                "stack",
                "strict-route",
                "auto-detect-interface",
                "auto-redirect",
                "endpoint-independent-nat",
                "mtu-v6",
                "route-address",
                "route-exclude-address",
                "include-uid",
                "exclude-uid",
            ][..],
        ),
    ] {
        let object = if section.is_empty() {
            value.as_mapping_mut()
        } else {
            value.get_mut(section).and_then(Value::as_mapping_mut)
        };
        if let Some(object) = object {
            for key in keys {
                if object
                    .remove(Value::from(*key))
                    .is_some_and(|v| !v.is_null())
                {
                    let field = if section.is_empty() {
                        (*key).into()
                    } else {
                        format!("{section}.{key}")
                    };
                    warning(
                        &mut result,
                        &field,
                        "Option is ignored; meow keeps its existing behavior",
                    );
                }
            }
        }
    }
    if let Some(android) = value
        .get_mut("clash-for-android")
        .and_then(Value::as_mapping_mut)
    {
        if let Some(pattern) = android.get("ui-subtitle-pattern").filter(|v| !v.is_null()) {
            if pattern.as_str().is_none_or(|p| subtitle_regex(p).is_err()) {
                warning(
                    &mut result,
                    "clash-for-android.ui-subtitle-pattern",
                    "Invalid or unsupported pattern; proxy names remain unchanged",
                );
                android.remove("ui-subtitle-pattern");
            }
        }
    }
    result
}

pub fn log(diagnostics: &[Diagnostic]) {
    for d in diagnostics {
        tracing::warn!(field = %d.field, code = d.code, "{}", d.message);
    }
}

fn subtitle_regex(pattern: &str) -> Result<Regex, fancy_regex::Error> {
    Regex::new(&format!("(?i:{pattern})"))
}

pub fn format_proxies(pattern: &str, mut proxies: serde_json::Value) -> serde_json::Value {
    let regex = (!pattern.is_empty())
        .then(|| subtitle_regex(pattern).ok())
        .flatten();
    if let Some(proxies) = proxies.as_array_mut() {
        for proxy in proxies {
            let name = proxy["name"].as_str().unwrap_or("");
            let mut title = name.to_owned();
            let mut subtitle = proxy["type"].as_str().unwrap_or("").to_owned();
            if proxy.get("all").is_none() && proxy["isGroup"] != true {
                if let Some(regex) = &regex {
                    if let Ok(Some(m)) = regex.find(name) {
                        title = format!("{}{}", &name[..m.start()], &name[m.end()..]);
                        subtitle = m.as_str().to_owned();
                    }
                }
            }
            proxy["title"] = title.trim().into();
            proxy["subtitle"] = subtitle.trim().into();
        }
    }
    proxies
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_subtitles_groups_and_invalid_patterns() {
        let proxies = serde_json::json!([
            {"name":" 🇭🇰 hk | 01 ","type":"Shadowsocks"},
            {"name":" HK group ","type":"Selector","all":["DIRECT"]}
        ]);
        let result = format_proxies(r"(?<=🇭🇰 )HK \|", proxies.clone());
        assert_eq!(result[0]["title"], "🇭🇰  01");
        assert_eq!(result[0]["subtitle"], "hk |");
        assert_eq!(result[1]["title"], "HK group");
        assert_eq!(result[1]["subtitle"], "Selector");
        assert_eq!(format_proxies("(", proxies)[0]["subtitle"], "Shadowsocks");
    }
}
