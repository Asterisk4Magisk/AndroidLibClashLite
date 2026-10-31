// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//! The Android profile contract shared by the compatibility facade and CLI.
use anyhow::{Context, Result};
use md5::{Digest, Md5};
use serde_yaml::Value;
use std::{io::Read, path::Path};

static AGE_KEYS: parking_lot::RwLock<String> = parking_lot::RwLock::new(String::new());
pub fn set_keys(keys: &str) {
    *AGE_KEYS.write() = keys.to_owned();
}
pub fn valid_keys(keys: &str) -> bool {
    age::IdentityFile::from_buffer(keys.as_bytes())
        .and_then(|f| f.into_identities().map_err(std::io::Error::other))
        .is_ok()
}
pub fn decrypt(bytes: &[u8], keys: &str) -> Result<Vec<u8>> {
    if !bytes.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
        && !bytes.starts_with(b"age-encryption.org/v1")
    {
        return Ok(bytes.to_vec());
    }
    let combined = format!("{keys}\n{}", AGE_KEYS.read());
    let identities = age::IdentityFile::from_buffer(combined.as_bytes())?.into_identities()?;
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(bytes))?;
    let mut reader = decryptor.decrypt(
        identities
            .iter()
            .map(|key| key.as_ref() as &dyn age::Identity),
    )?;
    let mut clear = Vec::new();
    reader.read_to_end(&mut clear)?;
    Ok(clear)
}

pub fn decode(bytes: &[u8]) -> Result<Value> {
    let (value, diagnostics) = decode_with_diagnostics(bytes)?;
    crate::compatibility::log(&diagnostics);
    Ok(value)
}

pub fn decode_with_diagnostics(
    bytes: &[u8],
) -> Result<(Value, Vec<crate::compatibility::Diagnostic>)> {
    let bytes = decrypt(bytes, "")?;
    let mut value: Value =
        serde_yaml::from_str(std::str::from_utf8(&bytes)?.trim_start_matches('\u{feff}'))?;
    value.apply_merge()?;
    anyhow::ensure!(value.is_mapping(), "configuration must be a YAML mapping");
    if let Some(store) = value
        .get("profile")
        .and_then(|p| p.get("store-fake-ip"))
        .cloned()
    {
        object(&mut value, "dns")
            .as_mapping_mut()
            .unwrap()
            .entry("store-fake-ip".into())
            .or_insert(store);
    }
    if let Some(urls) = value.get("geox-url").cloned() {
        let target = object(object(&mut value, "geodata"), "url");
        for key in ["mmdb", "asn", "geosite"] {
            if let Some(url) = urls.get(key) {
                target
                    .as_mapping_mut()
                    .unwrap()
                    .entry(key.into())
                    .or_insert(url.clone());
            }
        }
    }
    for (old, new) in [
        ("geo-auto-update", "auto-update"),
        ("geo-update-interval", "auto-update-interval"),
    ] {
        if let Some(v) = value.get(old).cloned() {
            object(&mut value, "geodata")
                .as_mapping_mut()
                .unwrap()
                .entry(new.into())
                .or_insert(v);
        }
    }
    let diagnostics = crate::compatibility::normalize(&mut value);
    Ok((value, diagnostics))
}
fn object<'a>(value: &'a mut Value, key: &str) -> &'a mut Value {
    let entry = value
        .as_mapping_mut()
        .unwrap()
        .entry(key.into())
        .or_insert(Value::Mapping(Default::default()));
    if !entry.is_mapping() {
        *entry = Value::Mapping(Default::default());
    }
    entry
}
fn merge(target: &mut Value, patch: Value) {
    if let (Some(target), Some(patch)) = (target.as_mapping_mut(), patch.as_mapping()) {
        for (key, value) in patch {
            if value.is_null() {
                continue;
            }
            match target.get_mut(key) {
                Some(old) if old.is_mapping() && value.is_mapping() => merge(old, value.clone()),
                _ => {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
    }
}
pub fn prepare(
    bytes: &[u8],
    base: &Path,
    home: &Path,
    persist: &str,
    session: &str,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        base.is_absolute() && home.is_absolute(),
        "profile and home paths must be absolute"
    );
    let mut value = decode(bytes)?;
    let profile_mode = value
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("rule")
        .to_owned();
    let profile_log = value
        .get("log-level")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_owned();
    value["external-controller"] = Value::Null;
    value["external-controller-tls"] = Value::Null;
    merge(&mut value, serde_yaml::from_str(persist)?);
    merge(&mut value, serde_yaml::from_str(session)?);
    value = decode(serde_yaml::to_string(&value)?.as_bytes())?;
    value["interface-name"] = "".into();
    value["routing-mark"] = 0.into();
    object(&mut value, "tun")["enable"] = false.into();
    if let Some(listeners) = value.get_mut("listeners").and_then(Value::as_sequence_mut) {
        listeners.retain(|v| {
            !matches!(
                v.get("type").and_then(Value::as_str),
                Some("tun" | "tproxy" | "redir")
            )
        });
    }
    let append = value
        .get("clash-for-android")
        .and_then(|v| v.get("append-system-dns"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let dns = object(&mut value, "dns");
    let default_dns = dns.get("enable").and_then(Value::as_bool) != Some(true);
    if default_dns {
        *dns = serde_yaml::from_str(include_str!("../resources/android-default-dns.yaml"))?;
    }
    dns["store-fake-ip"] = true.into();
    if append || default_dns {
        let servers = dns
            .as_mapping_mut()
            .unwrap()
            .entry("nameserver".into())
            .or_insert(Value::Sequence(Vec::new()));
        let servers = servers
            .as_sequence_mut()
            .context("dns.nameserver must be a list")?;
        if !servers.iter().any(|v| v.as_str() == Some("system://")) {
            servers.push("system://".into());
        }
    }
    // Use real files in the shared home; never reinterpret GeoIP.dat as MMDB.
    for (key, files) in [
        ("mmdb-path", &["Country.mmdb", "country.mmdb"][..]),
        ("asn-path", &["ASN.mmdb", "GeoLite2-ASN.mmdb"][..]),
        ("geosite-path", &["GeoSite.dat", "geosite.dat"][..]),
    ] {
        let geo = object(&mut value, "geodata");
        if geo.get(key).is_none() {
            if let Some(file) = files
                .iter()
                .map(|name| home.join(name))
                .find(|p| p.is_file())
            {
                geo[key] = file.to_string_lossy().to_string().into();
            }
        }
    }
    let mut providers = Vec::new();
    for (kind, prefix) in [("proxy-providers", "proxies"), ("rule-providers", "rules")] {
        if let Some(entries) = value.get_mut(kind).and_then(Value::as_mapping_mut) {
            for (name, entry) in entries {
                let url = entry
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let original = entry.get("path").and_then(Value::as_str).unwrap_or("");
                if original.is_empty() && url.is_empty() {
                    continue;
                }
                let relative = if original.is_empty() {
                    // Stable filename; the same normalizer is used by fetch and load.
                    format!("{prefix}/{:x}", Md5::digest(url.as_bytes()))
                } else {
                    let normalized = original.replace('\\', "/");
                    let mut parts = Vec::new();
                    for part in normalized.split('/') {
                        match part {
                            "" | "." => {}
                            ".." => {
                                parts.pop();
                            }
                            _ => parts.push(part),
                        }
                    }
                    parts.join("/")
                };
                let path = base.join("providers").join(relative);
                entry["path"] = path.to_string_lossy().to_string().into();
                providers.push(
                    serde_json::json!({"name":name.as_str().unwrap_or(""), "url":url,"path":path,"kind":prefix}),
                );
            }
        }
    }
    Ok(
        serde_json::json!({"yaml":serde_yaml::to_string(&value)?,"providers":providers,"profileMode":profile_mode,"profileLogLevel":profile_log,
            "subtitlePattern":value.get("clash-for-android").and_then(|v| v.get("ui-subtitle-pattern")).and_then(Value::as_str).unwrap_or("")}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn age_roundtrip_wrong_key_and_plaintext() {
        let key = age::x25519::Identity::generate();
        let recipient = key.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .unwrap();
        let mut encrypted = Vec::new();
        let armor =
            age::armor::ArmoredWriter::wrap_output(&mut encrypted, age::armor::Format::AsciiArmor)
                .unwrap();
        let mut writer = encryptor.wrap_output(armor).unwrap();
        writer.write_all(b"mode: direct\n").unwrap();
        writer.finish().unwrap().finish().unwrap();
        use age::secrecy::ExposeSecret;
        let keys = format!("# profile key\n{}\n", key.to_string().expose_secret());
        assert!(valid_keys(&keys));
        assert!(valid_keys(""));
        assert!(!valid_keys("not a key"));
        assert_eq!(decrypt(&encrypted, &keys).unwrap(), b"mode: direct\n");
        assert!(decrypt(&encrypted, "").is_err());
        assert_eq!(
            decrypt(b"mode: direct", "bad key").unwrap(),
            b"mode: direct"
        );
    }
    #[test]
    fn android_profile_overrides_providers_and_dns_mapping() {
        let directory = tempfile::tempdir().unwrap();
        let raw = b"mode: rule\nprofile: {store-fake-ip: false}\ngeox-url: {mmdb: 'https://geo.test/country.mmdb', geosite: 'https://geo.test/geosite.dat'}\nproxy-providers: {remote: {type: http, url: 'https://sub.test/nodes', path: '../outside/nodes.yaml'}}\ntun: {enable: true}\n";
        let mapped = decode(raw).unwrap();
        assert_eq!(mapped["dns"]["store-fake-ip"], false);
        assert_eq!(
            mapped["geodata"]["url"]["mmdb"].as_str().unwrap(),
            "https://geo.test/country.mmdb"
        );
        let result = prepare(
            raw,
            directory.path(),
            directory.path(),
            r#"{"mode":"direct","dns":{"enable":true,"nameserver":["1.1.1.1"]}}"#,
            r#"{"mode":"global","clash-for-android":{"append-system-dns":true}}"#,
        )
        .unwrap();
        let value: Value = serde_yaml::from_str(result["yaml"].as_str().unwrap()).unwrap();
        assert_eq!(value["mode"], "global");
        assert_eq!(value["tun"]["enable"], false);
        assert_eq!(value["dns"]["nameserver"][1], "system://");
        assert_eq!(value["dns"]["store-fake-ip"], true);
        assert!(Path::new(result["providers"][0]["path"].as_str().unwrap())
            .starts_with(directory.path().join("providers")));
        let defaults = prepare(
            b"mode: rule\n",
            directory.path(),
            directory.path(),
            "{}",
            "{}",
        )
        .unwrap();
        let defaults: Value = serde_yaml::from_str(defaults["yaml"].as_str().unwrap()).unwrap();
        assert_eq!(defaults["dns"]["fake-ip-range"], "28.0.0.0/8");
        assert_eq!(
            defaults["dns"]["nameserver"].as_sequence().unwrap().len(),
            5
        );
        assert!(defaults["dns"]["fake-ip-filter"]
            .as_sequence()
            .unwrap()
            .contains(&"WORKGROUP".into()));
    }
}
