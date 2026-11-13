// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use std::{
    fs,
    net::{IpAddr, SocketAddr},
};

// Called only for a local source on the standalone ROOT path. Never attribute
// a bridge's own socket or an ambiguous SO_REUSEPORT group to an application.
pub(super) fn lookup(udp: bool, source: SocketAddr, destination: SocketAddr) -> Option<u32> {
    let network = if udp { "udp" } else { "tcp" };
    let mut owner = None;
    for suffix in ["", "6"] {
        let Ok(table) = fs::read_to_string(format!("/proc/net/{network}{suffix}")) else {
            continue;
        };
        let uid = scan(&table, udp, source, destination).ok()?;
        if let Some(uid) = uid {
            if owner.is_some_and(|previous| previous != uid) {
                return None;
            }
            owner = Some(uid);
        }
    }
    owner
}

fn scan(
    table: &str,
    udp: bool,
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<Option<u32>, ()> {
    let source = SocketAddr::new(source.ip().to_canonical(), source.port());
    let destination = SocketAddr::new(destination.ip().to_canonical(), destination.port());
    let mut owner = None;
    for line in table.lines() {
        let mut fields = line.split_whitespace();
        let _ = fields.next();
        let Some(local) = fields.next().and_then(address) else {
            continue;
        };
        let Some(remote) = fields.next().and_then(address) else {
            continue;
        };
        if local.port() != source.port()
            || (local.ip().to_canonical() != source.ip().to_canonical()
                && !(udp && local.ip().is_unspecified()))
            || (remote != destination
                && !(udp && remote.ip().is_unspecified() && remote.port() == 0))
        {
            continue;
        }
        // After the remote endpoint: state, tx/rx queue, timer, retransmits, UID.
        let Some(uid) = fields.nth(4).and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        if owner.is_some_and(|previous| previous != uid) {
            return Err(());
        }
        owner = Some(uid);
    }
    Ok(owner)
}

fn address(value: &str) -> Option<SocketAddr> {
    let (ip, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let mut bytes = [0; 16];
    let width = match ip.len() {
        8 => 4,
        32 => 16,
        _ => return None,
    };
    for offset in (0..width).step_by(4) {
        let word = u32::from_str_radix(&ip[2 * offset..2 * offset + 8], 16).ok()?;
        bytes[offset..offset + 4].copy_from_slice(&word.to_ne_bytes());
    }
    let ip = if width == 4 {
        IpAddr::from(<[u8; 4]>::try_from(&bytes[..4]).ok()?)
    } else {
        IpAddr::from(bytes).to_canonical()
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_tuple_and_ambiguous_udp() {
        let source = "127.0.0.1:35000".parse().unwrap();
        let destination = "198.18.0.9:443".parse().unwrap();
        let wrong = "0: 0100007F:88B8 090012C6:01BA 01 0:0 0:0 0 10001\n";
        let correct = "1: 0100007F:88B8 090012C6:01BB 01 0:0 0:0 0 1012345\n";
        assert_eq!(scan(wrong, false, source, destination), Ok(None));
        assert_eq!(
            scan(&format!("{wrong}{correct}"), false, source, destination),
            Ok(Some(1012345))
        );
        let wildcard = "0: 00000000:88B8 00000000:0000 07 0:0 0:0 0 1012345\n";
        assert_eq!(scan(wildcard, true, source, destination), Ok(Some(1012345)));
        let ambiguous = format!("{wildcard}{}", wildcard.replace("1012345", "1012346"));
        assert_eq!(scan(&ambiguous, true, source, destination), Err(()));
        assert_eq!(
            address("00000000000000000000000001000000:88B8"),
            Some("[::1]:35000".parse().unwrap())
        );
    }
}
