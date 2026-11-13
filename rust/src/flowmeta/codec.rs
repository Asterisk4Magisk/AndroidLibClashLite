// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use subtle::ConstantTimeEq;

const SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct Header {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub udp: bool,
    pub uid: Option<u32>,
}

pub(super) fn parse(b: &[u8], token: &str, udp: bool) -> Result<(Header, usize)> {
    if b.len() < 16 || &b[..12] != SIGNATURE || b[12] != 0x21 {
        bail!("invalid flow header")
    }
    let (width, n) = match b[13] >> 4 {
        1 => (4, 12),
        2 => (16, 36),
        _ => bail!("invalid flow address family"),
    };
    if b[13] & 15 != (if udp { 2 } else { 1 })
        || u16::from_be_bytes([b[14], b[15]]) as usize != n + 40
        || b.len() < 16 + n + 40
    {
        bail!("invalid flow length or protocol")
    }
    let t = &b[16 + n..16 + n + 40];
    if t[..4] != [0xe0, 0, 37, 1]
        || token.len() != 32
        || !bool::from(t[4..36].ct_eq(token.as_bytes()))
    {
        bail!("invalid flow credential")
    }
    let ip = |offset| -> IpAddr {
        if width == 4 {
            Ipv4Addr::from(<[u8; 4]>::try_from(&b[offset..offset + 4]).unwrap()).into()
        } else {
            Ipv6Addr::from(<[u8; 16]>::try_from(&b[offset..offset + 16]).unwrap()).into()
        }
    };
    let source = SocketAddr::new(ip(16), u16::from_be_bytes([b[16 + n - 4], b[16 + n - 3]]));
    let destination = SocketAddr::new(
        ip(16 + width),
        u16::from_be_bytes([b[16 + n - 2], b[16 + n - 1]]),
    );
    if source.port() == 0 || destination.port() == 0 {
        bail!("invalid flow port")
    }
    let uid = u32::from_be_bytes(t[36..40].try_into()?);
    Ok((
        Header {
            source,
            destination,
            udp,
            uid: (uid != u32::MAX).then_some(uid),
        },
        16 + n + 40,
    ))
}

pub(super) fn encode_into(h: Header, token: &str, b: &mut Vec<u8>) -> Result<()> {
    if token.len() != 32 || h.source.is_ipv4() != h.destination.is_ipv4() {
        bail!("invalid flow credential or address family");
    }
    let width = if h.source.is_ipv4() { 4 } else { 16 };
    let n = width * 2 + 4;
    b.clear();
    b.resize(16 + n + 40, 0);
    b[..12].copy_from_slice(SIGNATURE);
    b[12] = 0x21;
    b[13] = (if width == 4 { 0x10 } else { 0x20 }) | if h.udp { 2 } else { 1 };
    b[15] = (n + 40) as u8;
    for (index, addr) in [h.source, h.destination].iter().enumerate() {
        let target = &mut b[16 + index * width..16 + (index + 1) * width];
        match addr.ip() {
            IpAddr::V4(ip) => target.copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => target.copy_from_slice(&ip.octets()),
        }
    }
    b[16 + n - 4..16 + n - 2].copy_from_slice(&h.source.port().to_be_bytes());
    b[16 + n - 2..16 + n].copy_from_slice(&h.destination.port().to_be_bytes());
    let t = &mut b[16 + n..];
    t[..4].copy_from_slice(&[0xe0, 0, 37, 1]);
    t[4..36].copy_from_slice(token.as_bytes());
    t[36..40].copy_from_slice(&h.uid.unwrap_or(u32::MAX).to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_vector() {
        let h = Header {
            source: "172.19.0.1:35000".parse().unwrap(),
            destination: "198.18.0.9:443".parse().unwrap(),
            udp: true,
            uid: Some(1012345),
        };
        let token = "0123456789abcdef0123456789abcdef";
        let mut b = Vec::new();
        encode_into(h, token, &mut b).unwrap();
        assert_eq!(parse(&b, token, true).unwrap(), (h, 68));
        assert_eq!(b.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "0d0a0d0a000d0a515549540a21120034ac130001c612000988b801bbe00025013031323334353637383961626364656630313233343536373839616263646566000f7279");
        assert!(parse(&b, "ffffffffffffffffffffffffffffffff", true).is_err());
        assert!(parse(&b, token, false).is_err());
        for n in 0..b.len() {
            assert!(parse(&b[..n], token, true).is_err());
        }
        let ipv6 = Header {
            source: "[2001:db8::9]:443".parse().unwrap(),
            destination: "[fdfe:dcba::1]:35000".parse().unwrap(),
            ..h
        };
        encode_into(ipv6, token, &mut b).unwrap();
        assert_eq!(parse(&b, token, true).unwrap(), (ipv6, 92));
    }
}
