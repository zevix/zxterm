//! A minimal STUN client (RFC 8489 Binding only) for server-reflexive ICE
//! candidates (K10, `D-11`, `X-10`): `super::rtc` sends a Binding Request
//! from each connection's socket to every `stun:` server of its ICE list and
//! turns the `XOR-MAPPED-ADDRESS` of the answer into a `srflx` candidate.
//! This closes K6's host-candidates-only gap for peers behind a NAT; TURN
//! (relayed candidates) is not implemented, so `describe()` never claims
//! `RELAY` from this core (`index.js::hasTurnServer` would, given a
//! `turn:` URL; `super::backend` reports it as ignored).
//!
//! Also here: [`primary_ipv4`], the local address of the interface the
//! default route leaves by, found without sending a packet (a UDP
//! `connect` only selects a route), so a connection can offer a host
//! candidate other peers on the LAN, and a STUN server, can reach.
//!
//! Tests never reach a public STUN server: they answer with a local
//! responder ([`binding_success`] builds its reply).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// RFC 8489 §5: the magic cookie.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Binding Request.
pub const BINDING_REQUEST: u16 = 0x0001;
/// Binding Success Response.
pub const BINDING_SUCCESS: u16 = 0x0101;
/// `MAPPED-ADDRESS`.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// `XOR-MAPPED-ADDRESS`.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// The STUN header: type, length, cookie, 12-byte transaction id.
pub const HEADER_BYTES: usize = 20;

/// A 12-byte STUN transaction id.
pub type TransactionId = [u8; 12];

/// A fresh random transaction id.
pub fn new_transaction_id() -> TransactionId {
    use crypto_secretbox::aead::rand_core::RngCore;
    let mut id = [0u8; 12];
    crypto_secretbox::aead::OsRng.fill_bytes(&mut id);
    id
}

/// A Binding Request with no attributes.
pub fn binding_request(id: &TransactionId) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES);
    out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(id);
    out
}

/// The type and transaction id of a STUN message, or `None` for anything
/// that is not one (RFC 8489 §5: top two bits zero, the magic cookie, a
/// length that is a multiple of 4 and fits).
pub fn header(packet: &[u8]) -> Option<(u16, TransactionId)> {
    if packet.len() < HEADER_BYTES || packet[0] & 0xC0 != 0 {
        return None;
    }
    let kind = u16::from_be_bytes([packet[0], packet[1]]);
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    if cookie != MAGIC_COOKIE || !len.is_multiple_of(4) || HEADER_BYTES + len > packet.len() {
        return None;
    }
    let mut id = [0u8; 12];
    id.copy_from_slice(&packet[8..20]);
    Some((kind, id))
}

/// The mapped address of a Binding Success Response to transaction `id`:
/// `XOR-MAPPED-ADDRESS`, else `MAPPED-ADDRESS`. `None` for any other
/// packet, or one naming no IPv4/IPv6 address.
pub fn mapped_address(packet: &[u8], id: &TransactionId) -> Option<SocketAddr> {
    let (kind, tid) = header(packet)?;
    if kind != BINDING_SUCCESS || &tid != id {
        return None;
    }
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let body = &packet[HEADER_BYTES..HEADER_BYTES + len];
    let mut plain = None;
    let mut at = 0;
    while at + 4 <= body.len() {
        let attr = u16::from_be_bytes([body[at], body[at + 1]]);
        let alen = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        let start = at + 4;
        let end = start + alen;
        if end > body.len() {
            return None;
        }
        let value = &body[start..end];
        match attr {
            ATTR_XOR_MAPPED_ADDRESS => return parse_address(value, Some(id)),
            ATTR_MAPPED_ADDRESS => plain = parse_address(value, None),
            _ => {}
        }
        at = end + (4 - alen % 4) % 4;
    }
    plain
}

/// An `(XOR-)MAPPED-ADDRESS` value: reserved byte, family, port, address.
fn parse_address(value: &[u8], xor_id: Option<&TransactionId>) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    if xor_id.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    match family {
        0x01 if value.len() >= 8 => {
            let mut ip = [value[4], value[5], value[6], value[7]];
            if xor_id.is_some() {
                for (b, c) in ip.iter_mut().zip(cookie.iter()) {
                    *b ^= c;
                }
            }
            Some(SocketAddr::new(IpAddr::from(ip), port))
        }
        0x02 if value.len() >= 20 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[4..20]);
            if let Some(id) = xor_id {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&cookie);
                mask[4..].copy_from_slice(id);
                for (b, m) in ip.iter_mut().zip(mask.iter()) {
                    *b ^= m;
                }
            }
            Some(SocketAddr::new(IpAddr::from(ip), port))
        }
        _ => None,
    }
}

/// A Binding Success Response to `id` carrying `mapped` as
/// `XOR-MAPPED-ADDRESS` (IPv4 only): what a STUN server answers, for tests'
/// local responders.
pub fn binding_success(id: &TransactionId, mapped: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(v4) = mapped else {
        panic!("binding_success: IPv4 only");
    };
    let mut out = Vec::with_capacity(HEADER_BYTES + 12);
    out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(0);
    out.push(0x01);
    out.extend_from_slice(&(v4.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    let cookie = MAGIC_COOKIE.to_be_bytes();
    for (b, c) in v4.ip().octets().iter().zip(cookie.iter()) {
        out.push(b ^ c);
    }
    out
}

/// A `stun:`/`stuns:` ICE URL's `host:port` (default port 3478), or `None`
/// for any other scheme (`turn:`, …). `stuns:` (STUN over TLS) is not
/// spoken here and is skipped like a TURN URL.
pub fn stun_target(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("stun:")?;
    let rest = rest.split('?').next().unwrap_or(rest);
    if let Some(v6) = rest.strip_prefix('[') {
        let (host, tail) = v6.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => 3478,
        };
        return Some((host.to_string(), port));
    }
    match rest.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((rest.to_string(), 3478)),
    }
}

/// The IPv4 address of the interface the default route leaves by, or
/// `None` (no route, or only loopback). No packet is sent: a UDP `connect`
/// to a documentation address (RFC 5737 TEST-NET-1) only selects a route.
pub fn primary_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() => {
            Some(ip)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_request_is_a_bare_header() {
        let id = [7u8; 12];
        let req = binding_request(&id);
        assert_eq!(req.len(), HEADER_BYTES);
        assert_eq!(header(&req), Some((BINDING_REQUEST, id)));
    }

    #[test]
    fn xor_mapped_address_round_trips() {
        let id = new_transaction_id();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let resp = binding_success(&id, mapped);
        assert_eq!(mapped_address(&resp, &id), Some(mapped));
        // Another transaction's answer is not ours.
        assert_eq!(mapped_address(&resp, &[0u8; 12]), None);
    }

    /// RFC 5769 §2.2's sample IPv4 response (192.0.2.1:32853), fingerprint
    /// and integrity attributes included: they are skipped.
    #[test]
    fn rfc5769_sample_ipv4_response() {
        let hexstr = "0101003c2112a442b7e7a701bc34d686fa87dfae\
                      8022000b7465737420766563746f7220\
                      002000080001a147e112a643\
                      000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7\
                      80280004c07d4c96";
        let packet = hex::decode(hexstr).unwrap();
        let mut id = [0u8; 12];
        id.copy_from_slice(&packet[8..20]);
        assert_eq!(
            mapped_address(&packet, &id),
            Some("192.0.2.1:32853".parse().unwrap())
        );
    }

    #[test]
    fn non_stun_packets_are_not_headers() {
        assert_eq!(header(&[0u8; 10]), None);
        let mut dtls = vec![0x16u8; 40];
        dtls[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        assert_eq!(header(&dtls), None, "top bits set");
    }

    #[test]
    fn stun_target_parses_ice_urls() {
        assert_eq!(
            stun_target("stun:stun.l.google.com:19302"),
            Some(("stun.l.google.com".into(), 19302))
        );
        assert_eq!(
            stun_target("stun:127.0.0.1"),
            Some(("127.0.0.1".into(), 3478))
        );
        assert_eq!(stun_target("stun:[::1]:5000"), Some(("::1".into(), 5000)));
        assert_eq!(stun_target("turn:user:pw@turn.example:3478"), None);
        assert_eq!(stun_target("stuns:stun.example:5349"), None);
    }
}
