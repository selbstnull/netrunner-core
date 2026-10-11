//! ICMP "port unreachable" for UDP flows the tunnel could not open.
//!
//! When the exit node cannot dial a UDP destination it closes the stream. The
//! local app, though, only sees silence: a QUIC client keeps retransmitting its
//! Initial until its own handshake timeout, and only then falls back to TCP,
//! which is the multi-second (sometimes minutes-long) stall users reported on
//! video that "does not load". A real network answers an unreachable UDP
//! destination with ICMP; this builds that answer so the app's stack reports
//! `ECONNREFUSED` straight away and the app falls back at once.

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, Icmpv6DstUnreachable, Icmpv6Packet,
    Icmpv6Repr, IpAddress, IpEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

const HOP_LIMIT: u8 = 64;

/// The UDP header of the datagram the app sent (ports, length 8, no checksum):
/// ICMP errors quote the offending IP header plus the first 8 payload bytes, and
/// the app's stack uses that quote to find the socket.
fn quoted_udp_header(app_port: u16, server_port: u16) -> [u8; 8] {
    let mut header = [0u8; 8];
    header[0..2].copy_from_slice(&app_port.to_be_bytes());
    header[2..4].copy_from_slice(&server_port.to_be_bytes());
    header[4..6].copy_from_slice(&8u16.to_be_bytes());
    header
}

/// An IP packet from `server` to `app` carrying ICMP(v6) "port unreachable" for
/// a UDP datagram `app` sent to `server`. `None` when the families differ.
pub fn udp_port_unreachable(app: IpEndpoint, server: IpEndpoint) -> Option<Vec<u8>> {
    let quote = quoted_udp_header(app.port, server.port);
    let caps = ChecksumCapabilities::default();
    match (app.addr, server.addr) {
        (IpAddress::Ipv4(app_ip), IpAddress::Ipv4(server_ip)) => {
            let icmp = Icmpv4Repr::DstUnreachable {
                reason: Icmpv4DstUnreachable::PortUnreachable,
                header: Ipv4Repr {
                    src_addr: app_ip,
                    dst_addr: server_ip,
                    next_header: IpProtocol::Udp,
                    payload_len: quote.len(),
                    hop_limit: HOP_LIMIT,
                },
                data: &quote,
            };
            let outer = Ipv4Repr {
                src_addr: server_ip,
                dst_addr: app_ip,
                next_header: IpProtocol::Icmp,
                payload_len: icmp.buffer_len(),
                hop_limit: HOP_LIMIT,
            };
            let ip_len = outer.buffer_len();
            let mut buf = vec![0u8; ip_len + icmp.buffer_len()];
            outer.emit(&mut Ipv4Packet::new_unchecked(&mut buf[..]), &caps);
            icmp.emit(&mut Icmpv4Packet::new_unchecked(&mut buf[ip_len..]), &caps);
            Some(buf)
        }
        (IpAddress::Ipv6(app_ip), IpAddress::Ipv6(server_ip)) => {
            let icmp = Icmpv6Repr::DstUnreachable {
                reason: Icmpv6DstUnreachable::PortUnreachable,
                header: Ipv6Repr {
                    src_addr: app_ip,
                    dst_addr: server_ip,
                    next_header: IpProtocol::Udp,
                    payload_len: quote.len(),
                    hop_limit: HOP_LIMIT,
                },
                data: &quote,
            };
            let outer = Ipv6Repr {
                src_addr: server_ip,
                dst_addr: app_ip,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp.buffer_len(),
                hop_limit: HOP_LIMIT,
            };
            let ip_len = outer.buffer_len();
            let mut buf = vec![0u8; ip_len + icmp.buffer_len()];
            outer.emit(&mut Ipv6Packet::new_unchecked(&mut buf[..]));
            icmp.emit(
                &server_ip,
                &app_ip,
                &mut Icmpv6Packet::new_unchecked(&mut buf[ip_len..]),
                &caps,
            );
            Some(buf)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{Ipv4Address, Ipv6Address};

    #[test]
    fn v4_error_quotes_the_apps_datagram_and_is_addressed_to_the_app() {
        let app = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 51000);
        let server = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(157, 240, 1, 1)), 443);
        let packet = udp_port_unreachable(app, server).expect("v4/v4");

        let ip = Ipv4Packet::new_checked(&packet[..]).expect("valid IPv4");
        assert_eq!(ip.src_addr(), Ipv4Address::new(157, 240, 1, 1));
        assert_eq!(ip.dst_addr(), Ipv4Address::new(10, 0, 0, 2));
        assert_eq!(ip.next_header(), IpProtocol::Icmp);
        assert!(ip.verify_checksum());

        let icmp = Icmpv4Packet::new_checked(ip.payload()).expect("valid ICMP");
        assert!(icmp.verify_checksum());
        let repr = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::default()).expect("parse");
        match repr {
            Icmpv4Repr::DstUnreachable { reason, header, data } => {
                assert_eq!(reason, Icmpv4DstUnreachable::PortUnreachable);
                assert_eq!(header.src_addr, Ipv4Address::new(10, 0, 0, 2));
                assert_eq!(header.dst_addr, Ipv4Address::new(157, 240, 1, 1));
                assert_eq!(header.next_header, IpProtocol::Udp);
                assert_eq!(&data[0..2], &51000u16.to_be_bytes());
                assert_eq!(&data[2..4], &443u16.to_be_bytes());
            }
            other => panic!("expected DstUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn v6_error_is_a_valid_icmpv6_port_unreachable() {
        let app = IpEndpoint::new(IpAddress::Ipv6(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)), 40000);
        let server =
            IpEndpoint::new(IpAddress::Ipv6(Ipv6Address::new(0x2a03, 0x2880, 0, 0, 0, 0, 0, 1)), 443);
        let packet = udp_port_unreachable(app, server).expect("v6/v6");

        let ip = Ipv6Packet::new_checked(&packet[..]).expect("valid IPv6");
        assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
        let icmp = Icmpv6Packet::new_checked(ip.payload()).expect("valid ICMPv6");
        assert!(icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
    }

    #[test]
    fn mixed_families_produce_nothing() {
        let app = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)), 1);
        let server = IpEndpoint::new(IpAddress::Ipv6(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1)), 2);
        assert!(udp_port_unreachable(app, server).is_none());
    }
}
