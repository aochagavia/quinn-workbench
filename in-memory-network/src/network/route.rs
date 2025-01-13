use crate::network::ip::Ipv4Cidr;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[derive(Clone)]
pub struct Route {
    pub destination: IpRange,
    pub next: IpAddr,
}

impl Route {
    pub(crate) fn next_hop_towards_destination(&self, ip: IpAddr) -> Option<IpAddr> {
        if (self.destination.start..=self.destination.end_inclusive).contains(&ip) {
            Some(self.next)
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct IpRange {
    pub start: IpAddr,
    pub end_inclusive: IpAddr,
}

impl IpRange {
    pub fn from_cidr(addr: Ipv4Cidr) -> Self {
        let base_ip_bits = addr.address.to_bits();
        let mask: u32 = u32::MAX << (32 - addr.network_prefix);
        let start = Ipv4Addr::from_bits(base_ip_bits & mask);
        let end_inclusive = Ipv4Addr::from_bits(base_ip_bits | (!mask));

        Self {
            start: IpAddr::V4(start),
            end_inclusive: IpAddr::V4(end_inclusive),
        }
    }
}

impl FromStr for IpRange {
    type Err = anyhow::Error;

    // Parse ranges in CIDR syntax (e.g. 10.0.0.0/24)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = Ipv4Cidr::from_str(s)?;
        Ok(Self::from_cidr(addr))
    }
}

#[test]
fn test_ip_range() {
    let cases = [
        ("10.0.0.0/24", "10.0.0.0", "10.0.0.255"),
        ("10.0.0.123/24", "10.0.0.0", "10.0.0.255"),
        ("10.0.0.0/8", "10.0.0.0", "10.255.255.255"),
        ("10.0.0.0/8", "10.0.0.0", "10.255.255.255"),
        ("20.0.0.0/12", "20.0.0.0", "20.15.255.255"),
    ];

    for (input, range_start, range_end_inclusive) in cases {
        let range = IpRange::from_str(input).unwrap();
        assert_eq!(range.start.to_string(), range_start);
        assert_eq!(range.end_inclusive.to_string(), range_end_inclusive);
    }
}
