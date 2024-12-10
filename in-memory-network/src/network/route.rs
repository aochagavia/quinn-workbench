use anyhow::{anyhow, bail, Context};
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

impl FromStr for IpRange {
    type Err = anyhow::Error;

    // Parse ranges in CIDR syntax (e.g. 10.0.0.0/24)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('/');
        let base_ip: IpAddr = parts
            .next()
            .ok_or(anyhow!("empty string"))?
            .parse()
            .context("invalid ip address in ip range")?;

        let IpAddr::V4(base_ip) = base_ip else {
            bail!("only IPv4 supported at the moment");
        };

        // A missing network prefix is interpreted as /32 (i.e. singleton ip range)
        let network_prefix: u8 = parts
            .next()
            .unwrap_or("32")
            .parse()
            .context("the provided network prefix is not a valid unsigned integer")?;
        if network_prefix == 0 {
            bail!("network prefix cannot be 0");
        }
        if network_prefix > 32 {
            bail!("network prefix cannot be higher than 32");
        }

        if parts.next().is_some() {
            bail!("ip range contains trailing characters");
        }

        let base_ip_bits = base_ip.to_bits();
        let mask: u32 = u32::MAX << (32 - network_prefix);
        let start = Ipv4Addr::from_bits(base_ip_bits & mask);
        let end_inclusive = Ipv4Addr::from_bits(base_ip_bits | (!mask));

        Ok(Self {
            start: IpAddr::V4(start),
            end_inclusive: IpAddr::V4(end_inclusive),
        })
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
