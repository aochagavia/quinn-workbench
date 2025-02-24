use anyhow::{Context, anyhow, bail};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[derive(Clone)]
pub struct Ipv4Cidr {
    pub(crate) address: Ipv4Addr,
    pub(crate) network_prefix: u8,
}

impl Ipv4Cidr {
    pub(crate) fn as_ip_addr(&self) -> IpAddr {
        IpAddr::V4(self.address)
    }
}

impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.network_prefix)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = anyhow::Error;

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

        Ok(Self {
            address: base_ip,
            network_prefix,
        })
    }
}
