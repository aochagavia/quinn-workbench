use quinn::udp::EcnCodepoint;
use std::net::SocketAddr;

pub const UDP_OVERHEAD: usize = 8;
pub const IPV4_OVERHEAD: usize = 20;
pub const IPV6_OVERHEAD: usize = 40;

#[derive(Clone, Debug)]
pub struct OwnedTransmit {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: Vec<u8>,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
}

impl OwnedTransmit {
    pub fn packet_size(&self) -> usize {
        let ip_overhead = if self.destination.ip().is_ipv4() {
            IPV4_OVERHEAD
        } else {
            IPV6_OVERHEAD
        };

        UDP_OVERHEAD + ip_overhead + self.contents.len()
    }
}
