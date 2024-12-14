use crate::network::inbound_queue::InboundQueue;
use crate::network::spec::{NetworkNodeSpec, NodeKind};
use crate::network::InMemoryNetwork;
use crate::stats_tracker::NetworkStatsTracker;
use crate::HOST_PORT;
use anyhow::bail;
use parking_lot::Mutex;
use std::fmt::{Debug, Formatter};
use std::iter;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

pub trait Node {
    fn addresses(&self) -> impl Iterator<Item = IpAddr>;
}

pub struct HostHandle {
    pub network: Arc<InMemoryNetwork>,
    pub(crate) host: Host,
}

impl HostHandle {
    pub fn addr(&self) -> SocketAddr {
        self.host.addr
    }
}

impl Debug for HostHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "host ({})", self.addr())
    }
}

#[derive(Clone)]
pub struct Host {
    pub(crate) addr: SocketAddr,
    pub(crate) id: Arc<str>,
    pub(crate) inbound: Arc<Mutex<InboundQueue>>,
}

impl Host {
    pub(crate) fn from_network_node(
        node: NetworkNodeSpec,
        stats_tracker: NetworkStatsTracker,
        start: Instant,
    ) -> anyhow::Result<Self> {
        if node.kind != NodeKind::Host {
            bail!(
                "Attempted to create a host from a node that is not a host: {}",
                node.id
            );
        }
        if node.interfaces.is_empty() {
            bail!("Host {} has no interfaces", node.id);
        }
        if node.interfaces[0].addresses.is_empty() {
            bail!("Host {} has an interface without any address", node.id);
        }
        let node_address = node.interfaces[0].addresses[0];
        Ok(Self {
            addr: SocketAddr::new(node_address, HOST_PORT),
            id: Arc::from(node.id.into_boxed_str()),
            inbound: Arc::new(Mutex::new(InboundQueue::new(
                // Hosts have zero delay (delay is handled at the link level)
                Duration::default(),
                // Hosts have an infinite inbound bandwidth (bandwidth limits are handled at the
                // link level)
                u64::MAX,
                stats_tracker.clone(),
                start,
            ))),
        })
    }
}

impl Node for Host {
    fn addresses(&self) -> impl Iterator<Item = IpAddr> {
        iter::once(self.addr.ip())
    }
}

pub struct Router {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) id: Arc<str>,
}

impl Node for Router {
    fn addresses(&self) -> impl Iterator<Item = IpAddr> {
        self.addresses.iter().cloned()
    }
}
