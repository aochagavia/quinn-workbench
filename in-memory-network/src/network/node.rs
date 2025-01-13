use crate::network::inbound_queue::InboundQueue;
use crate::network::outbound_buffer::OutboundBuffer;
use crate::network::spec::{NetworkNodeSpec, NodeKind};
use crate::network::InMemoryNetwork;
use crate::HOST_PORT;
use anyhow::bail;
use parking_lot::Mutex;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[derive(Clone)]
pub enum Node {
    Host(Host),
    Router(Arc<Router>),
}

impl Node {
    pub fn id(&self) -> &Arc<str> {
        match self {
            Node::Host(h) => &h.id,
            Node::Router(r) => &r.id,
        }
    }

    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> {
        match self {
            Node::Host(host) => vec![host.addr.ip()].into_iter(),
            Node::Router(router) => router.addresses.clone().into_iter(),
        }
    }

    pub fn outbound_buffer(&self) -> Arc<OutboundBuffer> {
        match self {
            Node::Host(host) => host.outbound.clone(),
            Node::Router(router) => router.outbound_buffer.clone(),
        }
    }
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
    pub id: Arc<str>,
    pub addr: SocketAddr,
    pub(crate) highest_received_packet_number: Arc<AtomicU64>,
    pub(crate) inbound: Arc<Mutex<InboundQueue>>,
    outbound: Arc<OutboundBuffer>,
}

impl Host {
    pub(crate) fn from_network_node(node: NetworkNodeSpec) -> anyhow::Result<Self> {
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
        let node_address = node.interfaces[0].addresses[0].as_ip_addr();
        Ok(Self {
            addr: SocketAddr::new(node_address, HOST_PORT),
            id: Arc::from(node.id.into_boxed_str()),
            highest_received_packet_number: Arc::new(Default::default()),
            inbound: Arc::new(Mutex::new(InboundQueue::new())),

            // Hosts have no outbound queue, which is equivalent to a zero-capacity queue
            outbound: Arc::new(OutboundBuffer::new(0)),
        })
    }
}

pub struct Router {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) id: Arc<str>,
    pub(crate) outbound_buffer: Arc<OutboundBuffer>,
}
