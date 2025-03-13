use crate::HOST_PORT;
use crate::network::inbound_queue::InboundQueue;
use crate::network::outbound_buffer::OutboundBuffer;
use crate::network::spec::{NetworkNodeSpec, NodeKind};
use anyhow::bail;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Clone)]
pub struct Node {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) id: Arc<str>,
    pub(crate) outbound_buffer: Arc<OutboundBuffer>,
    pub(crate) quinn_endpoint: Option<Arc<QuinnEndpoint>>,
}

impl Node {
    pub(crate) fn host(node: NetworkNodeSpec) -> anyhow::Result<(Self, Arc<QuinnEndpoint>)> {
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

        let addresses = node.addresses();
        let quic_address = addresses[0];
        let quinn_endpoint = Arc::new(QuinnEndpoint {
            addr: SocketAddr::new(quic_address, HOST_PORT),
            inbound: Arc::new(Mutex::new(InboundQueue::new())),
        });
        let host = Self {
            id: node.id.into(),
            addresses,
            outbound_buffer: Arc::new(OutboundBuffer::new(node.buffer_size_bytes as usize)),
            quinn_endpoint: Some(quinn_endpoint.clone()),
        };
        Ok((host, quinn_endpoint))
    }

    pub(crate) fn router(node: NetworkNodeSpec) -> anyhow::Result<Self> {
        let addresses = node.addresses();
        if addresses.is_empty() {
            bail!("found router with no addresses: {}", node.id);
        }

        Ok(Node {
            id: node.id.into(),
            addresses,
            outbound_buffer: Arc::new(OutboundBuffer::new(node.buffer_size_bytes as usize)),
            quinn_endpoint: None,
        })
    }

    pub fn quic_addr(&self) -> SocketAddr {
        self.quinn_endpoint.as_ref().unwrap().addr
    }

    pub fn id(&self) -> &Arc<str> {
        &self.id
    }

    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + use<> {
        self.addresses.clone().into_iter()
    }

    pub fn outbound_buffer(&self) -> Arc<OutboundBuffer> {
        self.outbound_buffer.clone()
    }
}

#[derive(Clone)]
pub struct QuinnEndpoint {
    pub inbound: Arc<Mutex<InboundQueue>>,
    pub addr: SocketAddr,
}
