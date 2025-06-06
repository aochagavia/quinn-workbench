use crate::network::InMemoryNetwork;
use crate::network::inbound_queue::InboundQueue;
use crate::network::link::NetworkLink;
use crate::network::outbound_buffer::OutboundBuffer;
use crate::network::spec::{NetworkNodeSpec, NodeKind};
use crate::{HOST_PORT, InTransitData};
use anyhow::bail;
use event_listener::Event;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::ops::ControlFlow;
use std::sync::Arc;

pub struct Node {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) id: Arc<str>,
    pub(crate) udp_endpoint: Option<Arc<UdpEndpoint>>,
    pub(crate) injected_failures: NodeInjectedFailures,
    outbound_buffer: Arc<OutboundBuffer>,
    outbound_tx: futures::channel::mpsc::UnboundedSender<InTransitData>,
}

impl Node {
    pub(crate) fn host(
        node: NetworkNodeSpec,
    ) -> anyhow::Result<(
        Self,
        Arc<UdpEndpoint>,
        futures::channel::mpsc::UnboundedReceiver<InTransitData>,
    )> {
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
        let quinn_endpoint = Arc::new(UdpEndpoint {
            addr: SocketAddr::new(quic_address, HOST_PORT),
            inbound: Arc::new(Mutex::new(InboundQueue::new())),
        });

        let (tx, rx) = futures::channel::mpsc::unbounded();
        let host = Self {
            injected_failures: NodeInjectedFailures::from_spec(&node),
            id: node.id.into(),
            addresses,
            outbound_buffer: Arc::new(OutboundBuffer::new(node.buffer_size_bytes as usize)),
            udp_endpoint: Some(quinn_endpoint.clone()),
            outbound_tx: tx,
        };
        Ok((host, quinn_endpoint, rx))
    }

    pub(crate) fn router(
        node: NetworkNodeSpec,
    ) -> anyhow::Result<(
        Self,
        futures::channel::mpsc::UnboundedReceiver<InTransitData>,
    )> {
        let addresses = node.addresses();
        if addresses.is_empty() {
            bail!("found router with no addresses: {}", node.id);
        }

        let (tx, rx) = futures::channel::mpsc::unbounded();
        let node = Node {
            injected_failures: NodeInjectedFailures::from_spec(&node),
            id: node.id.into(),
            addresses,
            outbound_buffer: Arc::new(OutboundBuffer::new(node.buffer_size_bytes as usize)),
            udp_endpoint: None,
            outbound_tx: tx,
        };

        Ok((node, rx))
    }

    pub(crate) async fn sleep_until_ready_to_send(
        &self,
        network: &Arc<InMemoryNetwork>,
        data: &InTransitData,
    ) -> Arc<Mutex<NetworkLink>> {
        let cancellation_token = Event::new();
        let mut futures = Vec::new();
        network.walk_links::<()>(self, data.transmit.destination.ip(), |link| {
            futures.push(NetworkLink::sleep_until_ready_to_send(
                link.clone(),
                cancellation_token.listen(),
            ));
            ControlFlow::Continue(())
        });

        let link = futures_util::future::select_all(futures).await.0.unwrap();

        // Ensure the other links stop waiting for this packet to be sendable
        cancellation_token.notify(cancellation_token.total_listeners());

        link
    }

    pub(crate) fn enqueue_outbound(&self, network: &Arc<InMemoryNetwork>, data: InTransitData) {
        // Try to enqueue the data on the node's outbound buffer for later sending
        let outbound_buffer = self.outbound_buffer();
        let data_len = data.transmit.packet_size();

        if outbound_buffer.reserve(data_len) {
            // The buffer has capacity!
            self.outbound_tx.clone().unbounded_send(data).unwrap();
        } else {
            // The buffer is full and the packet is being dropped
            network.tracer.track_dropped_from_buffer(&data, self);
        }
    }

    pub fn quic_addr(&self) -> SocketAddr {
        self.udp_endpoint.as_ref().unwrap().addr
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

pub struct NodeInjectedFailures {
    pub(crate) packet_loss_ratio: f64,
    pub(crate) packet_duplication_ratio: f64,
}

impl NodeInjectedFailures {
    pub(crate) fn from_spec(spec: &NetworkNodeSpec) -> Self {
        Self {
            packet_loss_ratio: spec.packet_loss_ratio,
            packet_duplication_ratio: spec.packet_duplication_ratio,
        }
    }
}

#[derive(Clone)]
pub struct UdpEndpoint {
    pub inbound: Arc<Mutex<InboundQueue>>,
    pub addr: SocketAddr,
}
