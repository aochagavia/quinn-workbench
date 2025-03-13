use crate::network::InMemoryNetwork;
use crate::network::inbound_queue::InboundQueue;
use crate::network::link::NetworkLink;
use crate::network::outbound_buffer::OutboundBuffer;
use crate::network::spec::{NetworkNodeSpec, NodeKind};
use crate::{HOST_PORT, InTransitData};
use anyhow::bail;
use parking_lot::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::ops::ControlFlow;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub struct Node {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) id: Arc<str>,
    pub(crate) quinn_endpoint: Option<Arc<QuinnEndpoint>>,
    pub(crate) injected_failures: NodeInjectedFailures,
    outbound_buffer: Arc<OutboundBuffer>,
    outbound_tx: tokio::sync::mpsc::UnboundedSender<InTransitData>,
}

impl Node {
    pub(crate) fn host(
        node: NetworkNodeSpec,
    ) -> anyhow::Result<(
        Self,
        Arc<QuinnEndpoint>,
        tokio::sync::mpsc::UnboundedReceiver<InTransitData>,
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
        let quinn_endpoint = Arc::new(QuinnEndpoint {
            addr: SocketAddr::new(quic_address, HOST_PORT),
            inbound: Arc::new(Mutex::new(InboundQueue::new())),
        });

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let host = Self {
            injected_failures: NodeInjectedFailures::from_spec(&node),
            id: node.id.into(),
            addresses,
            outbound_buffer: Arc::new(OutboundBuffer::new(node.buffer_size_bytes as usize)),
            quinn_endpoint: Some(quinn_endpoint.clone()),
            outbound_tx: tx,
        };
        Ok((host, quinn_endpoint, rx))
    }

    pub(crate) fn router(
        node: NetworkNodeSpec,
    ) -> anyhow::Result<(Self, tokio::sync::mpsc::UnboundedReceiver<InTransitData>)> {
        let addresses = node.addresses();
        if addresses.is_empty() {
            bail!("found router with no addresses: {}", node.id);
        }

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let node = Node {
            injected_failures: NodeInjectedFailures::from_spec(&node),
            id: node.id.into(),
            addresses,
            outbound_buffer: Arc::new(OutboundBuffer::new(node.buffer_size_bytes as usize)),
            quinn_endpoint: None,
            outbound_tx: tx,
        };

        Ok((node, rx))
    }

    pub(crate) async fn sleep_until_ready_to_send(
        &self,
        network: &Arc<InMemoryNetwork>,
        data: &InTransitData,
    ) -> Arc<Mutex<NetworkLink>> {
        let cancellation_token = CancellationToken::new();
        let mut futures = Vec::new();
        network.walk_links::<()>(self, data.transmit.destination.ip(), |link| {
            futures.push(NetworkLink::sleep_until_ready_to_send(
                link.clone(),
                data,
                cancellation_token.clone(),
            ));
            ControlFlow::Continue(())
        });

        let link = futures_util::future::select_all(futures).await.0.unwrap();

        // Ensure the other links stop waiting for this packet to be sendable
        cancellation_token.cancel();

        link
    }

    pub(crate) fn enqueue_outbound(&self, network: &Arc<InMemoryNetwork>, data: InTransitData) {
        // Try to enqueue the data on the node's outbound buffer for later sending
        let outbound_buffer = self.outbound_buffer();
        let data_len = data.transmit.packet_size();

        if outbound_buffer.reserve(data_len) {
            // The buffer has capacity!
            self.outbound_tx.send(data).unwrap();
        } else {
            // The buffer is full and the packet is being dropped
            network.tracer.track_dropped_from_buffer(&data, self);
        }
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
pub struct QuinnEndpoint {
    pub inbound: Arc<Mutex<InboundQueue>>,
    pub addr: SocketAddr,
}
