use crate::network::InMemoryNetwork;
use crate::network::inbound_queue::NextPacketDelivery;
use crate::network::node::{Node, UdpEndpoint};
use crate::transmit::OwnedTransmit;
use parking_lot::Mutex;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::fmt::{Debug, Formatter};
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

#[derive(Debug)]
pub struct InMemoryUdpPoller;

impl UdpPoller for InMemoryUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct InMemoryUdpSocket {
    pub network: Arc<InMemoryNetwork>,
    pub endpoint: Arc<UdpEndpoint>,
    pub node: Arc<Node>,
    pub next_packet_delivery: Mutex<Option<Pin<Box<NextPacketDelivery>>>>,
}

impl Debug for InMemoryUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("InMemoryUdpSocket")
    }
}

impl AsyncUdpSocket for InMemoryUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(InMemoryUdpPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        // We don't have code to handle GSO, so let's ensure transmits are always a single UDP
        // packet
        assert!(transmit.segment_size.is_none());

        let data = self.network.in_transit_data(
            &self.node,
            OwnedTransmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents.to_vec(),
                segment_size: transmit.segment_size,
            },
        );
        self.network.forward(self.node.clone(), data);

        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let node = self.node.clone();
        let max_transmits = meta.len();
        assert!(meta.len() <= bufs.len());

        let mut lock = self.next_packet_delivery.lock();
        let delivery = lock.get_or_insert(Box::pin(NextPacketDelivery::new(
            self.endpoint.inbound.clone(),
            max_transmits,
        )));
        let delivered = ready!(delivery.as_mut().poll(cx));
        let delivered_len = delivered.len();

        let out = meta.iter_mut().zip(bufs);
        for (in_transit, (meta, buf)) in delivered.into_iter().zip(out) {
            self.network
                .tracer
                .track_read_by_host(node.id.clone(), &in_transit.data);

            let transmit = in_transit.data.transmit;

            // Meta
            meta.addr = in_transit.data.source_endpoint.addr;
            meta.ecn = transmit.ecn;
            meta.dst_ip = Some(transmit.destination.ip());
            meta.len = transmit.contents.len();
            meta.stride = transmit.segment_size.unwrap_or(meta.len);

            // Buffer
            buf[..transmit.contents.len()].copy_from_slice(&transmit.contents);
        }

        Poll::Ready(Ok(delivered_len))
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.endpoint.addr)
    }
}
