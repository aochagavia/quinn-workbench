use crate::network::node::{HostHandle, Node};
use crate::OwnedTransmit;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Debug)]
pub struct InMemoryUdpPoller;

impl UdpPoller for InMemoryUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for HostHandle {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(InMemoryUdpPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        // We don't have code to handle GSO, so let's ensure transmits are always a single UDP
        // packet
        assert!(transmit.segment_size.is_none());

        let data = self.network.in_transit_data(
            self.host.clone(),
            OwnedTransmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents.to_vec(),
                segment_size: transmit.segment_size,
            },
        );
        self.network.forward(Node::Host(self.host.clone()), data);

        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let host = self.network.host_internal(self.addr());
        let mut inbound = host.inbound.lock();

        let max_transmits = meta.len();
        let mut received = 0;
        let mut highest_received = self
            .host
            .highest_received_packet_number
            .load(Ordering::SeqCst);

        let out = meta.iter_mut().zip(bufs);
        for (in_transit, (meta, buf)) in inbound.receive(max_transmits).into_iter().zip(out) {
            let out_of_order = in_transit.number < highest_received;
            highest_received = highest_received.max(in_transit.number);
            self.network
                .tracer
                .track_read_by_host(host.id.clone(), &in_transit, out_of_order);

            received += 1;
            let transmit = in_transit.transmit;

            // Meta
            meta.addr = in_transit.source.addr;
            meta.ecn = transmit.ecn;
            meta.dst_ip = Some(transmit.destination.ip());
            meta.len = transmit.contents.len();
            meta.stride = transmit.segment_size.unwrap_or(meta.len);

            // Buffer
            buf[..transmit.contents.len()].copy_from_slice(&transmit.contents);
        }

        self.host
            .highest_received_packet_number
            .fetch_max(highest_received, Ordering::SeqCst);

        if received == 0 {
            inbound.register_waker(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(received))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addr())
    }
}
