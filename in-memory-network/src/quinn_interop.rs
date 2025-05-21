use crate::network::InMemoryNetwork;
use crate::network::inbound_queue::NextPacketDelivery;
use crate::network::node::{Node, UdpEndpoint};
use crate::pcap_exporter::PcapExporter;
use crate::transmit::OwnedTransmit;
use cfg_if::cfg_if;
use parking_lot::Mutex;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

#[derive(Debug)]
pub struct InMemoryUdpPoller;

impl UdpPoller for InMemoryUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct InMemoryUdpSocket {
    network: Arc<InMemoryNetwork>,
    endpoint: Arc<UdpEndpoint>,
    node: Arc<Node>,
    next_packet_delivery: Mutex<Option<Pin<Box<NextPacketDelivery>>>>,
    pcap_exporter: PcapExporter,
}

impl Debug for InMemoryUdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("InMemoryUdpSocket")
    }
}

impl InMemoryUdpSocket {
    pub fn from_node(
        network: Arc<InMemoryNetwork>,
        node: Arc<Node>,
        pcap_exporter: PcapExporter,
    ) -> Self {
        InMemoryUdpSocket {
            endpoint: node.udp_endpoint.as_ref().unwrap().clone(),
            node,
            network: network.clone(),
            next_packet_delivery: Mutex::new(None),
            pcap_exporter,
        }
    }
}

impl AsyncUdpSocket for InMemoryUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(InMemoryUdpPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // We don't have code to handle GSO, so let's ensure transmits are always a single UDP
        // packet
        assert!(transmit.segment_size.is_none());

        // Track in pcap
        let source_addr = self.node.quic_addr();
        self.pcap_exporter.track_transmit(source_addr, transmit);

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
    ) -> Poll<io::Result<usize>> {
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

            // Track in pcap
            let source_addr = in_transit.data.source_endpoint.addr;
            self.pcap_exporter
                .track_transmit(source_addr, &transmit.as_transmit());
        }

        Poll::Ready(Ok(delivered_len))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.endpoint.addr)
    }
}

impl InMemoryUdpSocket {
    pub async fn receive<'a>(
        &self,
        bufs_and_meta: &'a mut BufsAndMeta,
    ) -> io::Result<Vec<UdpPacket<'a>>> {
        let packets = self.receive_raw(bufs_and_meta).await?;

        let mut result = Vec::with_capacity(packets);
        for i in 0..packets {
            let meta = &bufs_and_meta.meta[i];
            let source_addr = meta.addr;
            let payload = &bufs_and_meta.bufs[i][..meta.len];

            result.push(UdpPacket {
                source_addr,
                payload,
            });
        }

        Ok(result)
    }

    pub async fn receive_raw(&self, bufs_and_meta: &mut BufsAndMeta) -> io::Result<usize> {
        let receive = UdpReceive {
            socket: self,
            result: bufs_and_meta,
        };

        receive.await
    }
}

pub struct UdpPacket<'a> {
    pub source_addr: SocketAddr,
    pub payload: &'a [u8],
}

pub struct UdpReceive<'a, 'b> {
    socket: &'a dyn AsyncUdpSocket,
    result: &'b mut BufsAndMeta,
}

pub struct BufsAndMeta {
    pub bufs: Vec<Vec<u8>>,
    pub meta: Vec<RecvMeta>,
}

impl BufsAndMeta {
    pub fn new(max_packet_size: usize, max_packets_per_read: usize) -> Self {
        Self {
            bufs: vec![vec![0u8; max_packet_size]; max_packets_per_read],
            meta: vec![RecvMeta::default(); max_packets_per_read],
        }
    }
}

impl Future for UdpReceive<'_, '_> {
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        let socket = &mut this.socket;
        let bufs = &mut this.result.bufs;
        let meta = &mut this.result.meta;

        let mut bufs: Vec<_> = bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        socket.poll_recv(cx, &mut bufs, meta)
    }
}

cfg_if! {
    if #[cfg(feature = "rt-custom")] {
        use async_runtime::rt::Rt;
        use async_runtime::time::timer::Timer;
        use std::time::Instant;
        use std::net::UdpSocket;
        use quinn::{AsyncTimer, Runtime};

        pub struct RtAdapter;

        impl Debug for RtAdapter {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "rt-adapter")
            }
        }

        impl Runtime for RtAdapter {
            fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
                Box::pin(RtTimerAdapter { inner: Rt::active().new_timer(i) })
            }

            fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
                Rt::active().spawn(future)
            }

            fn wrap_udp_socket(&self, _: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
                unimplemented!("not used")
            }

            fn now(&self) -> Instant {
                Rt::active().now()
            }
        }

        pin_project_lite::pin_project! {
            struct RtTimerAdapter {
                #[pin]
                inner: Timer
            }
        }

        impl Debug for RtTimerAdapter {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "rt-timer-adapter")
            }
        }

        impl AsyncTimer for RtTimerAdapter {
            fn reset(self: Pin<&mut Self>, i: Instant) {
                let this = self.project();
                this.inner.reset(i)
            }

            fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
                let this = self.project();
                this.inner.poll(cx)
            }
        }
    }
}
