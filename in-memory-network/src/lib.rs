use fastrand::Rng;
use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::blocks::section_header::SectionHeaderBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::{DataLink, Endianness};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::udp;
use pnet_packet::udp::MutableUdpPacket;
use pnet_packet::{ipv4, PacketSize};
use queue::InboundQueue;
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::time::Instant;

pub const SERVER_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(88, 88, 88, 88)), 8080);
pub const CLIENT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8080);

#[derive(Clone, Debug)]
struct NetworkStatsTracker {
    inner: Arc<Mutex<NetworkStatsInner>>,
}

#[derive(Debug, Default)]
struct NetworkStatsInner {
    transmits_metadata: Vec<TransmitMetadata>,
}

#[derive(Debug)]
struct TransmitMetadata {
    source: SocketAddr,
    byte_size: usize,
    dropped: bool,
}

impl NetworkStatsTracker {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NetworkStatsInner::default())),
        }
    }

    fn track_sent(&self, source: SocketAddr, size: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.transmits_metadata.push(TransmitMetadata {
            source,
            byte_size: size,
            dropped: false,
        });
    }

    fn track_dropped(&self, source: SocketAddr, size: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.transmits_metadata.push(TransmitMetadata {
            source,
            byte_size: size,
            dropped: true,
        });
    }
}

pub struct NetworkStats {
    pub client: EndpointStats,
    pub server: EndpointStats,
}

#[derive(Default)]
pub struct EndpointStats {
    pub sent_packets: usize,
    pub dropped_packets: usize,
    pub sent_bytes: usize,
    pub dropped_bytes: usize,
}

pub struct PcapExporter {
    capture_start: Instant,
    total_tracked_packets: AtomicU64,
    writer: Mutex<PcapNgWriter<Vec<u8>>>,
}

impl PcapExporter {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut writer = PcapNgWriter::with_section_header(
            Vec::new(),
            SectionHeaderBlock {
                endianness: Endianness::Big,
                major_version: 1,
                minor_version: 0,
                section_length: 0,
                options: vec![],
            },
        )
        .unwrap();

        writer
            .write_pcapng_block(InterfaceDescriptionBlock {
                linktype: DataLink::IPV4,
                snaplen: 65535,
                options: vec![],
            })
            .unwrap();

        Self {
            capture_start: Instant::now(),
            writer: Mutex::new(writer),
            total_tracked_packets: AtomicU64::new(0),
        }
    }

    pub fn save(&self, path: &Path) {
        let dummy_writer = PcapNgWriter::new(Vec::new()).unwrap();
        let mut writer = self.writer.lock().unwrap();
        let writer = std::mem::replace(&mut *writer, dummy_writer);
        let bytes = writer.into_inner();
        std::fs::write(path, bytes).unwrap();
    }

    fn total_tracked_packets(&self) -> u64 {
        self.total_tracked_packets.load(Ordering::Relaxed)
    }

    fn track_packet(
        &self,
        now: Instant,
        transmit: &OwnedTransmit,
        source_addr: &SocketAddr,
        dropped: bool,
    ) {
        let IpAddr::V4(source) = source_addr.ip() else {
            unreachable!()
        };

        let IpAddr::V4(destination) = transmit.destination.ip() else {
            unreachable!()
        };

        let mut buffer = vec![0; 2000];

        // Wrap the data in a UDP packet
        let mut udp_writer = MutableUdpPacket::new(&mut buffer).unwrap();
        let udp_packet_length = 8 + transmit.contents.len() as u16;
        udp_writer.set_source(source_addr.port());
        udp_writer.set_destination(transmit.destination.port());
        udp_writer.set_length(udp_packet_length);
        udp_writer.set_payload(&transmit.contents);
        let checksum = udp::ipv4_checksum(&udp_writer.to_immutable(), &source, &destination);
        udp_writer.set_checksum(checksum);
        drop(udp_writer);
        let udp_packet = buffer[0..udp_packet_length as usize].to_vec();

        // Wrap the UDP packet in an IP packet
        let mut ip_writer = MutableIpv4Packet::new(&mut buffer).unwrap();
        let ip_packet_length = 20 + udp_packet_length;
        ip_writer.set_version(4);
        ip_writer.set_header_length(5); // We don't use options
        ip_writer.set_dscp(0); // Copied from a Wireshark dump
        ip_writer.set_ecn(0b10); // Copied from a Wireshark dump
        ip_writer.set_identification(0); // We never fragment
        ip_writer.set_flags(0b010); // We never fragment
        ip_writer.set_fragment_offset(0); // We never fragment
        ip_writer.set_ttl(64);
        ip_writer.set_next_level_protocol(IpNextHeaderProtocol::new(17)); // 17 = UDP
        ip_writer.set_source(source);
        ip_writer.set_destination(destination);
        ip_writer.set_payload(&udp_packet);
        ip_writer.set_total_length(ip_packet_length);
        let checksum = ipv4::checksum(&ip_writer.to_immutable());
        ip_writer.set_checksum(checksum);
        let ip_packet_length = ip_writer.packet_size();
        drop(ip_writer);

        let ip_packet = buffer[0..ip_packet_length as usize].to_vec();

        self.total_tracked_packets.fetch_add(1, Ordering::Relaxed);

        let options = if dropped {
            vec![EnhancedPacketOption::Comment(
                "This packet was lost in transit!".into(),
            )]
        } else {
            Vec::new()
        };

        let mut writer = self.writer.lock().unwrap();
        writer
            .write_pcapng_block(EnhancedPacketBlock {
                interface_id: 0,
                timestamp: correct_timestamp(now - self.capture_start),
                original_len: ip_packet.len() as u32,
                data: ip_packet.into(),
                options,
            })
            .unwrap();
    }
}

fn correct_timestamp(d: Duration) -> Duration {
    // Round to the nearest millisecond
    let millis = (d.as_secs_f64() * 1000.0).round();

    // Return the time, an order of magnitude smaller (there seems to be a bug in the library we are
    // using, which multiplies seconds by 1000)
    Duration::from_secs_f64(millis / 1_000_000.0)
}

#[derive(Debug)]
pub struct InMemoryUdpPoller;

impl UdpPoller for InMemoryUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct InMemorySocketHandle {
    pub network: Arc<InMemoryNetwork>,
    pub addr: SocketAddr,
    rng: Mutex<Rng>,
    packet_loss_ratio: f64,
    pcap_exporter: Arc<PcapExporter>,
    stats: NetworkStatsTracker,
    start: Instant,
}

impl Debug for InMemorySocketHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "in memory socket ({})", self.addr)
    }
}

impl AsyncUdpSocket for InMemorySocketHandle {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(InMemoryUdpPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let now = Instant::now();

        // We don't have code to handle GSO, so let's ensure transmits are always a single UDP
        // packet
        assert!(transmit.segment_size.is_none());

        let transmit = OwnedTransmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: transmit.contents.to_vec(),
            segment_size: transmit.segment_size,
        };

        {
            let roll = self.rng.lock().unwrap().f64();
            if roll < self.packet_loss_ratio {
                let source = match self.addr {
                    CLIENT_ADDR => "Client",
                    SERVER_ADDR => "Server",
                    _ => unreachable!(),
                };

                self.stats.track_dropped(self.addr, transmit.contents.len());
                self.pcap_exporter
                    .track_packet(now, &transmit, &self.addr, true);

                println!(
                    "{:.2}s {source} packet lost (#{})!",
                    self.start.elapsed().as_secs_f64(),
                    self.pcap_exporter.total_tracked_packets(),
                );

                return Ok(());
            }
        }

        // Track in the pcap capture
        self.pcap_exporter
            .track_packet(now, &transmit, &self.addr, false);
        self.stats.track_sent(self.addr, transmit.contents.len());

        // Actually send it
        self.network.send(now, self.addr, transmit);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let socket = self.network.socket(self.addr);
        let mut inbound = socket.inbound.lock().unwrap();

        let max_transmits = meta.len();
        let mut received = 0;

        let out = meta.iter_mut().zip(bufs);
        for (in_transit, (meta, buf)) in inbound.receive(max_transmits).zip(out) {
            received += 1;
            let transmit = in_transit.transmit;

            // Meta
            meta.addr = in_transit.source_addr;
            meta.ecn = transmit.ecn;
            meta.dst_ip = Some(transmit.destination.ip());
            meta.len = transmit.contents.len();
            meta.stride = transmit.segment_size.unwrap_or(meta.len);

            // Buffer
            buf[..transmit.contents.len()].copy_from_slice(&transmit.contents);
        }

        if received == 0 {
            if inbound.is_empty() {
                // Store the waker so we can be notified of new transmits
                let mut waker = socket.waker.lock().unwrap();
                if waker.is_none() {
                    *waker = Some(cx.waker().clone())
                }
            } else {
                // Wake up next time we can read
                let next_read = inbound.time_of_next_receive();
                let waker = cx.waker().clone();
                tokio::task::spawn(async move {
                    tokio::time::sleep_until(next_read).await;
                    waker.wake();
                });
            }

            Poll::Pending
        } else {
            Poll::Ready(Ok(received))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

#[derive(Clone)]
pub struct InMemorySocket {
    addr: SocketAddr,
    inbound: Arc<Mutex<InboundQueue>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl InMemorySocket {
    pub fn new(addr: SocketAddr, link_delay: Duration, link_capacity: usize) -> InMemorySocket {
        InMemorySocket {
            addr,
            inbound: Arc::new(Mutex::new(InboundQueue::new(link_delay, link_capacity))),
            waker: Arc::new(Mutex::new(None)),
        }
    }
}

// This mod is meant to enforce encapsulation of InboundQueue's private fields
mod queue {
    use super::*;

    pub struct InboundQueue {
        queue: VecDeque<InTransitData>,
        bytes_in_transit: usize,
        link_delay: Duration,
        link_capacity: usize,
    }

    impl InboundQueue {
        pub(super) fn new(link_delay: Duration, link_capacity: usize) -> Self {
            Self {
                queue: VecDeque::new(),
                bytes_in_transit: 0,
                link_delay,
                link_capacity,
            }
        }

        pub(super) fn send(&mut self, data: InTransitData) -> bool {
            if self.bytes_in_transit + data.transmit.contents.len() <= self.link_capacity {
                self.bytes_in_transit += data.transmit.contents.len();
                self.queue.push_back(data);
                true
            } else {
                false
            }
        }

        pub(super) fn is_empty(&self) -> bool {
            self.queue.is_empty()
        }

        pub(super) fn receive(
            &mut self,
            max_transmits: usize,
        ) -> impl Iterator<Item = InTransitData> + '_ {
            let now = Instant::now();
            let transmits_to_read = self
                .queue
                .iter()
                .take(max_transmits)
                .take_while(|t| t.sent + self.link_delay <= now)
                .count();

            for data in self.queue.iter().take(transmits_to_read) {
                self.bytes_in_transit -= data.transmit.contents.len();
            }

            self.queue.drain(..transmits_to_read)
        }

        pub(super) fn time_of_next_receive(&self) -> Instant {
            self.queue[0].sent + self.link_delay
        }
    }
}

pub struct InMemoryNetwork {
    pub sockets: Vec<InMemorySocket>,
    pcap_exporter: Arc<PcapExporter>,
    stats_tracker: NetworkStatsTracker,
    packet_loss_ratio: f64,
    start: Instant,
}

impl InMemoryNetwork {
    /// Initializes a new [`InMemoryNetwork`] with one socket for the server and one for the client
    ///
    /// The link capacity is measured in bytes per `link_delay`
    pub fn initialize(
        link_delay: Duration,
        link_capacity: usize,
        packet_loss_ratio: f64,
        pcap_exporter: Arc<PcapExporter>,
        start: Instant,
    ) -> Self {
        let server_addr = SERVER_ADDR;
        let client_addr = CLIENT_ADDR;

        Self {
            sockets: vec![
                InMemorySocket::new(server_addr, link_delay, link_capacity),
                InMemorySocket::new(client_addr, link_delay, link_capacity),
            ],
            pcap_exporter,
            stats_tracker: NetworkStatsTracker::new(),
            packet_loss_ratio,
            start,
        }
    }

    /// Returns a handle to the server's socket
    pub fn server_socket(self: Arc<InMemoryNetwork>, rng: &mut Rng) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.sockets[0].addr,
            packet_loss_ratio: self.packet_loss_ratio,
            rng: Mutex::new(Rng::with_seed(rng.u64(..))),
            network: self.clone(),
            stats: self.stats_tracker.clone(),
            pcap_exporter: self.pcap_exporter.clone(),
            start: self.start,
        }
    }

    /// Returns a handle to the client's socket
    pub fn client_socket(self: Arc<InMemoryNetwork>, rng: &mut Rng) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.sockets[1].addr,
            packet_loss_ratio: self.packet_loss_ratio,
            rng: Mutex::new(Rng::with_seed(rng.u64(..))),
            network: self.clone(),
            stats: self.stats_tracker.clone(),
            pcap_exporter: self.pcap_exporter.clone(),
            start: self.start,
        }
    }

    /// Returns the socket bound to the provided address
    fn socket(&self, addr: SocketAddr) -> InMemorySocket {
        self.sockets
            .iter()
            .find(|s| s.addr == addr)
            .cloned()
            .expect("socket does not exist")
    }

    /// Sends an [`OwnedTransmit`] to its destination
    fn send(&self, now: Instant, source_addr: SocketAddr, transmit: OwnedTransmit) {
        let socket = self.socket(transmit.destination);
        let sent = socket.inbound.lock().unwrap().send(InTransitData {
            source_addr,
            transmit,
            sent: now,
        });

        if sent {
            // Wake the receiver if it is waiting for incoming transmits
            let mut opt_waker = socket.waker.lock().unwrap();
            if let Some(waker) = opt_waker.take() {
                waker.wake();
            }
        }
    }

    pub fn stats(&self) -> NetworkStats {
        let stats_tracker = self.stats_tracker.inner.lock().unwrap();

        let mut client = EndpointStats::default();
        let mut server = EndpointStats::default();

        for metadata in &stats_tracker.transmits_metadata {
            match (metadata.source, metadata.dropped) {
                (CLIENT_ADDR, true) => {
                    client.dropped_packets += 1;
                    client.dropped_bytes += metadata.byte_size;
                }
                (CLIENT_ADDR, false) => {
                    client.sent_packets += 1;
                    client.sent_bytes += metadata.byte_size;
                }
                (SERVER_ADDR, false) => {
                    server.sent_packets += 1;
                    server.sent_bytes += metadata.byte_size;
                }
                (SERVER_ADDR, true) => {
                    server.dropped_packets += 1;
                    server.dropped_bytes += metadata.byte_size;
                }
                _ => unreachable!(),
            }
        }

        NetworkStats { client, server }
    }
}

#[derive(Debug)]
struct OwnedTransmit {
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

struct InTransitData {
    source_addr: SocketAddr,
    transmit: OwnedTransmit,
    sent: Instant,
}
