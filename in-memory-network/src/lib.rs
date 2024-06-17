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
pub struct NetworkStatsTracker {
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
    out_of_order: bool,
    duplicate: bool,
    pcap_number: u64,
}

impl NetworkStatsTracker {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NetworkStatsInner::default())),
        }
    }

    fn track_out_of_order(&self, metadata_index: usize) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        inner.transmits_metadata[metadata_index].out_of_order = true;
        inner.transmits_metadata[metadata_index].pcap_number
    }

    fn track_sent(
        &self,
        source: SocketAddr,
        size: usize,
        duplicate: bool,
        pcap_number: u64,
    ) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let metadata_index = inner.transmits_metadata.len();
        inner.transmits_metadata.push(TransmitMetadata {
            source,
            byte_size: size,
            dropped: false,
            out_of_order: false,
            duplicate,
            pcap_number,
        });

        metadata_index
    }

    fn track_dropped(&self, source: SocketAddr, size: usize, pcap_number: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.transmits_metadata.push(TransmitMetadata {
            source,
            byte_size: size,
            dropped: true,
            out_of_order: false,
            duplicate: false,
            pcap_number,
        });
    }
}

pub struct NetworkStats {
    pub client: EndpointStats,
    pub server: EndpointStats,
}

#[derive(Default)]
pub struct EndpointStats {
    pub sent: PacketStats,
    pub dropped: PacketStats,
    pub duplicates: PacketStats,
    pub out_of_order: PacketStats,
}

#[derive(Default)]
pub struct PacketStats {
    pub packets: usize,
    pub bytes: usize,
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
        data: &InTransitData,
        source_addr: &SocketAddr,
        dropped: bool,
        extra_delay: Duration,
    ) {
        let transmit = &data.transmit;
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

        let mut options = vec![EnhancedPacketOption::Comment(
            format!("Transmit no. {}", data.number).into(),
        )];

        if dropped {
            options.push(EnhancedPacketOption::Comment(
                "This packet was lost in transit!".into(),
            ));
        } else if !extra_delay.is_zero() {
            options.push(EnhancedPacketOption::Comment(
                format!(
                    "This packet had an additional delay of {:.2}s",
                    extra_delay.as_secs_f64()
                )
                .into(),
            ));
        }

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
        // We don't have code to handle GSO, so let's ensure transmits are always a single UDP
        // packet
        assert!(transmit.segment_size.is_none());

        self.network.send(
            Instant::now(),
            self.addr,
            OwnedTransmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents.to_vec(),
                segment_size: transmit.segment_size,
            },
        );

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
    pub fn new(
        addr: SocketAddr,
        config: &NetworkConfig,
        stats_tracker: NetworkStatsTracker,
        start: Instant,
    ) -> InMemorySocket {
        InMemorySocket {
            addr,
            inbound: Arc::new(Mutex::new(InboundQueue::new(
                config.link_delay,
                config.link_capacity,
                stats_tracker,
                start,
            ))),
            waker: Arc::new(Mutex::new(None)),
        }
    }

    pub fn has_enough_capacity(&self, data: &InTransitData, duplicate: bool) -> bool {
        self.inbound
            .lock()
            .unwrap()
            .has_enough_capacity(data, duplicate)
    }

    pub fn enqueue_send(&self, data: InTransitData, metadata_index: usize, extra_delay: Duration) {
        self.inbound
            .lock()
            .unwrap()
            .send(data, metadata_index, extra_delay);
    }
}

// This mod is meant to enforce encapsulation of InboundQueue's private fields
mod queue {
    use super::*;
    use std::collections::BinaryHeap;

    pub struct InboundQueue {
        queue: BinaryHeap<PrioritizedInTransitData>,
        bytes_in_transit: usize,
        link_delay: Duration,
        link_capacity: usize,
        highest_received_transmit_number: AtomicU64,
        stats_tracker: NetworkStatsTracker,
        start: Instant,
    }

    impl InboundQueue {
        pub(super) fn new(
            link_delay: Duration,
            link_capacity: u64,
            stats_tracker: NetworkStatsTracker,
            start: Instant,
        ) -> Self {
            Self {
                queue: BinaryHeap::new(),
                bytes_in_transit: 0,
                link_delay,
                link_capacity: link_capacity as usize,
                highest_received_transmit_number: Default::default(),
                stats_tracker,
                start,
            }
        }

        pub(super) fn has_enough_capacity(&self, data: &InTransitData, duplicate: bool) -> bool {
            let duplicate_multiplier = if duplicate { 2 } else { 1 };
            self.bytes_in_transit + data.transmit.contents.len() * duplicate_multiplier
                <= self.link_capacity
        }

        pub(super) fn send(
            &mut self,
            data: InTransitData,
            metadata_index: usize,
            extra_delay: Duration,
        ) {
            assert!(self.has_enough_capacity(&data, false));
            self.bytes_in_transit += data.transmit.contents.len();
            self.queue.push(PrioritizedInTransitData {
                data,
                metadata_index,
                delay: self.link_delay + extra_delay,
            });
        }

        pub(super) fn is_empty(&self) -> bool {
            self.queue.is_empty()
        }

        pub(super) fn receive(
            &mut self,
            max_transmits: usize,
        ) -> impl Iterator<Item = InTransitData> {
            let now = Instant::now();
            let mut highest_received = self
                .highest_received_transmit_number
                .load(Ordering::Relaxed);
            let mut received = Vec::new();

            for _ in 0..max_transmits {
                if self
                    .queue
                    .peek()
                    .is_some_and(|next| next.arrival_time() <= now)
                {
                    let data = self.queue.pop().unwrap();

                    // Keep track of out-of-order packets
                    if data.data.number < highest_received {
                        let pcap_number =
                            self.stats_tracker.track_out_of_order(data.metadata_index);
                        println!(
                            "{:.2}s WARN Received reordered packet (#{pcap_number}) after it was delayed for extra {:.2}s",
                            self.start.elapsed().as_secs_f64(),
                            (data.delay - self.link_delay).as_secs_f64(),
                        );
                    }
                    highest_received = highest_received.max(data.data.number);

                    // Keep track of bytes in transit
                    self.bytes_in_transit -= data.data.transmit.contents.len();

                    received.push(data.data);
                } else {
                    break;
                }
            }

            self.highest_received_transmit_number
                .store(highest_received, Ordering::Relaxed);

            received.into_iter()
        }

        pub(super) fn time_of_next_receive(&self) -> Instant {
            self.queue.peek().unwrap().arrival_time()
        }
    }
}

pub struct InMemoryNetwork {
    pub sockets: Vec<InMemorySocket>,
    pcap_exporter: Arc<PcapExporter>,
    stats_tracker: NetworkStatsTracker,
    rng: Mutex<Rng>,
    config: NetworkConfig,
    start: Instant,
    next_transmit_number: AtomicU64,
}

impl InMemoryNetwork {
    /// Initializes a new [`InMemoryNetwork`] with one socket for the server and one for the client
    ///
    /// The link capacity is measured in bytes per `link_delay`
    pub fn initialize(
        config: NetworkConfig,
        pcap_exporter: Arc<PcapExporter>,
        rng: Rng,
        start: Instant,
    ) -> Self {
        let server_addr = SERVER_ADDR;
        let client_addr = CLIENT_ADDR;

        let stats_tracker = NetworkStatsTracker::new();
        Self {
            sockets: vec![
                InMemorySocket::new(server_addr, &config, stats_tracker.clone(), start),
                InMemorySocket::new(client_addr, &config, stats_tracker.clone(), start),
            ],
            pcap_exporter,
            stats_tracker,
            config,
            rng: Mutex::new(rng),
            start,
            next_transmit_number: Default::default(),
        }
    }

    /// Returns a handle to the server's socket
    pub fn server_socket(self: Arc<InMemoryNetwork>) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.sockets[0].addr,
            network: self.clone(),
        }
    }

    /// Returns a handle to the client's socket
    pub fn client_socket(self: Arc<InMemoryNetwork>) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.sockets[1].addr,
            network: self.clone(),
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

        let source = match source_addr {
            CLIENT_ADDR => "Client",
            SERVER_ADDR => "Server",
            _ => unreachable!(),
        };

        let mut dropped = false;
        let mut duplicate = false;
        let mut extra_delay = Duration::from_secs(0);

        let roll1 = self.rng.lock().unwrap().f64();
        if roll1 < self.config.packet_loss_ratio {
            dropped = true;
        } else if roll1 < self.config.packet_loss_ratio + self.config.packet_duplication_ratio {
            duplicate = true;
        }

        let roll2 = self.rng.lock().unwrap().f64();
        if roll2 < self.config.link_extra_delay_ratio {
            extra_delay = self.config.link_extra_delay;
        }

        let data = InTransitData {
            source_addr,
            transmit,
            sent: now,
            number: self.next_transmit_number.fetch_add(1, Ordering::Relaxed),
        };

        // A packet could also be dropped if the socket doesn't have enough capacity
        if dropped || !socket.has_enough_capacity(&data, duplicate) {
            self.pcap_exporter
                .track_packet(now, &data, &source_addr, true, Duration::from_secs(0));
            self.stats_tracker.track_dropped(
                source_addr,
                data.transmit.contents.len(),
                self.pcap_exporter.total_tracked_packets(),
            );

            println!(
                "{:.2}s WARN {source} packet lost (#{})!",
                self.start.elapsed().as_secs_f64(),
                self.pcap_exporter.total_tracked_packets(),
            );
        } else {
            let total = if duplicate { 2 } else { 1 };
            let packets = vec![data; total];

            for (i, packet) in packets.into_iter().enumerate() {
                let duplicate = i == 1;

                self.pcap_exporter
                    .track_packet(now, &packet, &source_addr, false, extra_delay);
                let metadata_index = self.stats_tracker.track_sent(
                    source_addr,
                    packet.transmit.contents.len(),
                    duplicate,
                    self.pcap_exporter.total_tracked_packets(),
                );

                if duplicate {
                    println!(
                        "{:.2}s WARN {source} sent duplicate packet (#{})!",
                        self.start.elapsed().as_secs_f64(),
                        self.pcap_exporter.total_tracked_packets(),
                    );
                }

                socket.enqueue_send(packet, metadata_index, extra_delay);
            }

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
            let endpoint_stats = match metadata.source {
                CLIENT_ADDR => &mut client,
                SERVER_ADDR => &mut server,
                _ => unreachable!(),
            };

            if metadata.dropped {
                endpoint_stats.dropped.packets += 1;
                endpoint_stats.dropped.bytes += metadata.byte_size;
            } else {
                endpoint_stats.sent.packets += 1;
                endpoint_stats.sent.bytes += metadata.byte_size;
            }
        }

        for metadata in &stats_tracker.transmits_metadata {
            if metadata.dropped {
                continue;
            }

            let endpoint_stats = match metadata.source {
                CLIENT_ADDR => &mut client,
                SERVER_ADDR => &mut server,
                _ => unreachable!(),
            };

            if metadata.out_of_order {
                endpoint_stats.out_of_order.packets += 1;
                endpoint_stats.out_of_order.bytes += metadata.byte_size;
            }

            if metadata.duplicate {
                endpoint_stats.duplicates.packets += 1;
                endpoint_stats.duplicates.bytes += metadata.byte_size;
            }
        }

        NetworkStats { client, server }
    }
}

pub struct NetworkConfig {
    pub packet_loss_ratio: f64,
    pub packet_duplication_ratio: f64,
    pub link_capacity: u64,
    pub link_delay: Duration,
    pub link_extra_delay: Duration,
    pub link_extra_delay_ratio: f64,
}

#[derive(Clone, Debug)]
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

#[derive(Clone)]
pub struct InTransitData {
    source_addr: SocketAddr,
    transmit: OwnedTransmit,
    sent: Instant,
    number: u64,
}

// In transit data, sorted by arrival time
struct PrioritizedInTransitData {
    data: InTransitData,
    metadata_index: usize,
    delay: Duration,
}

impl PrioritizedInTransitData {
    fn arrival_time(&self) -> Instant {
        self.data.sent + self.delay
    }
}

impl Eq for PrioritizedInTransitData {}

impl PartialEq<Self> for PrioritizedInTransitData {
    fn eq(&self, other: &Self) -> bool {
        self.arrival_time() == other.arrival_time() && self.data.number == other.data.number
    }
}

impl PartialOrd<Self> for PrioritizedInTransitData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedInTransitData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Note: the order is reversed, so the "max" in transit data will be the next one to be sent
        other
            .arrival_time()
            .cmp(&self.arrival_time())
            .then(other.data.number.cmp(&self.data.number))
    }
}
