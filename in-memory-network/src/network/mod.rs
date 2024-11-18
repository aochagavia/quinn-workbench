mod inbound_queue;
pub mod quinn_interop;
pub mod socket;

use crate::network::socket::{InMemorySocket, InMemorySocketHandle};
use crate::pcap_exporter::PcapExporter;
use crate::stats_tracker::{EndpointStats, NetworkStats, NetworkStatsTracker};
use crate::{InTransitData, NetworkConfig, OwnedTransmit, PEER_A_ADDR, PEER_B_ADDR};
use fastrand::Rng;
use quinn::udp::EcnCodepoint;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

pub struct InMemoryNetwork {
    peer_a_socket: InMemorySocket,
    peer_b_socket: InMemorySocket,
    pcap_exporter: Arc<PcapExporter>,
    stats_tracker: NetworkStatsTracker,
    rng: Mutex<Rng>,
    config: NetworkConfig,
    start: Instant,
    next_transmit_number: AtomicU64,
}

impl InMemoryNetwork {
    /// Initializes a new [`InMemoryNetwork`] with two peers
    ///
    /// The link capacity is measured in bytes per `link_delay`
    pub fn initialize(
        config: NetworkConfig,
        pcap_exporter: Arc<PcapExporter>,
        rng: Rng,
        start: Instant,
    ) -> Self {
        let stats_tracker = NetworkStatsTracker::new();
        Self {
            peer_a_socket: InMemorySocket::new(
                PEER_A_ADDR,
                Arc::from("Server".to_string().into_boxed_str()),
                &config,
                stats_tracker.clone(),
                start,
            ),
            peer_b_socket: InMemorySocket::new(
                PEER_B_ADDR,
                Arc::from("Client".to_string().into_boxed_str()),
                &config,
                stats_tracker.clone(),
                start,
            ),
            pcap_exporter,
            stats_tracker,
            config,
            rng: Mutex::new(rng),
            start,
            next_transmit_number: Default::default(),
        }
    }

    /// Returns a handle to peer a's socket
    pub fn peer_a_socket(self: &Arc<InMemoryNetwork>) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.peer_a_socket.addr,
            network: self.clone(),
        }
    }

    /// Returns a handle to the peer b's socket
    pub fn peer_b_socket(self: &Arc<InMemoryNetwork>) -> InMemorySocketHandle {
        InMemorySocketHandle {
            addr: self.peer_b_socket.addr,
            network: self.clone(),
        }
    }

    /// Returns the socket bound to the provided address
    fn socket(&self, addr: SocketAddr) -> InMemorySocket {
        [&self.peer_a_socket, &self.peer_b_socket]
            .into_iter()
            .find(|s| s.addr == addr)
            .cloned()
            .expect("socket does not exist")
    }

    /// Sends an [`OwnedTransmit`] to its destination
    fn send(&self, now: Instant, source_addr: SocketAddr, mut transmit: OwnedTransmit) {
        let socket = self.socket(transmit.destination);
        let source = &*socket.name;

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

        let congestion_experienced =
            self.rng.lock().unwrap().f64() < self.config.congestion_event_ratio;
        if congestion_experienced {
            // The Quinn-provided transmit must indicate support for ECN
            assert!(transmit
                .ecn
                .is_some_and(|codepoint| codepoint as u8 == 0b10 || codepoint as u8 == 0b01));

            // Set explicit congestion event codepoint
            transmit.ecn = Some(EcnCodepoint::from_bits(0b11).unwrap())
        }

        let data = InTransitData {
            source_addr,
            transmit,
            sent: now,
            number: self.next_transmit_number.fetch_add(1, Ordering::Relaxed),
        };

        // A packet could also be dropped if the socket doesn't have enough capacity
        if dropped || !socket.has_enough_capacity(&data, duplicate) {
            self.pcap_exporter.track_packet(
                now,
                &data,
                &source_addr,
                data.transmit.ecn,
                true,
                Duration::from_secs(0),
            );
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

                self.pcap_exporter.track_packet(
                    now,
                    &packet,
                    &source_addr,
                    packet.transmit.ecn,
                    false,
                    extra_delay,
                );
                let metadata_index = self.stats_tracker.track_sent(
                    source_addr,
                    packet.transmit.contents.len(),
                    duplicate,
                    self.pcap_exporter.total_tracked_packets(),
                    congestion_experienced,
                );

                if duplicate {
                    println!(
                        "{:.2}s WARN {source} sent duplicate packet (#{})!",
                        self.start.elapsed().as_secs_f64(),
                        self.pcap_exporter.total_tracked_packets(),
                    );
                }

                if packet.transmit.ecn.is_some_and(|t| t == EcnCodepoint::Ce) {
                    println!(
                        "{:.2}s WARN {source} sent packet marked with CE ECN (#{})!",
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

        let mut peer_a = EndpointStats::default();
        let mut peer_b = EndpointStats::default();

        for metadata in &stats_tracker.transmits_metadata {
            let endpoint_stats = match metadata.source {
                PEER_B_ADDR => &mut peer_b,
                PEER_A_ADDR => &mut peer_a,
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
                PEER_B_ADDR => &mut peer_b,
                PEER_A_ADDR => &mut peer_a,
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

            if metadata.congestion_experienced {
                endpoint_stats.congestion_experienced += 1;
            }
        }

        NetworkStats { peer_b, peer_a }
    }
}
