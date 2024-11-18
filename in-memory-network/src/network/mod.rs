//! In-memory network implementation
//!
//! Provides an in-memory network with two peers and an arbitrary number of routers in between

mod inbound_queue;
pub mod quinn_interop;
pub mod socket;

use crate::network::inbound_queue::InboundQueue;
use crate::network::socket::{InMemorySocket, InMemorySocketHandle};
use crate::pcap_exporter::PcapExporter;
use crate::stats_tracker::{EndpointStats, NetworkStats, NetworkStatsTracker};
use crate::{InTransitData, NetworkConfig, OwnedTransmit, PEER_A_ADDR, PEER_B_ADDR};
use fastrand::Rng;
use quinn::udp::EcnCodepoint;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

struct Router {
    link_configs: HashMap<SocketAddr, Arc<NetworkConfig>>,
    inbound: HashMap<SocketAddr, Mutex<InboundQueue>>,
    outbound: HashMap<SocketAddr, InMemorySocket>,
}

impl Router {
    fn link_config(&self, source_addr: SocketAddr) -> &NetworkConfig {
        &self.link_configs[&source_addr]
    }

    fn has_enough_capacity(&self, data: &InTransitData, duplicate: bool) -> bool {
        self.inbound[&data.source_addr]
            .lock()
            .unwrap()
            .has_enough_capacity(data, duplicate)
    }

    fn enqueue_inbound(&self, data: InTransitData, metadata_index: usize, extra_delay: Duration) {
        self.inbound[&data.source_addr]
            .lock()
            .unwrap()
            .send(data, metadata_index, extra_delay);
    }

    fn process_inbound(self: &Arc<Self>, source_addr: SocketAddr) {
        let inbound = &self.inbound[&source_addr];
        if let Some(next_receive) = inbound.lock().unwrap().time_of_next_receive() {
            let router = self.clone();
            tokio::spawn(async move {
                // Take delays into account
                tokio::time::sleep_until(next_receive).await;

                // Now transfer inbound to outbound!
                let mut inbound = router.inbound[&source_addr].lock().unwrap();
                let transmits = inbound.receive(usize::MAX);

                for transmit in transmits {
                    let mut destination_inbound_queue = router.outbound
                        [&transmit.transmit.destination]
                        .inbound
                        .lock()
                        .unwrap();

                    // TODO: using 0 here is wrong. It messes up reporting of reordered packets.
                    destination_inbound_queue.send(transmit, 0, Duration::default());
                }
            });
        }
    }
}

pub struct InMemoryNetwork {
    peer_a_socket: InMemorySocket,
    peer_b_socket: InMemorySocket,
    routers: Vec<Arc<Router>>,
    pcap_exporter: Arc<PcapExporter>,
    stats_tracker: NetworkStatsTracker,
    rng: Mutex<Rng>,
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
        let config = Arc::new(config);
        let peer_a_socket = InMemorySocket::new(
            PEER_A_ADDR,
            Arc::from("Server".to_string().into_boxed_str()),
            &config,
            stats_tracker.clone(),
            start,
        );
        let peer_b_socket = InMemorySocket::new(
            PEER_B_ADDR,
            Arc::from("Client".to_string().into_boxed_str()),
            &config,
            stats_tracker.clone(),
            start,
        );

        let mut network = Self {
            peer_a_socket: peer_a_socket.clone(),
            peer_b_socket: peer_b_socket.clone(),
            routers: Vec::new(),
            pcap_exporter,
            stats_tracker,
            rng: Mutex::new(rng),
            start,
            next_transmit_number: Default::default(),
        };

        network.routers = vec![Arc::new(Router {
            link_configs: [(PEER_A_ADDR, config.clone()), (PEER_B_ADDR, config.clone())]
                .into_iter()
                .collect(),
            inbound: [
                (
                    PEER_A_ADDR,
                    Mutex::new(InboundQueue::new(
                        config.link_delay,
                        config.link_capacity,
                        network.stats_tracker.clone(),
                        start,
                    )),
                ),
                (
                    PEER_B_ADDR,
                    Mutex::new(InboundQueue::new(
                        config.link_delay,
                        config.link_capacity,
                        network.stats_tracker.clone(),
                        start,
                    )),
                ),
            ]
            .into_iter()
            .collect(),
            outbound: [(PEER_A_ADDR, peer_a_socket), (PEER_B_ADDR, peer_b_socket)]
                .into_iter()
                .collect(),
        })];

        network
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

    /// Returns the router bound to the provided address
    fn router(&self, addr: SocketAddr) -> &Arc<Router> {
        if addr == self.peer_a_socket.addr {
            self.routers.first().unwrap()
        } else if addr == self.peer_b_socket.addr {
            self.routers.last().unwrap()
        } else {
            unreachable!("no router connected to the specified address");
        }
    }

    /// Sends an [`OwnedTransmit`] to its destination
    fn send(&self, now: Instant, source_addr: SocketAddr, mut transmit: OwnedTransmit) {
        let source = self.socket(source_addr).name;

        let router = self.router(source_addr);
        let config = router.link_config(source_addr);

        let mut dropped = false;
        let mut duplicate = false;
        let mut extra_delay = Duration::from_secs(0);

        let roll1 = self.rng.lock().unwrap().f64();
        if roll1 < config.packet_loss_ratio {
            dropped = true;
        } else if roll1 < config.packet_loss_ratio + config.packet_duplication_ratio {
            duplicate = true;
        }

        let roll2 = self.rng.lock().unwrap().f64();
        if roll2 < config.link_extra_delay_ratio {
            extra_delay = config.link_extra_delay;
        }

        let congestion_experienced = self.rng.lock().unwrap().f64() < config.congestion_event_ratio;
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
        if dropped || !router.has_enough_capacity(&data, duplicate) {
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

                router.enqueue_inbound(packet, metadata_index, extra_delay);
            }
        }

        router.process_inbound(source_addr);
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
