//! In-memory network implementation
//!
//! Provides an in-memory network with two peers and an arbitrary number of routers in between

pub mod host;
mod inbound_queue;
pub mod quinn_interop;
mod router;

use crate::network::host::{Host, HostHandle};
use crate::network::inbound_queue::InboundQueue;
use crate::pcap_exporter::PcapExporter;
use crate::stats_tracker::{EndpointStats, NetworkStats, NetworkStatsTracker};
use crate::{InTransitData, NetworkConfig, OwnedTransmit, HOST_A_ADDR, HOST_B_ADDR};
use fastrand::Rng;
use parking_lot::Mutex;
use quinn::udp::EcnCodepoint;
use router::Router;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone)]
pub enum Node {
    Router(String),
    Host(Host),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeName {
    Router(String),
    Host(String),
}

#[derive(Clone, Debug)]
pub struct PacketArrived {
    pub path: Vec<(Instant, NodeName)>,
    pub content: Vec<u8>,
}

/// A network between two hosts, with multiple routers in between
pub struct InMemoryNetwork {
    pub(crate) host_a: Host,
    pub(crate) host_b: Host,
    /// The router connected to host A
    host_a_router: Arc<Router>,
    /// The router connected to host B
    host_b_router: Arc<Router>,
    /// Map from router names to the corresponding router object
    router_map: Arc<HashMap<String, Arc<Router>>>,
    pcap_exporter: Arc<PcapExporter>,
    stats_tracker: NetworkStatsTracker,
    rng: Mutex<Rng>,
    start: Instant,
    next_transmit_number: AtomicU64,
    packet_arrived_tx: tokio::sync::broadcast::Sender<PacketArrived>,
    packet_arrived_rx: tokio::sync::broadcast::Receiver<PacketArrived>,
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
        let host_a = Host::new(
            HOST_A_ADDR,
            Arc::from("Server".to_string().into_boxed_str()),
            &config,
            stats_tracker.clone(),
            start,
        );
        let host_b = Host::new(
            HOST_B_ADDR,
            Arc::from("Client".to_string().into_boxed_str()),
            &config,
            stats_tracker.clone(),
            start,
        );
        let host_a_router = Arc::new(Router {
            name: "router1".to_string(),
            link_configs: [(HOST_A_ADDR, config.clone()), (HOST_B_ADDR, config.clone())]
                .into_iter()
                .collect(),
            inbound: [
                (
                    HOST_A_ADDR,
                    Mutex::new(InboundQueue::new(
                        config.link_delay,
                        config.link_capacity,
                        stats_tracker.clone(),
                        start,
                    )),
                ),
                (
                    HOST_B_ADDR,
                    Mutex::new(InboundQueue::new(
                        config.link_delay,
                        config.link_capacity,
                        stats_tracker.clone(),
                        start,
                    )),
                ),
            ]
            .into_iter()
            .collect(),
            outbound: [
                (HOST_A_ADDR, Node::Host(host_a.clone())),
                (HOST_B_ADDR, Node::Router("router2".to_string())),
            ]
            .into_iter()
            .collect(),
        });
        let host_b_router = Arc::new(Router {
            name: "router2".to_string(),
            link_configs: [(HOST_A_ADDR, config.clone()), (HOST_B_ADDR, config.clone())]
                .into_iter()
                .collect(),
            inbound: [
                (
                    HOST_A_ADDR,
                    Mutex::new(InboundQueue::new(
                        config.link_delay,
                        config.link_capacity,
                        stats_tracker.clone(),
                        start,
                    )),
                ),
                (
                    HOST_B_ADDR,
                    Mutex::new(InboundQueue::new(
                        config.link_delay,
                        config.link_capacity,
                        stats_tracker.clone(),
                        start,
                    )),
                ),
            ]
            .into_iter()
            .collect(),
            outbound: [
                (HOST_A_ADDR, Node::Router("router1".to_string())),
                (HOST_B_ADDR, Node::Host(host_b.clone())),
            ]
            .into_iter()
            .collect(),
        });

        let (tx, rx) = tokio::sync::broadcast::channel(10);

        Self {
            host_a,
            host_a_router: host_a_router.clone(),
            host_b,
            host_b_router: host_b_router.clone(),
            router_map: Arc::new(
                [host_a_router, host_b_router]
                    .into_iter()
                    .map(|r| (r.name.clone(), r))
                    .collect(),
            ),
            pcap_exporter,
            stats_tracker,
            rng: Mutex::new(rng),
            start,
            next_transmit_number: Default::default(),
            packet_arrived_tx: tx,
            packet_arrived_rx: rx,
        }
    }

    pub fn subscribe_to_packet_arrived(&self) -> tokio::sync::broadcast::Receiver<PacketArrived> {
        self.packet_arrived_rx.resubscribe()
    }

    /// Returns a handle to host A
    pub fn host_a(self: &Arc<InMemoryNetwork>) -> HostHandle {
        HostHandle {
            host: self.host_a.clone(),
            network: self.clone(),
        }
    }

    /// Returns a handle to host B
    pub fn host_b(self: &Arc<InMemoryNetwork>) -> HostHandle {
        HostHandle {
            host: self.host_b.clone(),
            network: self.clone(),
        }
    }

    /// Returns the host bound to the provided address
    fn host(&self, addr: SocketAddr) -> &Host {
        [&self.host_a, &self.host_b]
            .into_iter()
            .find(|s| s.addr == addr)
            .expect("host does not exist")
    }

    /// Returns the router bound to the provided address
    fn router(&self, addr: SocketAddr) -> &Arc<Router> {
        if addr == self.host_a.addr {
            &self.host_a_router
        } else if addr == self.host_b.addr {
            &self.host_b_router
        } else {
            unreachable!("no router connected to the specified address");
        }
    }

    fn get_link_config(&self, source: &Node, destination: SocketAddr) -> &NetworkConfig {
        match source {
            Node::Router(name) => {
                // Link between a router and another node
                self.router_map[name].link_config(destination)
            }
            Node::Host(source) => {
                // Link between a host and a router
                let router = self.router(source.addr);
                router.link_config(source.addr)
            }
        }
    }

    pub(crate) fn in_transit_data(
        &self,
        now: Instant,
        source_addr: SocketAddr,
        transmit: OwnedTransmit,
    ) -> InTransitData {
        let source_host = self.host(source_addr);
        InTransitData {
            source_addr,
            transmit,
            last_sent: now,
            number: self.next_transmit_number.fetch_add(1, Ordering::Relaxed),
            path: vec![(now, NodeName::Host(source_host.name.to_string()))],
        }
    }

    fn inbound_queue_for_destination(
        &self,
        source: &Node,
        source_addr: SocketAddr,
        destination: SocketAddr,
    ) -> &Mutex<InboundQueue> {
        if let Some(router) = self.target_router_for_destination(source, destination) {
            &router.inbound[&source_addr]
        } else {
            // Destination is a host
            &self.host(destination).inbound
        }
    }

    fn target_router_for_destination(
        &self,
        source: &Node,
        destination: SocketAddr,
    ) -> Option<&Arc<Router>> {
        match source {
            Node::Host(source) => {
                // Hosts are always associated to a router for sending
                Some(self.router(source.addr))
            }
            Node::Router(source_router) => {
                // A router might have a link to another router, or to a host
                let router = &self.router_map[source_router];
                match &router.outbound[&destination] {
                    Node::Router(target_router) => Some(&self.router_map[target_router]),
                    Node::Host(_) => None,
                }
            }
        }
    }

    /// Sends an [`InTransitData`] from a host to its destination
    pub(crate) fn send(
        self: &Arc<InMemoryNetwork>,
        now: Instant,
        source: Node,
        mut data: InTransitData,
    ) {
        data.last_sent = now;
        let mut dropped = false;
        let mut duplicate = false;
        let mut extra_delay = Duration::from_secs(0);
        let transmit_source_addr = data.source_addr;
        let transmit_destination_addr = data.transmit.destination;
        let config = self.get_link_config(&source, data.transmit.destination);

        let roll1 = self.rng.lock().f64();
        if roll1 < config.packet_loss_ratio {
            dropped = true;
        } else if roll1 < config.packet_loss_ratio + config.packet_duplication_ratio {
            duplicate = true;
        }

        let roll2 = self.rng.lock().f64();
        if roll2 < config.link_extra_delay_ratio {
            extra_delay = config.link_extra_delay;
        }

        let congestion_experienced = self.rng.lock().f64() < config.congestion_event_ratio;
        if congestion_experienced {
            // The Quinn-provided transmit must indicate support for ECN
            assert!(data
                .transmit
                .ecn
                .is_some_and(|codepoint| codepoint as u8 == 0b10 || codepoint as u8 == 0b01));

            // Set explicit congestion event codepoint
            data.transmit.ecn = Some(EcnCodepoint::from_bits(0b11).unwrap())
        }

        let queue = self.inbound_queue_for_destination(
            &source,
            transmit_source_addr,
            transmit_destination_addr,
        );

        // A packet could also be dropped if the target doesn't have enough capacity
        let dropped = dropped || !queue.lock().has_enough_capacity(&data, duplicate);
        if dropped {
            // Only track lost packets for hosts, not for routers
            if let Node::Host(source) = &source {
                let source_name = &source.name;
                self.pcap_exporter.track_packet(
                    now,
                    &data,
                    &source.addr,
                    data.transmit.ecn,
                    true,
                    Duration::from_secs(0),
                );
                self.stats_tracker.track_dropped(
                    source.addr,
                    data.transmit.contents.len(),
                    self.pcap_exporter.total_tracked_packets(),
                );

                println!(
                    "{:.2}s WARN {source_name} packet lost (#{})!",
                    self.start.elapsed().as_secs_f64(),
                    self.pcap_exporter.total_tracked_packets(),
                );
            }
        } else {
            let total = if duplicate { 2 } else { 1 };
            let packets = vec![data; total];

            for (i, packet) in packets.into_iter().enumerate() {
                let duplicate = i == 1;
                let mut metadata_index = None;

                // Only track duplicate packets for hosts, not for routers
                if let Node::Host(source) = &source {
                    let source_name = &source.name;
                    self.pcap_exporter.track_packet(
                        now,
                        &packet,
                        &source.addr,
                        packet.transmit.ecn,
                        false,
                        extra_delay,
                    );
                    metadata_index = Some(self.stats_tracker.track_sent(
                        source.addr,
                        packet.transmit.contents.len(),
                        duplicate,
                        self.pcap_exporter.total_tracked_packets(),
                        congestion_experienced,
                    ));

                    if duplicate {
                        println!(
                            "{:.2}s WARN {source_name} sent duplicate packet (#{})!",
                            self.start.elapsed().as_secs_f64(),
                            self.pcap_exporter.total_tracked_packets(),
                        );
                    }

                    if packet.transmit.ecn.is_some_and(|t| t == EcnCodepoint::Ce) {
                        println!(
                            "{:.2}s WARN {source_name} sent packet marked with CE ECN (#{})!",
                            self.start.elapsed().as_secs_f64(),
                            self.pcap_exporter.total_tracked_packets(),
                        );
                    }
                }

                queue.lock().send(packet, metadata_index, extra_delay);
            }
        }

        // If the destination is a router, we need to manually trigger it to process inbound traffic
        // (hosts do so automatically, because quinn polls them)
        if let Some(router) = self.target_router_for_destination(&source, transmit_destination_addr)
        {
            router.handle(self).process_inbound(transmit_source_addr);
        }
    }

    fn notify_packet_arrived(&self, path: Vec<(Instant, NodeName)>, content: Vec<u8>) {
        self.packet_arrived_tx
            .send(PacketArrived { path, content })
            .unwrap();
    }

    pub fn stats(&self) -> NetworkStats {
        let stats_tracker = self.stats_tracker.inner.lock();

        let mut peer_a = EndpointStats::default();
        let mut peer_b = EndpointStats::default();

        for metadata in &stats_tracker.transmits_metadata {
            let endpoint_stats = match metadata.source {
                HOST_B_ADDR => &mut peer_b,
                HOST_A_ADDR => &mut peer_a,
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
                HOST_B_ADDR => &mut peer_b,
                HOST_A_ADDR => &mut peer_a,
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
