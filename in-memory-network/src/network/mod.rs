//! In-memory network implementation
//!
//! Provides an in-memory network with two peers and an arbitrary number of routers in between

pub mod event;
pub(crate) mod inbound_queue;
pub mod link;
pub mod node;
pub mod route;
pub mod spec;

use crate::network::event::NetworkEvent;
use crate::network::inbound_queue::InboundQueue;
use crate::network::link::LinkStatus;
use crate::network::node::{Host, HostHandle, Node};
use crate::network::spec::{NetworkSpec, NodeKind};
use crate::pcap_exporter::PcapExporter;
use crate::stats_tracker::{EndpointStats, NetworkStats, NetworkStatsTracker};
use crate::{InTransitData, OwnedTransmit};
use anyhow::bail;
use fastrand::Rng;
use link::NetworkLink;
use node::Router;
use parking_lot::Mutex;
use quinn::udp::EcnCodepoint;
use route::Route;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Clone, Debug)]
pub struct PacketArrived {
    pub path: Vec<(Instant, Arc<str>)>,
    pub content: Vec<u8>,
}

/// A network between two hosts, with multiple routers in between
pub struct InMemoryNetwork {
    pub(crate) host_a: Host,
    pub(crate) host_b: Host,
    /// Map from socket addresses to the corresponding host object
    hosts_by_addr: HashMap<SocketAddr, Host>,
    /// Map from ip addresses to the corresponding router object
    routers_by_addr: Arc<HashMap<IpAddr, Arc<Router>>>,
    /// Map from ip addresses to the available route information
    routes_by_addr: Arc<HashMap<IpAddr, Arc<Vec<Route>>>>,
    /// Map from ip address pairs to the corresponding links
    links: Arc<HashMap<(IpAddr, IpAddr), Arc<Mutex<NetworkLink>>>>,
    pcap_exporter: Arc<PcapExporter>,
    stats_tracker: NetworkStatsTracker,
    rng: Mutex<Rng>,
    start: Instant,
    next_transmit_number: AtomicU64,
    packet_arrived_tx: tokio::sync::broadcast::Sender<PacketArrived>,
    packet_arrived_rx: tokio::sync::broadcast::Receiver<PacketArrived>,
}

impl InMemoryNetwork {
    /// Initializes a new [`InMemoryNetwork`] based on the provided spec
    pub fn initialize(
        network_spec: NetworkSpec,
        _events: Vec<NetworkEvent>,
        pcap_exporter: Arc<PcapExporter>,
        rng: Rng,
        start: Instant,
    ) -> anyhow::Result<Self> {
        let mut routes_by_addr = HashMap::new();
        let routes = network_spec
            .nodes
            .iter()
            .map(|n| (&n.interfaces, &n.routes));
        for (interfaces, routes) in routes {
            for &addr in interfaces.iter().flat_map(|i| &i.addresses) {
                routes_by_addr.insert(addr, Arc::new(routes.clone()));
            }
        }

        let (mut hosts, routers): (Vec<_>, _) = network_spec
            .nodes
            .into_iter()
            .partition(|n| n.kind == NodeKind::Host);
        if hosts.is_empty() {
            bail!("Expected exactly two hosts in network graph, found zero");
        } else if hosts.len() != 2 {
            let ids: Vec<_> = hosts.into_iter().map(|h| h.id).collect();
            bail!(
                "Expected exactly two hosts in network graph, found a different amount: {}",
                ids.join(", ")
            );
        }

        let stats_tracker = NetworkStatsTracker::new();
        let host_a = hosts.remove(0);
        let host_a = Host::from_network_node(host_a, stats_tracker.clone(), start)?;
        let host_b = hosts.remove(0);
        let host_b = Host::from_network_node(host_b, stats_tracker.clone(), start)?;
        let hosts_by_addr = [host_a.clone(), host_b.clone()]
            .into_iter()
            .map(|h| (h.addr, h))
            .collect();

        if host_a.addr.ip() == host_b.addr.ip() {
            bail!(
                "Expected hosts to have different ip addresses, found the same: {}",
                host_a.addr.ip()
            );
        }

        let mut links = HashMap::new();
        for l in network_spec.links {
            let source = l.source;
            let target = l.target;
            let l = Arc::new(Mutex::new(NetworkLink {
                id: l.id,
                status: LinkStatus::Up,
                target,
                queue: InboundQueue::new(l.delay, l.capacity_bytes, stats_tracker.clone(), start),
                congestion_event_ratio: l.congestion_event_ratio,
                packet_loss_ratio: l.packet_loss_ratio,
                packet_duplication_ratio: l.packet_duplication_ratio,
                extra_delay: l.extra_delay,
                extra_delay_ratio: l.extra_delay_ratio,
            }));
            let conflicting_link = links.insert((source, target), l.clone());
            if let Some(conflicting_link) = conflicting_link {
                bail!(
                    "links {} and {} share the same address pair: {} -> {}",
                    l.lock().id,
                    conflicting_link.lock().id,
                    source,
                    target
                );
            }
        }

        let mut routers_by_addr = HashMap::new();
        for r in routers {
            let addresses: Vec<_> = r.interfaces.into_iter().flat_map(|i| i.addresses).collect();
            if addresses.is_empty() {
                bail!("found router with no addresses: {}", r.id);
            }

            let mut inbound_links = HashMap::new();
            for (&(source, target), link) in &links {
                if addresses.contains(&target) {
                    inbound_links.insert(source, link.clone());
                }
            }

            let router = Arc::new(Router {
                id: Arc::from(r.id.into_boxed_str()),
                addresses: addresses.clone(),
            });

            for address in addresses {
                let address_taken = routers_by_addr.insert(address, router.clone());
                if let Some(conflicting_router) = address_taken {
                    bail!(
                        "routers {} and {} share the same address: {}",
                        router.id,
                        conflicting_router.id,
                        address
                    );
                }
            }
        }

        let (tx, rx) = tokio::sync::broadcast::channel(10);

        Ok(Self {
            host_a,
            host_b,
            hosts_by_addr,
            routers_by_addr: Arc::new(routers_by_addr),
            routes_by_addr: Arc::new(routes_by_addr),
            links: Arc::new(links),
            pcap_exporter,
            stats_tracker,
            rng: Mutex::new(rng),
            start,
            next_transmit_number: Default::default(),
            packet_arrived_tx: tx,
            packet_arrived_rx: rx,
        })
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
    pub(crate) fn host(&self, addr: SocketAddr) -> &Host {
        &self.hosts_by_addr[&addr]
    }

    pub async fn assert_connectivity_between_hosts(self: &Arc<Self>) -> anyhow::Result<()> {
        let now = Instant::now();

        let peers = [
            (&self.host_a, self.host_b.addr),
            (&self.host_b, self.host_a.addr),
        ];

        // Send a packet both ways
        for (source, target_addr) in peers {
            let data = self.in_transit_data(
                now,
                source.addr,
                OwnedTransmit {
                    destination: target_addr,
                    ecn: None,
                    contents: vec![42],
                    segment_size: None,
                },
            );

            self.send(now, source, data);
        }

        // Wait for 90 days for the packets to arrive
        let days = 90;
        tokio::time::sleep(Duration::from_secs(3600 * 24 * days)).await;

        // Ensure the packets arrived at each host
        let a_to_b_failed = self.host_b.inbound.lock().receive(1).is_empty();
        let b_to_a_failed = self.host_a.inbound.lock().receive(1).is_empty();

        if a_to_b_failed || b_to_a_failed {
            let report = |failed| if failed { "failed" } else { "succeeded" };
            bail!("failed to deliver packets between the hosts after {days} days (A to B {}, B to A {})", report(a_to_b_failed), report(b_to_a_failed));
        }

        Ok(())
    }

    fn node_to_host(&self, node: &impl Node) -> Option<&Host> {
        let mut addresses = node.addresses();
        match (addresses.next(), addresses.next()) {
            (Some(addr), None) => self
                .hosts_by_addr
                .iter()
                .find(|(key, _)| key.ip() == addr)
                .map(|(_, host)| host),
            _ => None,
        }
    }

    /// Resolves the link that should be used to go from the node to the destination
    ///
    /// Uses the node's routing table to identify the next hop's link
    fn resolve_link(
        &self,
        node: &impl Node,
        destination: SocketAddr,
    ) -> Option<Arc<Mutex<NetworkLink>>> {
        for node_addr in node.addresses() {
            let routes = &self.routes_by_addr[&node_addr];
            let Some(next_hop_addr) = routes
                .iter()
                .find_map(|r| r.next_hop_towards_destination(destination.ip()))
            else {
                // No route found for this node's address, try another one
                continue;
            };

            if let Some(link) = self.links.get(&(node_addr, next_hop_addr)) {
                return Some(link.clone());
            }
        }

        None
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
            path: vec![(now, source_host.id.clone())],
        }
    }

    /// Sends an [`InTransitData`] from one node to the next
    pub(crate) fn send(
        self: &Arc<InMemoryNetwork>,
        now: Instant,
        previous_node: &impl Node,
        mut data: InTransitData,
    ) {
        data.last_sent = now;
        let mut dropped = false;
        let mut duplicate = false;
        let congestion_experienced;
        let mut extra_delay = Duration::from_secs(0);
        let transmit_destination_addr = data.transmit.destination;

        let Some(link) = self.resolve_link(previous_node, data.transmit.destination) else {
            let nodes: Vec<_> = data.path.into_iter().map(|(_, n)| n).collect();
            let mut path = nodes.join(" -> ");
            path.push_str(" -> ?");

            println!(
                "Network error: missing link to {} ({path})",
                data.transmit.destination
            );
            return;
        };

        // Concurrency: limit the lock guard's lifetime
        {
            let link = link.lock();
            let roll1 = self.rng.lock().f64();
            if roll1 < link.packet_loss_ratio {
                dropped = true;
            } else if roll1 < link.packet_loss_ratio + link.packet_duplication_ratio {
                duplicate = true;
            }

            let roll2 = self.rng.lock().f64();
            if roll2 < link.extra_delay_ratio {
                extra_delay = link.extra_delay;
            }

            congestion_experienced = self.rng.lock().f64() < link.congestion_event_ratio;
        }

        if congestion_experienced {
            // The Quinn-provided transmit must indicate support for ECN
            assert!(data
                .transmit
                .ecn
                .is_some_and(|codepoint| codepoint as u8 == 0b10 || codepoint as u8 == 0b01));

            // Set explicit congestion event codepoint
            data.transmit.ecn = Some(EcnCodepoint::from_bits(0b11).unwrap())
        }

        // A packet could also be dropped if the target doesn't have enough capacity
        let dropped = dropped || !link.lock().queue.has_enough_capacity(&data, duplicate);
        if dropped {
            // Only track lost packets for hosts, not for routers
            if let Some(source) = self.node_to_host(previous_node) {
                let source_name = &source.id;
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
                if let Some(source) = self.node_to_host(previous_node) {
                    let source_name = &source.id;
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

                link.lock().queue.send(packet, metadata_index, extra_delay);
            }
        }

        // Schedule the packet to be forwarded at the `next_receive` instant
        let next_receive = link.lock().queue.time_of_next_receive().unwrap();
        if let Some(router) = self.routers_by_addr.get(&link.lock().target) {
            // The packet should be forwarded to the next router, after which it needs to be sent to
            // the next hop (hence the `network.send`)
            let network = self.clone();
            let router = router.clone();
            schedule_forward_packet(link.clone(), next_receive, move |mut transmit| {
                // Update the packet's path
                transmit.path.push((Instant::now(), router.id.clone()));

                // Send to next hop
                network.send(Instant::now(), &*router, transmit);
            });
        } else {
            // The packet should be forwarded to the final host's inbound queue (from where it will
            // be automatically picked up by quinn)
            let host = self.hosts_by_addr.get(&transmit_destination_addr).unwrap();
            let host_queue = host.inbound.clone();
            schedule_forward_packet(link.clone(), next_receive, move |transmit| {
                host_queue.lock().send(transmit, None, Duration::default())
            });
        };
    }

    pub(crate) fn notify_packet_arrived(&self, path: Vec<(Instant, Arc<str>)>, content: Vec<u8>) {
        self.packet_arrived_tx
            .send(PacketArrived { path, content })
            .unwrap();
    }

    pub fn stats(&self) -> NetworkStats {
        let stats_tracker = self.stats_tracker.inner.lock();

        let peer_a_addr = self.host_a.addr;
        let mut peer_a = EndpointStats::default();
        let peer_b_addr = self.host_b.addr;
        let mut peer_b = EndpointStats::default();

        for metadata in &stats_tracker.transmits_metadata {
            let endpoint_stats = match metadata.source {
                addr if addr == peer_a_addr => &mut peer_b,
                addr if addr == peer_b_addr => &mut peer_a,
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
                addr if addr == peer_a_addr => &mut peer_b,
                addr if addr == peer_b_addr => &mut peer_a,
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

fn schedule_forward_packet(
    link: Arc<Mutex<NetworkLink>>,
    next_receive: Instant,
    handle_transmit: impl Fn(InTransitData) + Send + 'static,
) {
    tokio::spawn(async move {
        // Take link delay into account
        tokio::time::sleep_until(next_receive).await;

        // Now transfer inbound to outbound
        let mut link = link.lock();
        let transmits = link.queue.receive(usize::MAX);
        for transmit in transmits {
            handle_transmit(transmit);
        }
    });
}
