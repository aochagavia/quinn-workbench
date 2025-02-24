//! In-memory network implementation
//!
//! Provides an in-memory network with two peers and an arbitrary number of routers in between

pub mod event;
pub(crate) mod inbound_queue;
pub mod ip;
pub mod link;
pub mod node;
mod outbound_buffer;
pub mod route;
pub mod spec;

use crate::network::event::{NetworkEventPayload, NetworkEvents, UpdateLinkStatus};
use crate::network::link::LinkStatus;
use crate::network::node::{Host, HostHandle, Node};
use crate::network::outbound_buffer::OutboundBuffer;
use crate::network::spec::{NetworkSpec, NodeKind};
use crate::tracing::tracer::SimulationStepTracer;
use crate::{HOST_PORT, InTransitData, OwnedTransmit};
use anyhow::bail;
use fastrand::Rng;
use link::NetworkLink;
use node::Router;
use parking_lot::Mutex;
use quinn::udp::EcnCodepoint;
use route::Route;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PacketArrived {
    pub path: Vec<(Instant, Arc<str>)>,
    pub content: Vec<u8>,
}

/// A network between two hosts, with multiple routers in between
pub struct InMemoryNetwork {
    /// Map from socket addresses to the corresponding host object
    hosts_by_addr: HashMap<SocketAddr, Host>,
    /// Map from ip addresses to the corresponding router object
    routers_by_addr: Arc<HashMap<IpAddr, Arc<Router>>>,
    /// Map from ip addresses to the available route information
    routes_by_addr: Arc<HashMap<IpAddr, Arc<Vec<Route>>>>,
    /// Map from ip address pairs to the corresponding links
    links_by_addr: Arc<HashMap<(IpAddr, IpAddr), Arc<Mutex<NetworkLink>>>>,
    /// Map from ids the corresponding links
    links_by_id: Arc<HashMap<Arc<str>, Arc<Mutex<NetworkLink>>>>,
    pub(crate) tracer: Arc<SimulationStepTracer>,
    rng: Mutex<Rng>,
    next_transmit_number: AtomicU64,
}

impl InMemoryNetwork {
    /// Initializes a new [`InMemoryNetwork`] based on the provided spec
    pub fn initialize(
        network_spec: NetworkSpec,
        events: NetworkEvents,
        tracer: Arc<SimulationStepTracer>,
        rng: Rng,
        start: Instant,
    ) -> anyhow::Result<Arc<Self>> {
        let mut routes_by_addr = HashMap::new();
        let all_node_interfaces = network_spec.nodes.iter().map(|n| &n.interfaces);
        for single_node_interfaces in all_node_interfaces {
            for interface in single_node_interfaces {
                for interface_addr in &interface.addresses {
                    let mut routes = interface.routes.clone();
                    routes.sort_by_key(|r| r.cost); // ascending order
                    routes_by_addr.insert(interface_addr.as_ip_addr(), Arc::new(routes));
                }
            }
        }

        let (hosts, routers): (Vec<_>, _) = network_spec
            .nodes
            .into_iter()
            .partition(|n| n.kind == NodeKind::Host);
        if hosts.len() < 2 {
            bail!(
                "Expected at least two hosts in network graph, found {}",
                hosts.len()
            );
        }

        let mut hosts_by_addr = HashMap::new();
        for host in hosts {
            let h = Host::from_network_node(host)?;
            let already_existing = hosts_by_addr.insert(h.addr, h);

            if let Some(host) = already_existing {
                bail!(
                    "Expected hosts to have unique ip addresses, but at least two hosts are using {}",
                    host.addr.ip()
                );
            }
        }

        let mut links_by_addr = HashMap::new();
        let mut links_by_id = HashMap::new();
        let mut link_initial_statuses = events.initial_link_statuses;
        for l in network_spec.links {
            let id = l.id.clone();
            let source = l.source;
            let target = l.target;
            let status = link_initial_statuses
                .remove(id.as_ref())
                .unwrap_or(LinkStatus::Up);

            let l = Arc::new(Mutex::new(NetworkLink::new(l, tracer.clone(), status)));
            let conflicting_link = links_by_addr.insert((source, target), l.clone());
            if let Some(conflicting_link) = conflicting_link {
                bail!(
                    "links {} and {} share the same address pair: {} -> {}",
                    id,
                    conflicting_link.lock().id,
                    source,
                    target
                );
            }

            let conflicting_link = links_by_id.insert(id.clone(), l);
            if conflicting_link.is_some() {
                bail!("there is more than one link with id {}", id,);
            }
        }

        let mut routers_by_addr = HashMap::new();
        for r in routers {
            let addresses: Vec<_> = r
                .interfaces
                .into_iter()
                .flat_map(|i| {
                    i.addresses
                        .iter()
                        .map(|a| a.as_ip_addr())
                        .collect::<Vec<_>>()
                })
                .collect();
            if addresses.is_empty() {
                bail!("found router with no addresses: {}", r.id);
            }

            let mut inbound_links = HashMap::new();
            for (&(source, target), link) in &links_by_addr {
                if addresses.contains(&target) {
                    inbound_links.insert(source, link.clone());
                }
            }

            let router = Arc::new(Router {
                id: r.id.into(),
                addresses: addresses.clone(),
                outbound_buffer: Arc::new(OutboundBuffer::new(r.buffer_size_bytes as usize)),
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

        let network = Arc::new(Self {
            hosts_by_addr,
            routers_by_addr: Arc::new(routers_by_addr),
            routes_by_addr: Arc::new(routes_by_addr),
            links_by_addr: Arc::new(links_by_addr),
            links_by_id: Arc::new(links_by_id),
            tracer,
            rng: Mutex::new(rng),
            next_transmit_number: Default::default(),
        });

        // Process events in the background
        let network_clone = network.clone();
        tokio::spawn(async move {
            for event in events.sorted_events.into_iter() {
                // Wait until next event should run
                tokio::time::sleep_until(start + event.relative_time).await;

                let NetworkEventPayload {
                    link_id: id,
                    status,
                    bandwidth_bps,
                    delay,
                    extra_delay,
                    extra_delay_ratio,
                    packet_duplication_ratio,
                    packet_loss_ratio,
                    congestion_event_ratio,
                } = event.payload;

                if bandwidth_bps.is_some() {
                    println!("WARN: changing the bandwidth in events is currently unsupported");
                }

                if delay.is_some() {
                    println!("WARN: changing the delay in events is currently unsupported");
                }

                if extra_delay.is_some() {
                    println!("WARN: changing the extra delay in events is currently unsupported");
                }

                if extra_delay_ratio.is_some() {
                    println!(
                        "WARN: changing the extra delay ratio in events is currently unsupported"
                    );
                }

                if packet_duplication_ratio.is_some() {
                    println!(
                        "WARN: changing the packet duplication ratio in events is currently unsupported"
                    );
                }

                if packet_loss_ratio.is_some() {
                    println!(
                        "WARN: changing the packet loss ratio in events is currently unsupported"
                    );
                }

                if congestion_event_ratio.is_some() {
                    println!(
                        "WARN: changing the congestion event ratio in events is currently unsupported"
                    );
                }

                let Some(link) = network_clone.links_by_id.get(&id) else {
                    println!("WARN: skipping received event for link that doesn't exist ({id})");
                    continue;
                };

                link.lock()
                    .update_status(status.unwrap_or(UpdateLinkStatus::Up));
            }
        });

        Ok(network)
    }

    pub fn get_link_status(&self, link_id: &str) -> &'static str {
        self.links_by_id[link_id].lock().status_str()
    }

    /// Returns a handle to the provided host
    pub fn host_handle(self: &Arc<InMemoryNetwork>, host: Host) -> HostHandle {
        HostHandle {
            host,
            network: self.clone(),
        }
    }

    /// Returns the host bound to the provided address
    pub fn host(self: &InMemoryNetwork, ip: IpAddr) -> &Host {
        &self.hosts_by_addr[&SocketAddr::new(ip, HOST_PORT)]
    }

    /// Returns the host bound to the provided address
    pub(crate) fn host_internal(&self, addr: SocketAddr) -> &Host {
        &self.hosts_by_addr[&addr]
    }

    pub async fn assert_connectivity_between_hosts(
        self: &Arc<Self>,
        host_a_addr: IpAddr,
        host_b_addr: IpAddr,
    ) -> anyhow::Result<(Duration, Duration)> {
        let host_a = self.host(host_a_addr);
        let host_b = self.host(host_b_addr);
        let peers = [(host_a, host_b), (host_b, host_a)];

        // Send a packet both ways
        for (source, target) in peers {
            let data = self.in_transit_data(
                source.clone(),
                OwnedTransmit {
                    destination: target.addr,
                    ecn: None,
                    contents: vec![42],
                    segment_size: None,
                },
            );

            self.forward(Node::Host(source.clone()), data);
        }

        // Wait for 90 days for the packets to arrive
        let days = 90;
        tokio::time::sleep(Duration::from_secs(3600 * 24 * days)).await;

        // Ensure the packets arrived at each host
        let a_to_b = host_b.inbound.lock().receive(1);
        let a_to_b_failed = a_to_b.is_empty();
        let b_to_a = host_a.inbound.lock().receive(1);
        let b_to_a_failed = b_to_a.is_empty();

        if a_to_b_failed || b_to_a_failed {
            let report = |failed| if failed { "failed" } else { "succeeded" };
            bail!(
                "failed to deliver packets between the hosts after {days} days (A to B {}, B to A {})",
                report(a_to_b_failed),
                report(b_to_a_failed)
            );
        }

        let stepper = self.tracer.stepper();

        Ok((
            stepper
                .get_packet_arrived_at(a_to_b[0].id, &host_b.id)
                .unwrap(),
            stepper
                .get_packet_arrived_at(b_to_a[0].id, &host_a.id)
                .unwrap(),
        ))
    }

    /// Resolves the link that should be used to go from the node to the destination
    fn resolve_link(&self, node: &Node, data: &InTransitData) -> Option<Arc<Mutex<NetworkLink>>> {
        // If no links are found in the first try, try again allowing local buffering
        self.resolve_link_internal(node, data, false)
            .or_else(|| self.resolve_link_internal(node, data, true))
    }

    fn resolve_link_internal(
        &self,
        node: &Node,
        data: &InTransitData,
        allow_buffering: bool,
    ) -> Option<Arc<Mutex<NetworkLink>>> {
        // Prefer direct links if available
        for node_addr in node.addresses() {
            if let Some(link) = self
                .links_by_addr
                .get(&(node_addr, data.transmit.destination.ip()))
            {
                let bandwidth_available = link.lock().has_bandwidth_available(data);
                if bandwidth_available || allow_buffering {
                    return Some(link.clone());
                }
            }
        }

        // Use routing when no direct links are available
        for node_addr in node.addresses() {
            let routes = &self.routes_by_addr[&node_addr];
            let Some(next_hop_addr) = routes
                .iter()
                .find_map(|r| r.next_hop_towards_destination(data.transmit.destination.ip()))
            else {
                // No route found for this node's address, try another one
                continue;
            };

            if let Some(link) = self.links_by_addr.get(&(node_addr, next_hop_addr)) {
                let bandwidth_available = link.lock().has_bandwidth_available(data);
                if bandwidth_available || allow_buffering {
                    return Some(link.clone());
                }
            }
        }

        None
    }

    pub(crate) fn in_transit_data(&self, source: Host, transmit: OwnedTransmit) -> InTransitData {
        InTransitData {
            id: Uuid::new_v4(),
            duplicate: false,
            source,
            transmit,
            number: self.next_transmit_number.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Forwards an [`InTransitData`] to the next node in the network.
    ///
    /// Resolves the link through which the packet should be sent and attempts to send it right
    /// away. If the link is temporarily unavailable or saturated, stores the packet in the node's
    /// buffer (or drops it when the buffer is full).
    pub(crate) fn forward(
        self: &Arc<InMemoryNetwork>,
        current_node: Node,
        mut data: InTransitData,
    ) {
        self.tracer.track_packet_in_node(&current_node, &data);

        let Some(link) = self.resolve_link(&current_node, &data) else {
            let nodes = self.tracer.stepper().get_packet_path(data.id);
            let mut path = nodes.join(" -> ");
            path.push_str(" -> ?");

            println!(
                "Network error: missing link to {} ({path})",
                data.transmit.destination
            );
            return;
        };

        let mut randomly_dropped = false;
        let mut duplicate = false;
        let congestion_experienced;
        let mut extra_delay = Duration::from_secs(0);

        // Concurrency: limit the lock guard's lifetime
        {
            let link = link.lock();
            let roll1 = self.rng.lock().f64();
            if roll1 < link.packet_loss_ratio {
                randomly_dropped = true;
            } else if roll1 < link.packet_loss_ratio + link.packet_duplication_ratio {
                duplicate = true;
            }

            let roll2 = self.rng.lock().f64();
            if roll2 < link.extra_delay_ratio {
                extra_delay = link.extra_delay;
            }

            congestion_experienced = self.rng.lock().f64() < link.congestion_event_ratio;
        }

        if randomly_dropped {
            self.tracer.track_dropped_randomly(&data, &current_node);
            return;
        }

        if congestion_experienced {
            // The Quinn-provided transmit must indicate support for ECN
            assert!(
                data.transmit
                    .ecn
                    .is_some_and(|codepoint| codepoint as u8 == 0b10 || codepoint as u8 == 0b01)
            );

            // Set explicit congestion event codepoint
            data.transmit.ecn = Some(EcnCodepoint::from_bits(0b11).unwrap())
        }

        let transmit_destination_addr = data.transmit.destination;

        let maybe_duplicate = duplicate.then(|| {
            let mut duplicate_data = data.clone();
            duplicate_data.id = Uuid::new_v4();
            duplicate_data.duplicate = true;
            duplicate_data
        });

        let mut packets = vec![data];
        packets.extend(maybe_duplicate);

        for packet in packets.into_iter() {
            self.tracer.track_injected_failures(
                &packet,
                duplicate && packet.duplicate,
                extra_delay,
                congestion_experienced,
                &current_node,
            );

            let link_is_saturated = !link.lock().has_bandwidth_available(&packet);
            if link_is_saturated {
                // Try to enqueue the data on the node's outbound buffer for later sending
                let outbound_buffer = current_node.outbound_buffer();
                let data_len = packet.transmit.contents.len();

                if outbound_buffer.reserve(data_len) {
                    // The buffer has capacity!
                    let sent = NetworkLink::send_when_bandwidth_available(
                        link.clone(),
                        current_node.clone(),
                        packet,
                        extra_delay,
                    );
                    let network = self.clone();
                    let link = link.clone();

                    // When the packet is finally sent, we can release capacity from the outbound
                    // buffer and forward the packet
                    tokio::spawn(async move {
                        match sent.await {
                            Ok(_) => {
                                outbound_buffer.release(data_len);
                                schedule_forward_packet(network, link, transmit_destination_addr);
                            }
                            Err(_) => println!(
                                "ERROR: channel closed while waiting for bandwidth to become available"
                            ),
                        }
                    });
                } else {
                    // The buffer is full and the packet is being dropped
                    let link = link.lock();
                    self.tracer
                        .track_dropped_from_buffer(&packet, &current_node, &link);
                }

                // The link is saturated, so there's nothing else to do for this packet
                continue;
            }

            link.lock().send(&current_node, packet, extra_delay);
        }

        schedule_forward_packet(self.clone(), link.clone(), transmit_destination_addr);
    }
}

fn schedule_forward_packet(
    network: Arc<InMemoryNetwork>,
    link: Arc<Mutex<NetworkLink>>,
    transmit_destination_addr: SocketAddr,
) {
    let Some(next_receive) = link.lock().time_of_next_receive() else {
        // There are no packets waiting to be received in the link (e.g. maybe they were
        // dropped or are being buffered)
        return;
    };

    let tracer = network.tracer.clone();
    if let Some(router) = network.routers_by_addr.get(&link.lock().target) {
        // The packet should be forwarded to the next router, after which it needs to be sent to
        // the next hop (hence the `network.send`)
        let network = network.clone();
        let router = router.clone();
        schedule_forward_packet_inner(tracer, link.clone(), next_receive, move |transmit| {
            network.forward(Node::Router(router.clone()), transmit);
        });
    } else {
        // The packet should be forwarded to the final host's inbound queue (from where it will
        // be automatically picked up by quinn)
        let host = network
            .hosts_by_addr
            .get(&transmit_destination_addr)
            .unwrap()
            .clone();
        let host_queue = host.inbound.clone();

        schedule_forward_packet_inner(tracer, link.clone(), next_receive, move |transmit| {
            network
                .tracer
                .track_packet_in_node(&Node::Host(host.clone()), &transmit);
            host_queue.lock().send(transmit, Duration::default())
        });
    };
}

fn schedule_forward_packet_inner(
    tracer: Arc<SimulationStepTracer>,
    link: Arc<Mutex<NetworkLink>>,
    next_receive: Instant,
    handle_transmit: impl Fn(InTransitData) + Send + 'static,
) {
    tokio::spawn(async move {
        // Take link delay into account
        tokio::time::sleep_until(next_receive).await;

        // Now receive the packets
        let mut link = link.lock();
        let transmits = link.receive(usize::MAX);

        // Only handle the packets if the link is up, otherwise track them as lost
        if link.is_up() {
            for transmit in transmits {
                handle_transmit(transmit);
            }
        } else {
            for transmit in transmits {
                tracer.track_lost_in_transit(&transmit, &link);
            }
        }
    });
}
