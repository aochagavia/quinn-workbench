//! In-memory network implementation
//!
//! Provides an in-memory network with two peers and an arbitrary number of routers in between

pub mod event;
pub(crate) mod inbound_queue;
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
use uuid::Uuid;

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

        let host_a = hosts.remove(0);
        let host_a = Host::from_network_node(host_a)?;
        let host_b = hosts.remove(0);
        let host_b = Host::from_network_node(host_b)?;
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
            let addresses: Vec<_> = r.interfaces.into_iter().flat_map(|i| i.addresses).collect();
            if addresses.is_empty() {
                bail!("found router with no addresses: {}", r.id);
            }

            let mut inbound_links = HashMap::new();
            for (&(source, target), link) in &links_by_addr {
                if addresses.contains(&target) {
                    inbound_links.insert(source, link.clone());
                }
            }

            // TODO: get this from config instead of hardcoding it
            let buffer_size_bytes = 1024 * 1024 * 100;
            let router = Arc::new(Router {
                id: Arc::from(r.id.into_boxed_str()),
                addresses: addresses.clone(),
                outbound_buffer: Arc::new(OutboundBuffer::new(buffer_size_bytes)),
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
            host_a,
            host_b,
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
                    println!("WARN: changing the packet duplication ratio in events is currently unsupported");
                }

                if packet_loss_ratio.is_some() {
                    println!(
                        "WARN: changing the packet loss ratio in events is currently unsupported"
                    );
                }

                if congestion_event_ratio.is_some() {
                    println!("WARN: changing the congestion event ratio in events is currently unsupported");
                }

                let Some(link) = network_clone.links_by_id.get(id.as_str()) else {
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

    /// Returns host A
    pub fn host_a(self: &InMemoryNetwork) -> &Host {
        &self.host_a
    }

    /// Returns host B
    pub fn host_b(self: &InMemoryNetwork) -> &Host {
        &self.host_b
    }

    /// Returns a handle to host A
    pub fn host_a_handle(self: &Arc<InMemoryNetwork>) -> HostHandle {
        HostHandle {
            host: self.host_a.clone(),
            network: self.clone(),
        }
    }

    /// Returns a handle to host B
    pub fn host_b_handle(self: &Arc<InMemoryNetwork>) -> HostHandle {
        HostHandle {
            host: self.host_b.clone(),
            network: self.clone(),
        }
    }

    /// Returns the host bound to the provided address
    pub(crate) fn host(&self, addr: SocketAddr) -> &Host {
        &self.hosts_by_addr[&addr]
    }

    pub async fn assert_connectivity_between_hosts(
        self: &Arc<Self>,
    ) -> anyhow::Result<(Duration, Duration)> {
        let peers = [
            (&self.host_a, self.host_b.addr),
            (&self.host_b, self.host_a.addr),
        ];

        // Send a packet both ways
        for (source, target_addr) in peers {
            let data = self.in_transit_data(
                source.clone(),
                OwnedTransmit {
                    destination: target_addr,
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
        let a_to_b = self.host_b.inbound.lock().receive(1);
        let a_to_b_failed = a_to_b.is_empty();
        let b_to_a = self.host_a.inbound.lock().receive(1);
        let b_to_a_failed = b_to_a.is_empty();

        if a_to_b_failed || b_to_a_failed {
            let report = |failed| if failed { "failed" } else { "succeeded" };
            bail!("failed to deliver packets between the hosts after {days} days (A to B {}, B to A {})", report(a_to_b_failed), report(b_to_a_failed));
        }

        let stepper = self.tracer.stepper();

        Ok((
            stepper
                .get_packet_arrived_at(a_to_b[0].id, &self.host_b.id)
                .unwrap(),
            stepper
                .get_packet_arrived_at(b_to_a[0].id, &self.host_a.id)
                .unwrap(),
        ))
    }

    /// Resolves the link that should be used to go from the node to the destination
    ///
    /// Uses the node's routing table to identify the next hop's link
    fn resolve_link(
        &self,
        node: &Node,
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

            if let Some(link) = self.links_by_addr.get(&(node_addr, next_hop_addr)) {
                return Some(link.clone());
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

        let Some(link) = self.resolve_link(&current_node, data.transmit.destination) else {
            let stepper = self.tracer.stepper();
            let nodes: Vec<_> = stepper.get_packet_path(data.id);
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
            assert!(data
                .transmit
                .ecn
                .is_some_and(|codepoint| codepoint as u8 == 0b10 || codepoint as u8 == 0b01));

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
                            },
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

    if let Some(router) = network.routers_by_addr.get(&link.lock().target) {
        // The packet should be forwarded to the next router, after which it needs to be sent to
        // the next hop (hence the `network.send`)
        let network = network.clone();
        let router = router.clone();
        schedule_forward_packet_inner(link.clone(), next_receive, move |transmit| {
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

        schedule_forward_packet_inner(link.clone(), next_receive, move |transmit| {
            network
                .tracer
                .track_packet_in_node(&Node::Host(host.clone()), &transmit);
            host_queue.lock().send(transmit, Duration::default())
        });
    };
}

fn schedule_forward_packet_inner(
    link: Arc<Mutex<NetworkLink>>,
    next_receive: Instant,
    handle_transmit: impl Fn(InTransitData) + Send + 'static,
) {
    tokio::spawn(async move {
        // Take link delay into account
        tokio::time::sleep_until(next_receive).await;

        // Now transfer inbound to outbound
        let mut link = link.lock();
        let transmits = link.receive(usize::MAX);
        for transmit in transmits {
            handle_transmit(transmit);
        }
    });
}
