use crate::network::event::{NetworkEvent, NetworkEvents, UpdateLinkStatus};
use crate::network::link::LinkStatus;
use crate::network::spec::{NetworkSpec, NodeKind};
use crate::tracing::simulation_step::{
    GenericPacketEvent, PacketDropped, SimulationStep, SimulationStepKind,
};
use crate::tracing::simulation_verifier::InvalidSimulation::PacketCreatedByRouterNode;
use crate::tracing::simulation_verifier::replayed::ReplayedLink;
use crate::tracing::stats::{NodeStats, PacketStats};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, mem};
use thiserror::Error;
use uuid::Uuid;

pub struct VerifiedSimulation {
    pub stats_by_node: HashMap<Arc<str>, NodeStats>,
}

#[derive(Error, Debug)]
pub enum InvalidSimulation {
    #[error("network node `{node_id}` was referenced but does not exist")]
    MissingNode { node_id: Arc<str> },
    #[error("network link `{link_id}` was referenced but does not exist")]
    MissingLink { link_id: Arc<str> },
    #[error("network node received packet with id `{packet_id}` multiple times")]
    PacketAlreadyReceived { packet_id: Uuid },
    #[error("network node `{node_id}` created a packet out of thin air (packet `{packet_id}`)")]
    PacketCreatedByRouterNode { node_id: Arc<str>, packet_id: Uuid },
    #[error(
        "network node removed packet `{packet_id}` from its buffer, but according to the trace the packet was not present at all"
    )]
    MissingPacket { packet_id: Uuid },
    #[error(
        "packet `{packet_id}` was marked as lost in transit, but according to the trace the packet was not in transit at that moment"
    )]
    MissingLostPacket { packet_id: Uuid },
    #[error(
        "network node `{node_id}` sent a packet through link `{link_id}`, but said link was unavailable at this point in time (it was either saturated, down, or not even connected to the source node)"
    )]
    InvalidPacketSend {
        node_id: Arc<str>,
        link_id: Arc<str>,
    },
    #[error(
        "network node `{node_id}` received a packet through link `{link_id}`, but said link became unavailable while the packet was in flight"
    )]
    InvalidPacketReceive {
        node_id: Arc<str>,
        link_id: Arc<str>,
    },
}

#[derive(Default)]
pub struct SimulationVerifier {
    steps: Vec<SimulationStep>,
    /// Map from node ids to their associated state
    nodes: HashMap<Arc<str>, ReplayedNode>,
    /// Map from link ids to their associated state
    links: HashMap<Arc<str>, ReplayedLink>,
    /// Map from packet ids to the links where they can be found
    in_flight_packets: HashMap<Uuid, InFlightPacket>,
    /// Ids of nodes considered to be hosts
    host_nodes: HashSet<Arc<str>>,
    /// Network events
    network_events: Vec<NetworkEvent>,
}

impl SimulationVerifier {
    pub fn new(
        mut steps: Vec<SimulationStep>,
        network_spec: &NetworkSpec,
        events: NetworkEvents,
    ) -> Self {
        if !steps.is_sorted_by_key(|s| s.relative_time) {
            steps.sort_unstable_by_key(|s| s.relative_time);
        }

        let network_spec = network_spec.clone();

        let mut replayed_nodes = HashMap::new();
        let mut host_nodes = HashSet::new();
        for node in network_spec.nodes {
            let node_id: Arc<str> = node.id.clone().into();
            if let NodeKind::Host = node.kind {
                host_nodes.insert(node_id.clone());
            }
            replayed_nodes.insert(node_id, ReplayedNode::default());
        }

        let mut replayed_links = HashMap::new();
        for link in network_spec.links {
            replayed_links.insert(link.id, ReplayedLink::default());
        }

        for (link_id, status) in events.initial_link_statuses {
            if let LinkStatus::Down { .. } = status {
                if let Some(link) = replayed_links.get_mut(&link_id) {
                    link.set_status(UpdateLinkStatus::Down, Duration::from_secs(0));
                }
            }
        }

        Self {
            steps,
            nodes: replayed_nodes,
            links: replayed_links,
            host_nodes,
            network_events: events.sorted_events,
            ..Default::default()
        }
    }

    pub fn verify(mut self) -> Result<VerifiedSimulation, InvalidSimulation> {
        let events = mem::take(&mut self.network_events);
        let mut peekable_events = events.iter().peekable();
        let steps = mem::take(&mut self.steps);
        for step in steps {
            let next_step = step.relative_time;

            // Process any pending events before going to the next step
            loop {
                match peekable_events.peek() {
                    Some(e) if e.relative_time <= next_step => {
                        // Update status if the link exists (we ignore updates for links that have
                        // events but are not part of the network)
                        if let Some(status) = e.payload.status {
                            if let Some(link) = self.links.get_mut(&e.payload.link_id) {
                                link.set_status(status, e.relative_time);
                            }
                        }

                        // Advance the iterator
                        peekable_events.next();
                    }
                    _ => break,
                }
            }

            match &step.kind {
                SimulationStepKind::PacketInNode(s) => {
                    if let Some(in_flight) = self.in_flight_packets.remove(&s.packet_id) {
                        // TODO 1: check that the link is actually connected to the target node (we already checked that the link is connected to the source, when sending)

                        // Check that the link didn't go down after sending (i.e. forbid up -> down -> up)
                        let link = self.link(&in_flight.link_id)?;
                        if link
                            .last_down()
                            .is_some_and(|timestamp| timestamp >= in_flight.sent_at_relative)
                        {
                            return Err(InvalidSimulation::InvalidPacketReceive {
                                node_id: s.node_id.clone(),
                                link_id: in_flight.link_id,
                            });
                        }

                        self.node(&s.node_id)?.packet_received(s)?;
                    } else {
                        // The packet was not in flight, so it must have just been created at
                        // one of the hosts
                        if !self.host_nodes.contains(&s.node_id) {
                            return Err(PacketCreatedByRouterNode {
                                node_id: s.node_id.clone(),
                                packet_id: s.packet_id,
                            });
                        }

                        self.node(&s.node_id)?.packet_created(s)?;
                    }

                    // TODO: check that node never exceeds its outbound buffer size (or, check it at the end)
                }
                SimulationStepKind::PacketDuplicated(s) => {
                    self.node(&s.node_id)?.packet_duplicated(s)?;
                }
                SimulationStepKind::PacketDropped(s) => {
                    self.node(&s.node_id)?.packet_dropped(s)?;
                }
                SimulationStepKind::PacketLostInTransit(s) => {
                    let packet = self.in_flight_packets.remove(&s.packet_id);
                    if packet.is_none() {
                        return Err(InvalidSimulation::MissingLostPacket {
                            packet_id: s.packet_id,
                        });
                    }
                }
                SimulationStepKind::PacketInTransit(s) => {
                    self.node(&s.node_id)?.packet_sent(s.packet_id)?;

                    // TODO: check that the link is actually connected to the source node
                    // TODO: check that the link is not saturated
                    let link = self.link(&s.link_id)?;
                    if !link.is_up() {
                        return Err(InvalidSimulation::InvalidPacketSend {
                            node_id: s.node_id.clone(),
                            link_id: s.link_id.clone(),
                        });
                    }

                    self.in_flight_packets.insert(
                        s.packet_id,
                        InFlightPacket {
                            sent_at_relative: step.relative_time,
                            link_id: s.link_id.clone(),
                        },
                    );
                }

                SimulationStepKind::PacketCongestionEvent(s) => {
                    self.node(&s.node_id)?.packet_ecn(s);
                }

                SimulationStepKind::PacketDeliveredToApplication(s) => {
                    self.node(&s.node_id)?.packet_delivered(s.packet_id)?;
                }

                // TODO: do something with the step below, so we can check that each packet's delay
                // is respected (i.e. the time between PacketInTransit and PacketInNode matches the
                // link's delay + extra delay).
                SimulationStepKind::PacketExtraDelay(_) => {}
            }
        }

        let stats_by_node = self
            .nodes
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    NodeStats {
                        sent: v.sent_packets,
                        received: v.received_packets,
                        received_out_of_order: v.reordered_packets_received,
                        duplicates: v.duplicated_packets,
                        dropped_injected: v.dropped_packets_injected,
                        dropped_buffer_full: v.dropped_packets_buffer_full,
                        max_buffer_usage: v.max_buffer_usage,
                        congestion_experienced: v.ecn_packets,
                    },
                )
            })
            .collect();

        Ok(VerifiedSimulation { stats_by_node })
    }

    fn node(&mut self, node_id: &Arc<str>) -> Result<&mut ReplayedNode, InvalidSimulation> {
        if let Some(node) = self.nodes.get_mut(node_id) {
            Ok(node)
        } else {
            Err(InvalidSimulation::MissingNode {
                node_id: node_id.clone(),
            })
        }
    }

    fn link(&mut self, link_id: &Arc<str>) -> Result<&mut ReplayedLink, InvalidSimulation> {
        if let Some(link) = self.links.get_mut(link_id) {
            Ok(link)
        } else {
            Err(InvalidSimulation::MissingLink {
                link_id: link_id.clone(),
            })
        }
    }
}

#[derive(Default)]
struct ReplayedNode {
    packets: HashMap<Uuid, ReplayedPacket>,
    highest_received: u64,
    sent_packets: PacketStats,
    received_packets: PacketStats,
    reordered_packets_received: PacketStats,
    ecn_packets: PacketStats,
    duplicated_packets: PacketStats,
    dropped_packets_injected: PacketStats,
    dropped_packets_buffer_full: PacketStats,
    buffer_usage: usize,
    max_buffer_usage: usize,
}

impl ReplayedNode {
    fn packet_created(&mut self, s: &GenericPacketEvent) -> Result<(), InvalidSimulation> {
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes)
    }

    fn packet_received(&mut self, s: &GenericPacketEvent) -> Result<(), InvalidSimulation> {
        if self.highest_received > s.packet_number {
            self.reordered_packets_received
                .track_one(s.packet_size_bytes);
        }
        self.highest_received = self.highest_received.max(s.packet_number);

        self.received_packets.track_one(s.packet_size_bytes);
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes)
    }

    fn packet_duplicated(&mut self, s: &GenericPacketEvent) -> Result<(), InvalidSimulation> {
        self.duplicated_packets.track_one(s.packet_size_bytes);
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes)
    }

    fn packet_sent(&mut self, packet_id: Uuid) -> Result<(), InvalidSimulation> {
        let packet = self.remove_packet_from_buffer(packet_id)?;
        self.sent_packets.track_one(packet.size_bytes);
        Ok(())
    }

    fn packet_delivered(&mut self, packet_id: Uuid) -> Result<ReplayedPacket, InvalidSimulation> {
        self.remove_packet_from_buffer(packet_id)
    }

    fn packet_dropped(&mut self, s: &PacketDropped) -> Result<(), InvalidSimulation> {
        let packet = self.remove_packet_from_buffer(s.packet_id)?;
        if s.injected {
            self.dropped_packets_injected.track_one(packet.size_bytes);
        } else {
            self.dropped_packets_buffer_full
                .track_one(packet.size_bytes);
        }

        Ok(())
    }

    fn packet_ecn(&mut self, s: &GenericPacketEvent) {
        self.ecn_packets.track_one(s.packet_size_bytes);
    }

    fn add_packet_to_buffer(
        &mut self,
        packet_id: Uuid,
        size_bytes: usize,
    ) -> Result<(), InvalidSimulation> {
        let already_exists = self
            .packets
            .insert(packet_id, ReplayedPacket { size_bytes })
            .is_some();
        if already_exists {
            return Err(InvalidSimulation::PacketAlreadyReceived { packet_id });
        }

        self.buffer_usage += size_bytes;
        self.max_buffer_usage = cmp::max(self.max_buffer_usage, self.buffer_usage);

        Ok(())
    }

    fn remove_packet_from_buffer(
        &mut self,
        packet_id: Uuid,
    ) -> Result<ReplayedPacket, InvalidSimulation> {
        if let Some(packet) = self.packets.remove(&packet_id) {
            self.buffer_usage = self.buffer_usage.checked_sub(packet.size_bytes).unwrap();
            Ok(packet)
        } else {
            Err(InvalidSimulation::MissingPacket { packet_id })
        }
    }
}

mod replayed {
    use super::*;

    pub struct ReplayedLink {
        status: UpdateLinkStatus,
        last_down: Option<Duration>,
    }

    impl ReplayedLink {
        pub fn is_up(&self) -> bool {
            matches!(self.status, UpdateLinkStatus::Up)
        }

        pub fn last_down(&self) -> Option<Duration> {
            self.last_down
        }

        pub fn set_status(&mut self, status: UpdateLinkStatus, timestamp: Duration) {
            if let UpdateLinkStatus::Down = status {
                self.last_down = Some(timestamp);
            }

            self.status = status;
        }
    }

    impl Default for ReplayedLink {
        fn default() -> Self {
            Self {
                status: UpdateLinkStatus::Up,
                last_down: None,
            }
        }
    }
}

struct ReplayedPacket {
    size_bytes: usize,
}

struct InFlightPacket {
    sent_at_relative: Duration,
    link_id: Arc<str>,
}
