use crate::network::event::UpdateLinkStatus;
use crate::network::spec::{NetworkSpec, NodeKind};
use crate::tracing::simulation_step::{
    GenericPacketEvent, PacketDropped, SimulationStep, SimulationStepKind,
};
use crate::tracing::simulation_verifier::InvalidSimulation::PacketCreatedByRouterNode;
use crate::tracing::simulation_verifier::replayed::ReplayedLink;
use crate::tracing::stats::{NodeStats, PacketStats};
use anyhow::{anyhow, bail};
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
        "network node references packet `{packet_id}`, but according to the trace the packet is not present in the node at this moment"
    )]
    MissingPacket { packet_id: Uuid },
    #[error(
        "packet `{packet_id}` was marked as lost in transit, but according to the trace the packet was not in transit at that moment"
    )]
    MissingLostPacket { packet_id: Uuid },
    #[error(
        "network node `{node_id}` sent a packet through link `{link_id}`, but said link was offline at this point in time"
    )]
    OfflinePacketSend {
        node_id: Arc<str>,
        link_id: Arc<str>,
    },
    #[error(
        "network node `{node_id}` sent a packet through link `{link_id}`, but according to the network graph the node is not connected to that link as a sender"
    )]
    DisconnectedPacketSend {
        node_id: Arc<str>,
        link_id: Arc<str>,
    },
    #[error(
        "network node `{node_id}` received a packet through link `{link_id}`, but said link became unavailable while the packet was in flight (packet sent at {packet_sent_ns} ns, link was last down at {link_last_down_ns} ns)"
    )]
    OfflinePacketReceive {
        node_id: Arc<str>,
        link_id: Arc<str>,
        packet_sent_ns: u128,
        link_last_down_ns: u128,
    },
    #[error(
        "network node `{node_id}` received a packet through link `{link_id}`, but according to the network graph the node is not connected to that link as a receiver"
    )]
    DisconnectedPacketReceive {
        node_id: Arc<str>,
        link_id: Arc<str>,
    },
    #[error(
        "network node `{node_id}` received a packet through link `{link_id}` faster than the link's delay allows"
    )]
    TooFastPacketReceive {
        node_id: Arc<str>,
        link_id: Arc<str>,
    },
    #[error(
        "network node `{node_id}` sent a packet through link `{link_id}`, but the link didn't have enough available bandwidth (link bandwidth is {max_bps} bps, but used bandwidth was {observed_bps} bps)"
    )]
    LinkBandwidthExceeded {
        node_id: Arc<str>,
        link_id: Arc<str>,
        max_bps: usize,
        observed_bps: usize,
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
    /// Map from links to metadata useful for verification
    link_metadata: HashMap<Arc<str>, LinkMetadata>,
}

impl SimulationVerifier {
    pub fn new(mut steps: Vec<SimulationStep>, network_spec: &NetworkSpec) -> anyhow::Result<Self> {
        if !steps.is_sorted_by_key(|s| s.relative_time) {
            steps.sort_by_key(|s| s.relative_time);
        }

        let network_spec = network_spec.clone();

        let mut replayed_nodes = HashMap::new();
        let mut host_nodes = HashSet::new();
        let mut ip_to_node = HashMap::new();
        for node in network_spec.nodes {
            let node_id: Arc<str> = node.id.clone().into();
            if let NodeKind::Host = node.kind {
                host_nodes.insert(node_id.clone());
            }

            for interface in &node.interfaces {
                for addr in &interface.addresses {
                    let existing = ip_to_node.insert(addr.as_ip_addr(), node_id.clone());
                    match existing {
                        Some(existing) if existing != node_id => {
                            bail!(
                                "address `{addr}` is mapped to at least two nodes: `{node_id}` and `{existing}`"
                            );
                        }
                        _ => {}
                    }
                }
            }

            replayed_nodes.insert(node_id, ReplayedNode::default());
        }

        let mut replayed_links = HashMap::new();
        let mut link_metadata = HashMap::new();
        for link in network_spec.links {
            let source_id = ip_to_node.get(&link.source).ok_or(anyhow!("no corresponding node found for link `{}` (source address `{}` is not used by any node)", link.id, link.source))?;
            let target_id = ip_to_node.get(&link.target).ok_or(anyhow!("no corresponding node found for link `{}` (target address `{}` is not used by any node)", link.id, link.target))?;
            link_metadata.insert(
                link.id.clone(),
                LinkMetadata {
                    source_node_id: source_id.clone(),
                    target_node_id: target_id.clone(),
                    delay: link.delay,
                    bandwidth_bps: link.bandwidth_bps as usize,
                },
            );

            replayed_links.insert(link.id, ReplayedLink::default());
        }

        Ok(Self {
            steps,
            nodes: replayed_nodes,
            links: replayed_links,
            host_nodes,
            link_metadata,
            ..Default::default()
        })
    }

    pub fn verify(mut self) -> Result<VerifiedSimulation, InvalidSimulation> {
        let steps = mem::take(&mut self.steps);

        let mut last_step_time = Duration::from_secs(0);
        let mut last_buffer_usage_update = None;
        for step in steps {
            if step.relative_time != last_step_time {
                self.update_max_buffer_usage();
                last_buffer_usage_update = Some(last_step_time);
                last_step_time = step.relative_time;
            }

            match &step.kind {
                SimulationStepKind::PacketInNode(s) => {
                    if let Some(in_flight) = self.in_flight_packets.remove(&s.packet_id) {
                        // Check that the link is actually connected to the target node
                        let link_metadata = self.link_metadata.get(&in_flight.link_id).unwrap();
                        if s.node_id != link_metadata.target_node_id {
                            return Err(InvalidSimulation::DisconnectedPacketReceive {
                                node_id: s.node_id.clone(),
                                link_id: in_flight.link_id.clone(),
                            });
                        }

                        // Check that transmission took enough time
                        let time_in_flight = step.relative_time - in_flight.sent_at_relative;
                        if time_in_flight < link_metadata.delay + in_flight.extra_delay {
                            return Err(InvalidSimulation::TooFastPacketReceive {
                                node_id: s.node_id.clone(),
                                link_id: in_flight.link_id,
                            });
                        }

                        // Check that the link didn't go down after sending (i.e. forbid up -> down -> up)
                        let link = self.link(&in_flight.link_id)?;
                        match link.last_down() {
                            Some(last_down_relative)
                                if last_down_relative >= in_flight.sent_at_relative =>
                            {
                                return Err(InvalidSimulation::OfflinePacketReceive {
                                    node_id: s.node_id.clone(),
                                    link_id: in_flight.link_id.clone(),
                                    packet_sent_ns: in_flight.sent_at_relative.as_nanos(),
                                    link_last_down_ns: last_down_relative.as_nanos(),
                                });
                            }
                            _ => {}
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
                    let packet = self.node(&s.node_id)?.packet_sent(s.packet_id)?;

                    // Check that the link is actually connected to the source node
                    let link_metadata = self.link_metadata.get(&s.link_id).cloned().ok_or(
                        InvalidSimulation::MissingLink {
                            link_id: s.link_id.clone(),
                        },
                    )?;
                    if s.node_id != link_metadata.source_node_id {
                        return Err(InvalidSimulation::DisconnectedPacketSend {
                            node_id: s.node_id.clone(),
                            link_id: s.link_id.clone(),
                        });
                    }

                    // Check that the link is up
                    let link = self.link(&s.link_id)?;
                    if !link.is_up() {
                        return Err(InvalidSimulation::OfflinePacketSend {
                            node_id: s.node_id.clone(),
                            link_id: s.link_id.clone(),
                        });
                    }

                    // Track the packet send at the link level, to ensure we stay within the link's
                    // bandwidth
                    let used_bandwidth_bps = link.packet_sent(
                        step.relative_time,
                        packet.size_bytes,
                        link_metadata.bandwidth_bps,
                    );
                    if link_metadata.bandwidth_bps < used_bandwidth_bps {
                        return Err(InvalidSimulation::LinkBandwidthExceeded {
                            node_id: s.node_id.clone(),
                            link_id: s.link_id.clone(),
                            max_bps: link_metadata.bandwidth_bps,
                            observed_bps: used_bandwidth_bps,
                        });
                    }

                    self.in_flight_packets.insert(
                        s.packet_id,
                        InFlightPacket {
                            sent_at_relative: step.relative_time,
                            link_id: s.link_id.clone(),
                            extra_delay: packet.extra_delay,
                        },
                    );
                }

                SimulationStepKind::PacketCongestionEvent(s) => {
                    self.node(&s.node_id)?.packet_ecn(s);
                }

                SimulationStepKind::PacketDeliveredToApplication(s) => {
                    self.node(&s.node_id)?.packet_delivered(s.packet_id)?;
                }

                SimulationStepKind::PacketExtraDelay(s) => {
                    self.node(&s.node_id)?
                        .packet_has_extra_delay(s.packet_id, s.extra_delay)?;
                }

                SimulationStepKind::NetworkEvent(e) => {
                    if let Some(status) = e.status {
                        let link = self.links.get_mut(&e.link_id).ok_or(
                            InvalidSimulation::MissingLink {
                                link_id: e.link_id.clone(),
                            },
                        )?;
                        link.set_status(status, step.relative_time);
                    }
                }
            }
        }

        if last_buffer_usage_update != Some(last_step_time) {
            self.update_max_buffer_usage();
        }

        let stats_by_node = self
            .nodes
            .into_iter()
            .map(|(node_id, v)| {
                (
                    node_id,
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

    fn update_max_buffer_usage(&mut self) {
        for node in self.nodes.values_mut() {
            node.update_max_buffer_usage();
        }
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

    fn packet_sent(&mut self, packet_id: Uuid) -> Result<ReplayedPacket, InvalidSimulation> {
        let packet = self.remove_packet_from_buffer(packet_id)?;
        self.sent_packets.track_one(packet.size_bytes);
        Ok(packet)
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

    fn packet_has_extra_delay(
        &mut self,
        packet_id: Uuid,
        delay: Duration,
    ) -> anyhow::Result<(), InvalidSimulation> {
        let packet = self
            .packets
            .get_mut(&packet_id)
            .ok_or(InvalidSimulation::MissingPacket { packet_id })?;
        packet.extra_delay = delay;
        Ok(())
    }

    fn update_max_buffer_usage(&mut self) {
        self.max_buffer_usage = cmp::max(self.buffer_usage, self.max_buffer_usage);
    }

    fn add_packet_to_buffer(
        &mut self,
        packet_id: Uuid,
        size_bytes: usize,
    ) -> Result<(), InvalidSimulation> {
        let already_exists = self
            .packets
            .insert(
                packet_id,
                ReplayedPacket {
                    size_bytes,
                    extra_delay: Duration::default(),
                },
            )
            .is_some();
        if already_exists {
            return Err(InvalidSimulation::PacketAlreadyReceived { packet_id });
        }

        self.buffer_usage += size_bytes;

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
    use std::collections::VecDeque;

    pub struct ReplayedLink {
        status: UpdateLinkStatus,
        last_down_relative: Option<Duration>,
        used_bandwidth_bps_in_current_window: usize,
        packets_using_bandwidth: VecDeque<(Duration, usize)>,
    }

    impl ReplayedLink {
        pub fn is_up(&self) -> bool {
            matches!(self.status, UpdateLinkStatus::Up)
        }

        pub fn last_down(&self) -> Option<Duration> {
            self.last_down_relative
        }

        pub fn set_status(&mut self, status: UpdateLinkStatus, timestamp_relative: Duration) {
            if let UpdateLinkStatus::Down = status {
                self.last_down_relative = Some(timestamp_relative);
            }

            self.status = status;
        }

        pub fn packet_sent(
            &mut self,
            timestamp: Duration,
            size_bytes: usize,
            link_bandwidth_bps: usize,
        ) -> usize {
            let size_bits = size_bytes * 8;
            self.packets_using_bandwidth
                .push_back((timestamp, size_bits));
            self.used_bandwidth_bps_in_current_window += size_bits;

            // 9600 is the minimum packet size, so if a link can send less than that per second, it
            // will inevitably appear here as using more bps than available. For that reason, we use
            // a longer window in that case.
            let window_seconds = if link_bandwidth_bps < 9600 { 5 } else { 1 };

            loop {
                let Some((first_timestamp, first_size_bits)) =
                    self.packets_using_bandwidth.front().copied()
                else {
                    break;
                };

                let first_is_stale =
                    timestamp - first_timestamp > Duration::from_secs(window_seconds);
                if first_is_stale {
                    self.packets_using_bandwidth.pop_front();
                    self.used_bandwidth_bps_in_current_window -= first_size_bits;
                } else {
                    break;
                }
            }

            self.used_bandwidth_bps_in_current_window / window_seconds as usize
        }
    }

    impl Default for ReplayedLink {
        fn default() -> Self {
            Self {
                status: UpdateLinkStatus::Up,
                last_down_relative: None,
                used_bandwidth_bps_in_current_window: 0,
                packets_using_bandwidth: Default::default(),
            }
        }
    }
}

struct ReplayedPacket {
    size_bytes: usize,
    extra_delay: Duration,
}

struct InFlightPacket {
    sent_at_relative: Duration,
    extra_delay: Duration,
    link_id: Arc<str>,
}

#[derive(Clone)]
struct LinkMetadata {
    source_node_id: Arc<str>,
    target_node_id: Arc<str>,
    delay: Duration,
    bandwidth_bps: usize,
}
