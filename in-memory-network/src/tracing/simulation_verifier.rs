use crate::network::event::UpdateLinkStatus;
use crate::network::spec::{NetworkSpec, NodeKind};
use crate::tracing::simulation_step::{
    GenericPacketEvent, PacketDropped, SimulationStep, SimulationStepKind,
};
use crate::tracing::simulation_verifier::replayed::ReplayedLink;
use crate::tracing::stats::{LinkStats, NodeStats, PacketStats};
use anyhow::{anyhow, bail};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, mem};
use thiserror::Error;
use uuid::Uuid;

pub struct VerifiedSimulation {
    pub stats: SimulationStats,
    pub non_fatal_errors: Vec<NonFatalError>,
}

pub struct SimulationStats {
    pub stats_by_node: HashMap<Arc<str>, NodeStats>,
    pub stats_by_link: HashMap<Arc<str>, LinkStats>,
}

#[derive(Debug)]
pub struct InvalidSimulation {
    fatal_error: Option<FatalError>,
    non_fatal_errors: Vec<NonFatalError>,
}

impl Display for InvalidSimulation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.fatal_error {
            f.write_str("Fatal error:\n")?;
            Display::fmt(e, f)?;
        }

        if !self.non_fatal_errors.is_empty() {
            f.write_str("\nOther errors:\n")?;
        }

        for e in &self.non_fatal_errors {
            f.write_str("* ")?;
            Display::fmt(e, f)?;
            f.write_str("\n")?;
        }

        Ok(())
    }
}

impl std::error::Error for InvalidSimulation {}

#[derive(Error, Debug)]
pub enum NonFatalError {
    #[error(
        "network node `{node_id}` is storing {max_buffer_usage} bytes, but its buffer is of {buffer_size_bytes} bytes"
    )]
    NodeExceedsBufferSize {
        node_id: Arc<str>,
        buffer_size_bytes: usize,
        max_buffer_usage: usize,
    },
    #[error("network node `{node_id}` created a packet out of thin air (packet `{packet_id}`)")]
    PacketCreatedByRouterNode { node_id: Arc<str>, packet_id: Uuid },
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
        "network node `{node_id}` received a packet through link `{link_id}`, but said link became unavailable while the packet was in flight (packet sent at {packet_sent_ns} ns, link was last down at {link_last_down_ns} ns)"
    )]
    OfflinePacketReceive {
        node_id: Arc<str>,
        link_id: Arc<str>,
        packet_sent_ns: u128,
        link_last_down_ns: u128,
    },
    #[error(
        "network node `{node_id}` sent packet `{packet_id}` through link `{link_id}`, but the link didn't have enough available bandwidth (link bandwidth is {max_bps} bps, but used bandwidth was {observed_bps} bps)"
    )]
    LinkBandwidthExceeded {
        node_id: Arc<str>,
        link_id: Arc<str>,
        packet_id: Uuid,
        max_bps: usize,
        observed_bps: usize,
    },
}

#[derive(Error, Debug)]
pub enum FatalError {
    #[error("network node `{node_id}` was referenced but does not exist")]
    MissingNode { node_id: Arc<str> },
    #[error("network link `{link_id}` was referenced but does not exist")]
    MissingLink { link_id: Arc<str> },
    #[error(
        "network node references packet `{packet_id}`, but according to the trace the packet is not present in the node at this moment"
    )]
    MissingPacket { packet_id: Uuid },
    #[error("network node received packet with id `{packet_id}` multiple times")]
    PacketAlreadyReceived { packet_id: Uuid },
}

macro_rules! try_fatal {
    ($expr:expr, $non_fatal_errors:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                return Err(InvalidSimulation {
                    fatal_error: Some(err),
                    non_fatal_errors: $non_fatal_errors,
                });
            }
        }
    };
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
    /// Map from nodes to metadata useful for verification
    node_metadata: HashMap<Arc<str>, NodeMetadata>,
    /// Map from links to metadata useful for verification
    link_metadata: HashMap<Arc<str>, LinkMetadata>,
    /// Errors which don't prevent the verifier from continuing
    non_fatal_errors: Vec<NonFatalError>,
}

impl SimulationVerifier {
    pub fn new(mut steps: Vec<SimulationStep>, network_spec: &NetworkSpec) -> anyhow::Result<Self> {
        if !steps.is_sorted_by_key(|s| s.relative_time) {
            steps.sort_by_key(|s| s.relative_time);
        }

        let network_spec = network_spec.clone();

        let mut node_metadata = HashMap::new();
        let mut replayed_nodes = HashMap::new();
        let mut host_nodes = HashSet::new();
        let mut ip_to_node = HashMap::new();
        for node in network_spec.nodes {
            let node_id: Arc<str> = node.id.clone().into();
            if let NodeKind::Host = node.kind {
                host_nodes.insert(node_id.clone());
            }

            node_metadata.insert(
                node_id.clone(),
                NodeMetadata {
                    buffer_size_bytes: node.buffer_size_bytes as usize,
                },
            );

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
            node_metadata,
            link_metadata,
            ..Default::default()
        })
    }

    pub fn verify(mut self) -> Result<VerifiedSimulation, InvalidSimulation> {
        let steps = mem::take(&mut self.steps);

        let mut last_step_time = Duration::from_secs(0);
        let mut last_buffer_usage_update = None;
        let mut stats_by_link: HashMap<_, LinkStats> = HashMap::new();
        for step in steps {
            if step.relative_time != last_step_time {
                if let Err(e) = self.update_max_buffer_usage() {
                    self.non_fatal_errors.push(e);
                }

                last_buffer_usage_update = Some(last_step_time);
                last_step_time = step.relative_time;
            }

            match &step.kind {
                SimulationStepKind::PacketInNode(s) => {
                    if let Some(in_flight) = self.in_flight_packets.remove(&s.packet_id) {
                        // Check that the link is actually connected to the target node
                        let link_metadata = self.link_metadata.get(&in_flight.link_id).unwrap();
                        if s.node_id != link_metadata.target_node_id {
                            self.non_fatal_errors
                                .push(NonFatalError::DisconnectedPacketReceive {
                                    node_id: s.node_id.clone(),
                                    link_id: in_flight.link_id.clone(),
                                });
                        }

                        // Check that transmission took enough time
                        let time_in_flight = step.relative_time - in_flight.sent_at_relative;
                        if time_in_flight < link_metadata.delay + in_flight.extra_delay {
                            self.non_fatal_errors
                                .push(NonFatalError::TooFastPacketReceive {
                                    node_id: s.node_id.clone(),
                                    link_id: in_flight.link_id.clone(),
                                });
                        }

                        // Check that the link didn't go down after sending (i.e. forbid up -> down -> up)
                        let link = try_fatal!(self.link(&in_flight.link_id), self.non_fatal_errors);
                        match link.last_down() {
                            Some(last_down_relative)
                                if last_down_relative >= in_flight.sent_at_relative =>
                            {
                                self.non_fatal_errors
                                    .push(NonFatalError::OfflinePacketReceive {
                                        node_id: s.node_id.clone(),
                                        link_id: in_flight.link_id.clone(),
                                        packet_sent_ns: in_flight.sent_at_relative.as_nanos(),
                                        link_last_down_ns: last_down_relative.as_nanos(),
                                    });
                            }
                            _ => {}
                        }

                        let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                        try_fatal!(node.packet_received(s), self.non_fatal_errors);
                    } else {
                        // The packet was not in flight, so it must have just been created at
                        // one of the hosts
                        if !self.host_nodes.contains(&s.node_id) {
                            self.non_fatal_errors
                                .push(NonFatalError::PacketCreatedByRouterNode {
                                    node_id: s.node_id.clone(),
                                    packet_id: s.packet_id,
                                });
                        }

                        let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                        try_fatal!(node.packet_created(s), self.non_fatal_errors);
                    }
                }
                SimulationStepKind::PacketDuplicated(s) => {
                    let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                    try_fatal!(node.packet_duplicated(s), self.non_fatal_errors);
                }
                SimulationStepKind::PacketDropped(s) => {
                    let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                    try_fatal!(node.packet_dropped(s), self.non_fatal_errors);
                }
                SimulationStepKind::PacketLostInTransit(s) => {
                    if let Some(packet) = self.in_flight_packets.remove(&s.packet_id) {
                        stats_by_link
                            .entry(s.link_id.clone())
                            .or_default()
                            .dropped_in_transit
                            .track_one(packet.size_bytes);
                    } else {
                        self.non_fatal_errors
                            .push(NonFatalError::MissingLostPacket {
                                packet_id: s.packet_id,
                            });
                    }
                }
                SimulationStepKind::PacketInTransit(s) => {
                    let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                    let packet = try_fatal!(node.packet_sent(s.packet_id), self.non_fatal_errors);

                    // Check that the link is actually connected to the source node
                    let link_metadata = try_fatal!(
                        self.link_metadata.get(&s.link_id).cloned().ok_or(
                            FatalError::MissingLink {
                                link_id: s.link_id.clone(),
                            }
                        ),
                        self.non_fatal_errors
                    );
                    if s.node_id != link_metadata.source_node_id {
                        self.non_fatal_errors
                            .push(NonFatalError::DisconnectedPacketSend {
                                node_id: s.node_id.clone(),
                                link_id: s.link_id.clone(),
                            });
                    }

                    // Check that the link is up
                    let link = try_fatal!(self.link(&s.link_id), self.non_fatal_errors);
                    if !link.is_up() {
                        self.non_fatal_errors
                            .push(NonFatalError::OfflinePacketSend {
                                node_id: s.node_id.clone(),
                                link_id: s.link_id.clone(),
                            });
                    }

                    // Track the packet send at the link level, to ensure we stay within the link's
                    // bandwidth
                    let link = try_fatal!(self.link(&s.link_id), self.non_fatal_errors);
                    let used_bandwidth_bps = link.packet_sent(
                        step.relative_time,
                        packet.size_bytes,
                        link_metadata.bandwidth_bps,
                    );
                    if link_metadata.bandwidth_bps < used_bandwidth_bps {
                        self.non_fatal_errors
                            .push(NonFatalError::LinkBandwidthExceeded {
                                node_id: s.node_id.clone(),
                                link_id: s.link_id.clone(),
                                packet_id: s.packet_id,
                                max_bps: link_metadata.bandwidth_bps,
                                observed_bps: used_bandwidth_bps,
                            });
                    }

                    self.in_flight_packets.insert(
                        s.packet_id,
                        InFlightPacket {
                            size_bytes: packet.size_bytes,
                            sent_at_relative: step.relative_time,
                            link_id: s.link_id.clone(),
                            extra_delay: packet.extra_delay,
                        },
                    );
                }

                SimulationStepKind::PacketCongestionEvent(s) => {
                    let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                    node.packet_ecn(s);
                }

                SimulationStepKind::PacketDeliveredToApplication(s) => {
                    let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                    try_fatal!(node.packet_delivered(s.packet_id), self.non_fatal_errors);
                }

                SimulationStepKind::PacketExtraDelay(s) => {
                    let node = try_fatal!(self.node(&s.node_id), self.non_fatal_errors);
                    try_fatal!(
                        node.packet_has_extra_delay(s.packet_id, s.extra_delay),
                        self.non_fatal_errors
                    );
                }

                SimulationStepKind::NetworkEvent(e) => {
                    if let Some(status) = e.status {
                        let link = self
                            .links
                            .get_mut(&e.link_id)
                            .ok_or(FatalError::MissingLink {
                                link_id: e.link_id.clone(),
                            });
                        try_fatal!(link, self.non_fatal_errors)
                            .set_status(status, step.relative_time);
                    }
                }
            }
        }

        if last_buffer_usage_update != Some(last_step_time) {
            if let Err(e) = self.update_max_buffer_usage() {
                self.non_fatal_errors.push(e);
            }
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

        for (link_id, link) in self.links {
            stats_by_link
                .entry(link_id)
                .or_default()
                .max_used_bandwidth_bps = link.max_bandwidth_usage_bps();
        }

        Ok(VerifiedSimulation {
            stats: SimulationStats {
                stats_by_node,
                stats_by_link,
            },
            non_fatal_errors: self.non_fatal_errors,
        })
    }

    fn update_max_buffer_usage(&mut self) -> Result<(), NonFatalError> {
        for (node_id, node) in &mut self.nodes {
            let max_buffer_usage = node.update_max_buffer_usage();
            let buffer_size = self.node_metadata[node_id].buffer_size_bytes;
            if buffer_size < max_buffer_usage {
                return Err(NonFatalError::NodeExceedsBufferSize {
                    node_id: node_id.clone(),
                    buffer_size_bytes: buffer_size,
                    max_buffer_usage,
                });
            }
        }

        Ok(())
    }

    fn node(&mut self, node_id: &Arc<str>) -> Result<&mut ReplayedNode, FatalError> {
        if let Some(node) = self.nodes.get_mut(node_id) {
            Ok(node)
        } else {
            Err(FatalError::MissingNode {
                node_id: node_id.clone(),
            })
        }
    }

    fn link(&mut self, link_id: &Arc<str>) -> Result<&mut ReplayedLink, FatalError> {
        if let Some(link) = self.links.get_mut(link_id) {
            Ok(link)
        } else {
            Err(FatalError::MissingLink {
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
    fn packet_created(&mut self, s: &GenericPacketEvent) -> Result<(), FatalError> {
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes)
    }

    fn packet_received(&mut self, s: &GenericPacketEvent) -> Result<(), FatalError> {
        if self.highest_received > s.packet_number {
            self.reordered_packets_received
                .track_one(s.packet_size_bytes);
        }
        self.highest_received = self.highest_received.max(s.packet_number);

        self.received_packets.track_one(s.packet_size_bytes);
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes)
    }

    fn packet_duplicated(&mut self, s: &GenericPacketEvent) -> Result<(), FatalError> {
        self.duplicated_packets.track_one(s.packet_size_bytes);
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes)
    }

    fn packet_sent(&mut self, packet_id: Uuid) -> Result<ReplayedPacket, FatalError> {
        let packet = self.remove_packet_from_buffer(packet_id)?;
        self.sent_packets.track_one(packet.size_bytes);
        Ok(packet)
    }

    fn packet_delivered(&mut self, packet_id: Uuid) -> Result<ReplayedPacket, FatalError> {
        self.remove_packet_from_buffer(packet_id)
    }

    fn packet_dropped(&mut self, s: &PacketDropped) -> Result<(), FatalError> {
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
    ) -> anyhow::Result<(), FatalError> {
        let packet = self
            .packets
            .get_mut(&packet_id)
            .ok_or(FatalError::MissingPacket { packet_id })?;
        packet.extra_delay = delay;
        Ok(())
    }

    fn update_max_buffer_usage(&mut self) -> usize {
        self.max_buffer_usage = cmp::max(self.buffer_usage, self.max_buffer_usage);
        self.max_buffer_usage
    }

    fn add_packet_to_buffer(
        &mut self,
        packet_id: Uuid,
        size_bytes: usize,
    ) -> Result<(), FatalError> {
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
            return Err(FatalError::PacketAlreadyReceived { packet_id });
        }

        self.buffer_usage += size_bytes;

        Ok(())
    }

    fn remove_packet_from_buffer(&mut self, packet_id: Uuid) -> Result<ReplayedPacket, FatalError> {
        if let Some(packet) = self.packets.remove(&packet_id) {
            self.buffer_usage = self.buffer_usage.checked_sub(packet.size_bytes).unwrap();
            Ok(packet)
        } else {
            Err(FatalError::MissingPacket { packet_id })
        }
    }
}

mod replayed {
    use super::*;
    use std::collections::VecDeque;

    pub struct ReplayedLink {
        status: UpdateLinkStatus,
        last_down_relative: Option<Duration>,
        bandwidth_usage_bps: usize,
        packets_in_bandwidth_window: VecDeque<(Duration, usize)>,
        max_bandwidth_usage_bps: usize,
    }

    impl ReplayedLink {
        pub fn max_bandwidth_usage_bps(&self) -> usize {
            self.max_bandwidth_usage_bps
        }

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
            packet_sent_time: Duration,
            packet_size_bytes: usize,
            link_bandwidth_bps: usize,
        ) -> usize {
            // 9984 is the MTU (if you consider IPv6 and UDP headers), so if a link can send less
            // than that per second, it will inevitably appear here as using more bps than
            // available. For that reason, we use a longer window in that case.
            let window_seconds = if link_bandwidth_bps < 9984 { 10 } else { 1 };

            // Remove any packets that have fallen out of the window
            while self
                .packets_in_bandwidth_window
                .front()
                .is_some_and(|first| {
                    first.0 + Duration::from_secs(window_seconds) < packet_sent_time
                })
            {
                let (_, bits) = self.packets_in_bandwidth_window.pop_front().unwrap();
                self.bandwidth_usage_bps -= bits;
            }

            // Add the new packet to the window
            let packet_size_bits = packet_size_bytes * 8;
            self.packets_in_bandwidth_window
                .push_back((packet_sent_time, packet_size_bits));
            self.bandwidth_usage_bps += packet_size_bits;

            // Smooth out the bps if necessary
            let bandwidth_usage = self.bandwidth_usage_bps / window_seconds as usize;
            self.max_bandwidth_usage_bps = cmp::max(self.max_bandwidth_usage_bps, bandwidth_usage);

            bandwidth_usage
        }
    }

    impl Default for ReplayedLink {
        fn default() -> Self {
            Self {
                status: UpdateLinkStatus::Up,
                last_down_relative: None,
                bandwidth_usage_bps: 0,
                packets_in_bandwidth_window: Default::default(),
                max_bandwidth_usage_bps: 0,
            }
        }
    }
}

struct ReplayedPacket {
    size_bytes: usize,
    extra_delay: Duration,
}

struct InFlightPacket {
    size_bytes: usize,
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

#[derive(Clone)]
struct NodeMetadata {
    buffer_size_bytes: usize,
}
