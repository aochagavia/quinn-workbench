use crate::network::spec::NetworkNodeSpec;
use crate::tracing::simulation_step::{
    PacketDropped, PacketInNode, SimulationStep, SimulationStepKind,
};
use crate::tracing::stats::{NodeStats, PacketStats};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, mem};
use uuid::Uuid;

#[derive(Default)]
pub struct SimulationStepper {
    steps: Vec<SimulationStep>,
    /// Map from node ids to their associated state
    nodes: HashMap<Arc<str>, ReplayedNode>,
    /// Map from packet ids to the links where they can be found
    in_flight_packets: HashMap<Uuid, Arc<str>>,
}

impl SimulationStepper {
    pub fn new(mut steps: Vec<SimulationStep>, nodes: &[NetworkNodeSpec]) -> Self {
        if !steps.is_sorted_by_key(|s| s.relative_time) {
            steps.sort_unstable_by_key(|s| s.relative_time);
        }

        let nodes = nodes
            .iter()
            .map(|n| {
                (
                    n.id.clone().into_boxed_str().into(),
                    ReplayedNode::default(),
                )
            })
            .collect();

        Self {
            steps,
            nodes,
            ..Default::default()
        }
    }

    pub fn simulate(mut self) -> HashMap<Arc<str>, NodeStats> {
        let steps = mem::take(&mut self.steps);
        for step in steps {
            match &step.kind {
                SimulationStepKind::PacketInNode(s) => {
                    if let Some(_link) = self.in_flight_packets.remove(&s.packet_id) {
                        // TODO: check that the link is actually connected to the target node
                        self.node(&s.node_id).packet_received(s);
                    } else {
                        // TODO: the packet was not in flight, so it must have just been created at
                        // one of the hosts. Check that this node has "permission" to create packets.
                        self.node(&s.node_id).packet_created(s);
                    }
                }
                SimulationStepKind::PacketDuplicated(s) => {
                    self.node(&s.node_id).packet_duplicated(s);
                }
                SimulationStepKind::PacketDropped(s) => {
                    self.node(&s.node_id).packet_dropped(s);
                }
                SimulationStepKind::PacketInTransit(s) => {
                    self.node(&s.node_id).packet_sent(s.packet_id);

                    // TODO: check that the link is actually connected to the source node, up and not saturated

                    self.in_flight_packets
                        .insert(s.packet_id, s.link_id.clone());
                }

                SimulationStepKind::PacketCongestionEvent(s) => {
                    self.node(&s.node_id).packet_ecn(s);
                }

                // TODO: do something with the steps below, so we can check that each packet's delay
                // is respected (i.e. the time between PacketInTransit and PacketInNode matches the
                // link's delay + extra delay).
                SimulationStepKind::PacketExtraDelay(_) => {}
            }
        }

        self.nodes
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    NodeStats {
                        sent: v.sent_packets,
                        received: v.received_packets,
                        received_out_of_order: v.reordered_packets_received,
                        duplicates: v.duplicated_packets,
                        dropped: v.dropped_packets,
                        max_buffer_usage: v.max_buffer_usage,
                        congestion_experienced: v.ecn_packets,
                    },
                )
            })
            .collect()
    }

    fn node(&mut self, node_id: &Arc<str>) -> &mut ReplayedNode {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node
        } else {
            panic!("node not found: {node_id}")
        }
    }

    pub fn get_packet_hops(&self, id: Uuid) -> Vec<(Duration, Arc<str>)> {
        let mut hops = Vec::new();
        for step in &self.steps {
            match &step.kind {
                SimulationStepKind::PacketInNode(s) if s.packet_id == id => {
                    hops.push((step.relative_time, s.node_id.clone()));
                }
                _ => {}
            }
        }

        hops
    }

    pub fn get_packet_path(&self, id: Uuid) -> Vec<Arc<str>> {
        let mut path = Vec::new();
        for step in &self.steps {
            match &step.kind {
                SimulationStepKind::PacketInNode(s) if s.packet_id == id => {
                    path.push(s.node_id.clone());
                }
                _ => {}
            }
        }

        path
    }

    pub fn get_packet_arrived_at(&self, packet_id: Uuid, node_id: &str) -> Option<Duration> {
        self.steps
            .iter()
            .filter_map(|s| match &s.kind {
                SimulationStepKind::PacketInNode(kind)
                    if kind.packet_id == packet_id && kind.node_id.as_ref() == node_id =>
                {
                    Some(s.relative_time)
                }
                _ => None,
            })
            .next()
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
    dropped_packets: PacketStats,
    buffer_usage: usize,
    max_buffer_usage: usize,
}

impl ReplayedNode {
    fn packet_created(&mut self, s: &PacketInNode) {
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes);
    }

    fn packet_received(&mut self, s: &PacketInNode) {
        if self.highest_received > s.packet_number {
            self.reordered_packets_received
                .track_one(s.packet_size_bytes);
        }
        self.highest_received = self.highest_received.max(s.packet_number);

        self.received_packets.track_one(s.packet_size_bytes);
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes);
    }

    fn packet_duplicated(&mut self, s: &PacketInNode) {
        self.duplicated_packets.track_one(s.packet_size_bytes);
        self.add_packet_to_buffer(s.packet_id, s.packet_size_bytes);
    }

    fn packet_sent(&mut self, packet_id: Uuid) {
        let packet = self.remove_packet_from_buffer(packet_id);
        self.sent_packets.track_one(packet.size_bytes);
    }

    fn packet_dropped(&mut self, s: &PacketDropped) {
        let packet = self.remove_packet_from_buffer(s.packet_id);
        self.dropped_packets.track_one(packet.size_bytes);
    }

    fn packet_ecn(&mut self, s: &PacketInNode) {
        self.ecn_packets.track_one(s.packet_size_bytes);
    }

    fn add_packet_to_buffer(&mut self, packet_id: Uuid, size_bytes: usize) {
        let already_exists = self
            .packets
            .insert(packet_id, ReplayedPacket { size_bytes })
            .is_some();
        if already_exists {
            panic!("packet has already been received by node");
        }

        self.buffer_usage += size_bytes;
        self.max_buffer_usage = cmp::max(self.max_buffer_usage, self.buffer_usage);
    }

    fn remove_packet_from_buffer(&mut self, packet_id: Uuid) -> ReplayedPacket {
        if let Some(packet) = self.packets.remove(&packet_id) {
            self.buffer_usage = self.buffer_usage.checked_sub(packet.size_bytes).unwrap();
            packet
        } else {
            panic!("attempted to remove packet from buffer which was not present in the node");
        }
    }
}

struct ReplayedPacket {
    size_bytes: usize,
}
