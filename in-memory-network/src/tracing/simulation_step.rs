use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct SimulationStep {
    pub relative_time: Duration,
    pub kind: SimulationStepKind,
}

#[derive(Clone)]
pub enum SimulationStepKind {
    /// The packet is in one of the network nodes
    PacketInNode(PacketInNode),
    /// The packet was dropped by one of the network nodes
    PacketDropped(PacketDropped),
    /// The packet was duplicated as a consequence of an injected failure
    PacketDuplicated(PacketInNode),
    /// The packet has an extra delay as a consequence of an injected failure
    PacketExtraDelay(PacketAffectedByRandomEvent<Duration>),
    /// The packet is marked with an ECN codepoint as a consequence of an injected failure
    PacketCongestionEvent(PacketInNode),
    /// The packet is being transferred over a link
    PacketInTransit(PacketInTransit),
}

#[derive(Clone)]
pub struct PacketInNode {
    pub packet_id: Uuid,
    pub packet_number: u64,
    pub packet_size_bytes: usize,
    pub node_id: Arc<str>,
}

#[derive(Clone)]
pub struct PacketDropped {
    pub packet_id: Uuid,
    pub node_id: Arc<str>,
    pub random: bool,
}

#[derive(Clone)]
pub struct PacketAffectedByRandomEvent<T: Clone> {
    pub packet_id: Uuid,
    pub node_id: Arc<str>,
    pub payload: T,
}

#[derive(Clone)]
pub struct PacketInTransit {
    pub packet_id: Uuid,
    pub node_id: Arc<str>,
    pub link_id: Arc<str>,
}
