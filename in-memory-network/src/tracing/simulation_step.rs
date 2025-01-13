use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr, DurationNanoSeconds};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct SimulationStep {
    #[serde_as(as = "DurationNanoSeconds")]
    #[serde(rename = "relative_time_ns")]
    pub relative_time: Duration,
    #[serde(flatten)]
    pub kind: SimulationStepKind,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "data")]
pub enum SimulationStepKind {
    /// The packet is in one of the network nodes
    PacketInNode(GenericPacketEvent),
    /// The packet was dropped by one of the network nodes
    PacketDropped(PacketDropped),
    /// The packet was duplicated as a consequence of an injected failure
    PacketDuplicated(GenericPacketEvent),
    /// The packet has an extra delay as a consequence of an injected failure
    PacketExtraDelay(PacketHasExtraDelay),
    /// The packet is marked with an ECN codepoint as a consequence of an injected failure
    PacketCongestionEvent(GenericPacketEvent),
    /// The packet is being transferred over a link
    PacketInTransit(PacketInTransit),
    /// The packet has been delivered to an application
    PacketDeliveredToApplication(GenericPacketEvent),
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct GenericPacketEvent {
    #[serde_as(as = "DisplayFromStr")]
    pub packet_id: Uuid,
    pub packet_number: u64,
    pub packet_size_bytes: usize,
    #[serde(with = "crate::util::serde_arc_str")]
    pub node_id: Arc<str>,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct PacketDropped {
    #[serde_as(as = "DisplayFromStr")]
    pub packet_id: Uuid,
    #[serde(with = "crate::util::serde_arc_str")]
    pub node_id: Arc<str>,
    pub injected: bool,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct PacketHasExtraDelay {
    #[serde_as(as = "DisplayFromStr")]
    pub packet_id: Uuid,
    #[serde(with = "crate::util::serde_arc_str")]
    pub node_id: Arc<str>,
    #[serde_as(as = "DurationNanoSeconds")]
    #[serde(rename = "extra_delay_ns")]
    pub extra_delay: Duration,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct PacketInTransit {
    #[serde_as(as = "DisplayFromStr")]
    pub packet_id: Uuid,
    #[serde(with = "crate::util::serde_arc_str")]
    pub node_id: Arc<str>,
    #[serde(with = "crate::util::serde_arc_str")]
    pub link_id: Arc<str>,
}
