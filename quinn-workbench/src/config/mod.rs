use crate::config::network::{NetworkEventJson, NetworkSpecJson};
use crate::config::quinn::QuinnJsonConfig;

pub mod cli;
pub mod network;
pub mod quinn;

pub struct SimulationConfig {
    pub quinn: QuinnJsonConfig,
    pub network_graph: NetworkSpecJson,
    pub network_events: Vec<NetworkEventJson>,
}
