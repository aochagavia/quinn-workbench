use crate::config::network::{NetworkEventJson, NetworkSpecJson};

pub mod cli;
pub mod network;
pub mod quinn;

pub struct NetworkConfig {
    pub network_graph: NetworkSpecJson,
    pub network_events: Vec<NetworkEventJson>,
}
