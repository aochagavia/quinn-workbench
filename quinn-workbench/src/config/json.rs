use serde::Deserialize;

#[derive(Deserialize)]
pub struct JsonConfig {
    pub quinn: Option<QuinnJsonConfig>,
    pub network: NetworkJsonConfig,
}

#[derive(Deserialize)]
pub struct QuinnJsonConfig {
    pub initial_rtt_ms: u64,
    pub maximum_idle_timeout_ms: u64,
    pub packet_threshold: u32,
    pub mtu_discovery: bool,
    pub maximize_send_and_receive_windows: bool,
    pub ack_eliciting_threshold: u32,
    pub max_ack_delay_ms: u64,
    pub fixed_congestion_window: Option<u64>,
}

#[derive(Clone, Deserialize)]
pub struct NetworkJsonConfig {
    /// The one-way delay of the network, in milliseconds
    pub delay_ms: u64,
    /// The one-way extra delay of the network, which will be applied at random according to
    /// `extra_delay_ratio`
    pub extra_delay_ms: u64,
    /// The ratio of packets that will have an extra delay applied, to simulate packet reordering
    /// (the value must be between 0 and 1)
    pub extra_delay_ratio: f64,
    /// The ratio of packets that will be duplicated upon being sent (the value must be between 0
    /// and 1)
    pub packet_duplication_ratio: f64,
    /// The ratio of packets that will be lost (the value must be between 0 and 1)
    pub packet_loss_ratio: f64,
    /// The one-way bandwidth of the network, in bytes
    pub bandwidth: u64,
}
