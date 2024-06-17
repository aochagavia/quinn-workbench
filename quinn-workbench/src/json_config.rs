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
    pub delay_ms: u64,
    pub extra_delay_ms: u64,
    pub extra_delay_ratio: f64,
    pub packet_duplication_ratio: f64,
    pub packet_loss_ratio: f64,
    pub bandwidth: u64,
}
