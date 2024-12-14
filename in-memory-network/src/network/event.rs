use crate::network::link::LinkStatus;
use std::time::Duration;

pub struct NetworkEvent {
    pub relative_time: Duration,
    pub payload: NetworkEventPayload,
}

pub struct NetworkEventPayload {
    pub id: String,
    pub status: Option<LinkStatus>,
    pub bandwidth_bps: Option<u64>,
    pub delay: Option<Duration>,
    pub extra_delay: Option<Duration>,
    pub extra_delay_ratio: Option<f64>,
    pub packet_duplication_ratio: Option<f64>,
    pub packet_loss_ratio: Option<f64>,
    pub congestion_event_ratio: Option<f64>,
}
