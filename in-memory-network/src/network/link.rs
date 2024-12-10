use crate::network::inbound_queue::InboundQueue;
use std::net::IpAddr;
use std::time::Duration;

pub struct NetworkLink {
    pub id: String,
    pub target: IpAddr,
    pub queue: InboundQueue,
    pub status: LinkStatus,
    pub congestion_event_ratio: f64,
    pub packet_loss_ratio: f64,
    pub packet_duplication_ratio: f64,
    pub extra_delay: Duration,
    pub extra_delay_ratio: f64,
}

pub enum LinkStatus {
    Up,
    Down,
}
