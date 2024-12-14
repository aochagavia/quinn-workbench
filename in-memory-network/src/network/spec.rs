use crate::network::route::Route;
use std::net::IpAddr;
use std::time::Duration;

pub struct NetworkSpec {
    pub nodes: Vec<NetworkNodeSpec>,
    pub links: Vec<NetworkLinkSpec>,
}

pub struct NetworkNodeSpec {
    pub id: String,
    pub kind: NodeKind,
    pub interfaces: Vec<NetworkInterface>,
    pub routes: Vec<Route>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Host,
    Router,
}

pub struct NetworkInterface {
    pub addresses: Vec<IpAddr>,
}

pub struct NetworkLinkSpec {
    pub id: String,
    pub source: IpAddr,
    pub target: IpAddr,
    pub delay: Duration,
    pub bandwidth_bps: u64,
    pub congestion_event_ratio: f64,
    pub packet_loss_ratio: f64,
    pub packet_duplication_ratio: f64,
    pub extra_delay: Duration,
    pub extra_delay_ratio: f64,
}
