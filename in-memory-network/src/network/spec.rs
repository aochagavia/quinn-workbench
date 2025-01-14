use crate::network::ip::Ipv4Cidr;
use crate::network::route::Route;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct NetworkSpec {
    pub nodes: Vec<NetworkNodeSpec>,
    pub links: Vec<NetworkLinkSpec>,
}

#[derive(Clone)]
pub struct NetworkNodeSpec {
    pub id: String,
    pub buffer_size_bytes: u64,
    pub kind: NodeKind,
    pub interfaces: Vec<NetworkInterface>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Host,
    Router,
}

#[derive(Clone)]
pub struct NetworkInterface {
    pub addresses: Vec<Ipv4Cidr>,
    pub routes: Vec<Route>,
}

#[derive(Clone)]
pub struct NetworkLinkSpec {
    pub id: Arc<str>,
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
