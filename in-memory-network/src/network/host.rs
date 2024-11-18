use crate::network::inbound_queue::InboundQueue;
use crate::network::InMemoryNetwork;
use crate::stats_tracker::NetworkStatsTracker;
use crate::{InTransitData, NetworkConfig};
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

pub struct HostHandle {
    pub network: Arc<InMemoryNetwork>,
    pub addr: SocketAddr,
}

impl Debug for HostHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "host ({})", self.addr)
    }
}

#[derive(Clone)]
pub struct Host {
    pub(in crate::network) addr: SocketAddr,
    pub(in crate::network) name: Arc<str>,
    pub(in crate::network) inbound: Arc<Mutex<InboundQueue>>,
}

impl Host {
    pub(crate) fn new(
        addr: SocketAddr,
        name: Arc<str>,
        config: &NetworkConfig,
        stats_tracker: NetworkStatsTracker,
        start: Instant,
    ) -> Host {
        Host {
            addr,
            name,
            inbound: Arc::new(Mutex::new(InboundQueue::new(
                config.link_delay,
                config.link_capacity,
                stats_tracker,
                start,
            ))),
        }
    }

    pub fn has_enough_capacity(&self, data: &InTransitData, duplicate: bool) -> bool {
        self.inbound
            .lock()
            .unwrap()
            .has_enough_capacity(data, duplicate)
    }

    pub fn enqueue_send(&self, data: InTransitData, metadata_index: usize, extra_delay: Duration) {
        self.inbound
            .lock()
            .unwrap()
            .send(data, metadata_index, extra_delay);
    }
}
