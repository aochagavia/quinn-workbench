use crate::network::inbound_queue::InboundQueue;
use crate::network::{InMemoryNetwork, Node, NodeName};
use crate::NetworkConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

pub struct RouterHandle {
    pub network: Arc<InMemoryNetwork>,
    pub(crate) router: Arc<Router>,
}

impl RouterHandle {
    pub fn process_inbound(&self, source_addr: SocketAddr) {
        let inbound = &self.router.inbound[&source_addr];
        if let Some(next_receive) = inbound.lock().unwrap().time_of_next_receive() {
            let router = self.router.clone();
            let network = self.network.clone();
            tokio::spawn(async move {
                // Take delays into account
                tokio::time::sleep_until(next_receive).await;

                // Now transfer inbound to outbound
                let mut inbound = router.inbound[&source_addr].lock().unwrap();
                let transmits = inbound.receive(usize::MAX);
                for mut transmit in transmits {
                    // Update the packet's path
                    transmit
                        .path
                        .push((Instant::now(), NodeName::Router(router.name.clone())));

                    network.send(Instant::now(), Node::Router(router.name.clone()), transmit);
                }
            });
        }
    }
}

pub struct Router {
    pub(crate) name: String,
    pub(crate) link_configs: HashMap<SocketAddr, Arc<NetworkConfig>>,
    pub(crate) inbound: HashMap<SocketAddr, Mutex<InboundQueue>>,
    pub(crate) outbound: HashMap<SocketAddr, Node>,
}

impl Router {
    pub fn link_config(&self, source_addr: SocketAddr) -> &NetworkConfig {
        &self.link_configs[&source_addr]
    }

    pub fn handle(self: &Arc<Self>, network: &Arc<InMemoryNetwork>) -> RouterHandle {
        RouterHandle {
            network: network.clone(),
            router: self.clone(),
        }
    }
}
