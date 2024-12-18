use std::collections::HashMap;
use std::sync::Arc;

pub struct NetworkStats {
    pub by_node: HashMap<Arc<str>, NodeStats>,
}

#[derive(Default)]
pub struct NodeStats {
    pub sent: PacketStats,
    pub received: PacketStats,
    pub dropped: PacketStats,
    pub duplicates: PacketStats,
    pub received_out_of_order: PacketStats,
    pub congestion_experienced: PacketStats,
    pub max_buffer_usage: usize,
}

#[derive(Default)]
pub struct PacketStats {
    pub packets: u64,
    pub bytes: usize,
}

impl PacketStats {
    pub fn track_one(&mut self, size_bytes: usize) {
        self.packets += 1;
        self.bytes += size_bytes;
    }
}
