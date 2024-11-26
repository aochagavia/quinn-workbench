use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct NetworkStatsTracker {
    pub(crate) inner: Arc<Mutex<NetworkStatsInner>>,
}

#[derive(Debug, Default)]
pub(crate) struct NetworkStatsInner {
    pub(crate) transmits_metadata: Vec<TransmitMetadata>,
}

#[derive(Debug)]
pub(crate) struct TransmitMetadata {
    pub(crate) source: SocketAddr,
    pub(crate) byte_size: usize,
    pub(crate) dropped: bool,
    pub(crate) out_of_order: bool,
    pub(crate) duplicate: bool,
    pub(crate) pcap_number: u64,
    pub(crate) congestion_experienced: bool,
}

impl NetworkStatsTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NetworkStatsInner::default())),
        }
    }

    pub fn track_out_of_order(&self, metadata_index: usize) -> u64 {
        let mut inner = self.inner.lock();
        inner.transmits_metadata[metadata_index].out_of_order = true;
        inner.transmits_metadata[metadata_index].pcap_number
    }

    pub fn track_sent(
        &self,
        source: SocketAddr,
        size: usize,
        duplicate: bool,
        pcap_number: u64,
        congestion_experienced: bool,
    ) -> usize {
        let mut inner = self.inner.lock();
        let metadata_index = inner.transmits_metadata.len();
        inner.transmits_metadata.push(TransmitMetadata {
            source,
            byte_size: size,
            dropped: false,
            out_of_order: false,
            duplicate,
            pcap_number,
            congestion_experienced,
        });

        metadata_index
    }

    pub fn track_dropped(&self, source: SocketAddr, size: usize, pcap_number: u64) {
        let mut inner = self.inner.lock();
        inner.transmits_metadata.push(TransmitMetadata {
            source,
            byte_size: size,
            dropped: true,
            out_of_order: false,
            duplicate: false,
            pcap_number,
            congestion_experienced: false,
        });
    }
}

pub struct NetworkStats {
    pub peer_a: EndpointStats,
    pub peer_b: EndpointStats,
}

#[derive(Default)]
pub struct EndpointStats {
    pub sent: PacketStats,
    pub dropped: PacketStats,
    pub duplicates: PacketStats,
    pub out_of_order: PacketStats,
    pub congestion_experienced: u64,
}

#[derive(Default)]
pub struct PacketStats {
    pub packets: usize,
    pub bytes: usize,
}
