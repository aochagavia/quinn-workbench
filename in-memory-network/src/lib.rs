//! In-memory network implementation
//!
//! Provides an in-memory network with two peers and an arbitrary number of routers in between

pub mod network;
pub mod pcap_exporter;
mod stats_tracker;

use quinn::udp::EcnCodepoint;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::Instant;

const PEER_A_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(88, 88, 88, 88)), 8080);
const PEER_B_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8080);

pub struct NetworkConfig {
    pub congestion_event_ratio: f64,
    pub packet_loss_ratio: f64,
    pub packet_duplication_ratio: f64,
    pub link_capacity: u64,
    pub link_delay: Duration,
    pub link_extra_delay: Duration,
    pub link_extra_delay_ratio: f64,
}

#[derive(Clone, Debug)]
struct OwnedTransmit {
    /// The socket this datagram should be sent to
    pub destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: Vec<u8>,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
}

#[derive(Clone)]
pub struct InTransitData {
    source_addr: SocketAddr,
    transmit: OwnedTransmit,
    sent: Instant,
    number: u64,
}

// In transit data, sorted by arrival time
struct PrioritizedInTransitData {
    data: InTransitData,
    metadata_index: usize,
    delay: Duration,
}

impl PrioritizedInTransitData {
    fn arrival_time(&self) -> Instant {
        self.data.sent + self.delay
    }
}

impl Eq for PrioritizedInTransitData {}

impl PartialEq<Self> for PrioritizedInTransitData {
    fn eq(&self, other: &Self) -> bool {
        self.arrival_time() == other.arrival_time() && self.data.number == other.data.number
    }
}

impl PartialOrd<Self> for PrioritizedInTransitData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedInTransitData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Note: the order is reversed, so the "max" in transit data will be the next one to be sent
        other
            .arrival_time()
            .cmp(&self.arrival_time())
            .then(other.data.number.cmp(&self.data.number))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::network::InMemoryNetwork;
    use crate::pcap_exporter::PcapExporter;
    use fastrand::Rng;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use quinn::rustls::RootCertStore;
    use quinn::{rustls, ClientConfig, Endpoint, EndpointConfig, ServerConfig};
    use std::sync::Arc;

    fn default_network() -> Arc<InMemoryNetwork> {
        Arc::new(InMemoryNetwork::initialize(
            NetworkConfig {
                congestion_event_ratio: 0.0,
                packet_loss_ratio: 0.0,
                packet_duplication_ratio: 0.0,
                link_capacity: 1024 * 1024 * 10,
                link_delay: Duration::from_millis(10),
                link_extra_delay: Default::default(),
                link_extra_delay_ratio: 0.0,
            },
            Arc::new(PcapExporter::new()),
            Rng::with_seed(42),
            Instant::now(),
        ))
    }

    fn default_server_config() -> (&'static str, CertificateDer<'static>, ServerConfig) {
        let server_name = "server-name";
        let cert = rcgen::generate_simple_self_signed(vec![server_name.into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server_cert = CertificateDer::from(cert.cert);
        let server_config =
            ServerConfig::with_single_cert(vec![server_cert.clone()], key.into()).unwrap();
        (server_name, server_cert, server_config)
    }

    fn default_client_config(server_cert: CertificateDer) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(server_cert).unwrap();

        let default_provider = rustls::crypto::ring::default_provider();
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
            ..default_provider
        };

        let crypto = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()))
    }

    #[tokio::test]
    async fn quic_handshake_and_bidi_stream_works() {
        let rt = quinn::default_runtime().unwrap();

        // Network
        let network = default_network();
        let server_socket = Arc::new(network.peer_a_socket());
        let client_socket = Arc::new(network.peer_b_socket());
        let server_addr = server_socket.addr;

        // QUIC config
        let (server_name, server_cert, server_config) = default_server_config();
        let client_config = default_client_config(server_cert);

        // QUIC endpoints
        let server_endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            server_socket,
            rt.clone(),
        )
        .unwrap();
        let mut client_endpoint =
            Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, client_socket, rt)
                .unwrap();
        client_endpoint.set_default_client_config(client_config);

        // Run server in the background
        let server_handle = tokio::spawn(async move {
            let conn = server_endpoint.accept().await.unwrap().await.unwrap();
            let (mut bi_tx, mut bi_rx) = conn.accept_bi().await.unwrap();

            let msg = bi_rx.read_to_end(usize::MAX).await.unwrap();
            assert_eq!(msg.as_slice(), b"hello");

            bi_tx.write_all(b"world").await.unwrap();
            bi_tx.finish().unwrap();
            bi_tx.stopped().await.unwrap();
        });

        // Make a request from the client
        let client_conn = client_endpoint
            .connect(server_addr, server_name)
            .unwrap()
            .await
            .unwrap();
        let (mut client_bi_tx, mut client_bi_rx) = client_conn.open_bi().await.unwrap();
        client_bi_tx.write_all(b"hello").await.unwrap();
        client_bi_tx.finish().unwrap();

        let msg = client_bi_rx.read_to_end(usize::MAX).await.unwrap();
        assert_eq!(msg.as_slice(), b"world");

        // The server should now be done
        server_handle.await.unwrap();
    }
}
