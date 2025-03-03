#![allow(clippy::type_complexity)]

pub mod network;
pub mod pcap_exporter;
pub mod quinn_interop;
pub mod tracing;
mod util;

use crate::network::node::Host;
use quinn::udp::EcnCodepoint;
use std::fmt::Debug;
use std::net::SocketAddr;

const HOST_PORT: u16 = 8080;

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
    id: uuid::Uuid,
    duplicate: bool,
    source: Host,
    transmit: OwnedTransmit,
    number: u64,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::network::InMemoryNetwork;
    use crate::network::event::{
        NetworkEvent, NetworkEventPayload, NetworkEvents, UpdateLinkStatus,
    };
    use crate::network::ip::Ipv4Cidr;
    use crate::network::node::{HostHandle, Node};
    use crate::network::route::{IpRange, Route};
    use crate::network::spec::{
        NetworkInterface, NetworkLinkSpec, NetworkNodeSpec, NetworkSpec, NodeKind,
    };
    use crate::pcap_exporter::PcapExporter;
    use crate::tracing::tracer::SimulationStepTracer;
    use bon::builder;
    use fastrand::Rng;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::rustls::RootCertStore;
    use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use quinn::udp::RecvMeta;
    use quinn::{AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, ServerConfig, rustls};
    use std::future::Future;
    use std::io;
    use std::io::IoSliceMut;
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::time::Instant;

    const SERVER_ADDR: Ipv4Cidr = Ipv4Cidr::from_ipv4(Ipv4Addr::new(88, 88, 88, 88), 24);
    const ROUTER1_ADDR: Ipv4Cidr = Ipv4Cidr::from_ipv4(Ipv4Addr::new(200, 200, 200, 1), 24);
    const ROUTER2_ADDR: Ipv4Cidr = Ipv4Cidr::from_ipv4(Ipv4Addr::new(200, 200, 200, 2), 24);
    const CLIENT_ADDR: Ipv4Cidr = Ipv4Cidr::from_ipv4(Ipv4Addr::new(1, 1, 1, 1), 24);
    const BANDWIDTH_100_MBPS: u64 = 1000 * 1000 * 100;
    const BANDWIDTH_8_KBPS: u64 = 1000 * 8;

    #[builder]
    fn default_network(
        bandwidth_bps: Option<u64>,
        events: Option<Vec<NetworkEvent>>,
    ) -> Arc<InMemoryNetwork> {
        let bandwidth_bps = bandwidth_bps.unwrap_or(BANDWIDTH_100_MBPS);

        let default_link_delay = Duration::from_millis(10);
        let client_cidr = IpRange::from_cidr(CLIENT_ADDR);
        let server_cidr = IpRange::from_cidr(SERVER_ADDR);

        // SERVER_ADDR -> ROUTER1_ADDR

        let network_spec = NetworkSpec {
            nodes: vec![
                NetworkNodeSpec {
                    id: "server".to_string(),
                    kind: NodeKind::Host,
                    interfaces: vec![NetworkInterface {
                        addresses: vec![SERVER_ADDR],
                        routes: vec![Route {
                            destination: client_cidr.clone(),
                            next: ROUTER1_ADDR.as_ip_addr(),
                            cost: 0,
                        }],
                    }],
                    buffer_size_bytes: u64::MAX,
                },
                NetworkNodeSpec {
                    id: "client".to_string(),
                    kind: NodeKind::Host,
                    interfaces: vec![NetworkInterface {
                        addresses: vec![CLIENT_ADDR],
                        routes: vec![Route {
                            destination: server_cidr.clone(),
                            next: ROUTER2_ADDR.as_ip_addr(),
                            cost: 0,
                        }],
                    }],
                    buffer_size_bytes: u64::MAX,
                },
                NetworkNodeSpec {
                    id: "router1".to_string(),
                    kind: NodeKind::Router,
                    interfaces: vec![NetworkInterface {
                        addresses: vec![ROUTER1_ADDR],
                        routes: vec![
                            Route {
                                destination: client_cidr.clone(),
                                next: ROUTER2_ADDR.as_ip_addr(),
                                cost: 0,
                            },
                            Route {
                                destination: server_cidr.clone(),
                                next: SERVER_ADDR.as_ip_addr(),
                                cost: 0,
                            },
                        ],
                    }],
                    buffer_size_bytes: u64::MAX,
                },
                NetworkNodeSpec {
                    id: "router2".to_string(),
                    kind: NodeKind::Router,
                    interfaces: vec![NetworkInterface {
                        addresses: vec![ROUTER2_ADDR],
                        routes: vec![
                            Route {
                                destination: client_cidr.clone(),
                                next: CLIENT_ADDR.as_ip_addr(),
                                cost: 0,
                            },
                            Route {
                                destination: server_cidr.clone(),
                                next: ROUTER1_ADDR.as_ip_addr(),
                                cost: 0,
                            },
                        ],
                    }],
                    buffer_size_bytes: u64::MAX,
                },
            ],
            links: vec![
                NetworkLinkSpec {
                    id: "server-router1".to_string().into_boxed_str().into(),
                    source: SERVER_ADDR.as_ip_addr(),
                    target: ROUTER1_ADDR.as_ip_addr(),
                    delay: default_link_delay,
                    bandwidth_bps: BANDWIDTH_100_MBPS,
                    congestion_event_ratio: 0.0,
                    packet_loss_ratio: 0.0,
                    packet_duplication_ratio: 0.0,
                    extra_delay: Default::default(),
                    extra_delay_ratio: 0.0,
                },
                NetworkLinkSpec {
                    id: "router1-router2".to_string().into_boxed_str().into(),
                    source: ROUTER1_ADDR.as_ip_addr(),
                    target: ROUTER2_ADDR.as_ip_addr(),
                    delay: default_link_delay,
                    bandwidth_bps,
                    congestion_event_ratio: 0.0,
                    packet_loss_ratio: 0.0,
                    packet_duplication_ratio: 0.0,
                    extra_delay: Default::default(),
                    extra_delay_ratio: 0.0,
                },
                NetworkLinkSpec {
                    id: "router2-client".to_string().into_boxed_str().into(),
                    source: ROUTER2_ADDR.as_ip_addr(),
                    target: CLIENT_ADDR.as_ip_addr(),
                    delay: default_link_delay,
                    bandwidth_bps,
                    congestion_event_ratio: 0.0,
                    packet_loss_ratio: 0.0,
                    packet_duplication_ratio: 0.0,
                    extra_delay: Default::default(),
                    extra_delay_ratio: 0.0,
                },
                NetworkLinkSpec {
                    id: "router1-server".to_string().into_boxed_str().into(),
                    source: ROUTER1_ADDR.as_ip_addr(),
                    target: SERVER_ADDR.as_ip_addr(),
                    delay: default_link_delay,
                    bandwidth_bps,
                    congestion_event_ratio: 0.0,
                    packet_loss_ratio: 0.0,
                    packet_duplication_ratio: 0.0,
                    extra_delay: Default::default(),
                    extra_delay_ratio: 0.0,
                },
                NetworkLinkSpec {
                    id: "router2-router1".to_string().into_boxed_str().into(),
                    source: ROUTER2_ADDR.as_ip_addr(),
                    target: ROUTER1_ADDR.as_ip_addr(),
                    delay: default_link_delay,
                    bandwidth_bps,
                    congestion_event_ratio: 0.0,
                    packet_loss_ratio: 0.0,
                    packet_duplication_ratio: 0.0,
                    extra_delay: Default::default(),
                    extra_delay_ratio: 0.0,
                },
                NetworkLinkSpec {
                    id: "client-router2".to_string().into_boxed_str().into(),
                    source: CLIENT_ADDR.as_ip_addr(),
                    target: ROUTER2_ADDR.as_ip_addr(),
                    delay: default_link_delay,
                    bandwidth_bps: BANDWIDTH_100_MBPS,
                    congestion_event_ratio: 0.0,
                    packet_loss_ratio: 0.0,
                    packet_duplication_ratio: 0.0,
                    extra_delay: Default::default(),
                    extra_delay_ratio: 0.0,
                },
            ],
        };

        InMemoryNetwork::initialize(
            network_spec.clone(),
            NetworkEvents::new(events.unwrap_or_default(), &network_spec.links),
            Arc::new(SimulationStepTracer::new(
                Arc::new(PcapExporter::noop()),
                network_spec,
            )),
            Rng::with_seed(42),
            Instant::now(),
        )
        .unwrap()
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

    #[tokio::test(start_paused = true)]
    async fn test_quic_handshake_and_bidi_stream_works() {
        let rt = quinn::default_runtime().unwrap();

        // Network
        let network = default_network().call();
        let server_socket = Arc::new(network.host(SERVER_ADDR.as_ip_addr()));
        let client_socket = Arc::new(network.host(CLIENT_ADDR.as_ip_addr()));

        // QUIC config
        let (server_name, server_cert, server_config) = default_server_config();
        let client_config = default_client_config(server_cert);

        // QUIC endpoints
        let server_endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            Arc::new(network.host_handle((*server_socket).clone())),
            rt.clone(),
        )
        .unwrap();
        let mut client_endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            Arc::new(network.host_handle((*client_socket).clone())),
            rt,
        )
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
            .connect(server_socket.addr, server_name)
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

    #[tokio::test(start_paused = true)]
    async fn test_packet_arrives_at_expected_time() {
        // Sanity check
        let network = default_network().call();
        let server_socket = Arc::new(network.host(SERVER_ADDR.as_ip_addr()));
        let client_socket = Arc::new(network.host(CLIENT_ADDR.as_ip_addr()));
        network
            .assert_connectivity_between_hosts(server_socket.addr.ip(), client_socket.addr.ip())
            .await
            .unwrap();

        // Test
        let network = default_network().call();
        let server_socket = Arc::new(network.host(SERVER_ADDR.as_ip_addr()));
        let client_socket = Arc::new(network.host(CLIENT_ADDR.as_ip_addr()));
        let data = network.in_transit_data(
            (*client_socket).clone(),
            OwnedTransmit {
                destination: server_socket.addr,
                ecn: None,
                contents: b"hello world".to_vec(),
                segment_size: None,
            },
        );
        let packet_id = data.id;
        network.forward(Node::Host((*client_socket).clone()), data);

        let mut recv_result = BufsAndMeta::new();
        let received = {
            let host_receive = HostReceive {
                host_handle: network.host_handle((*server_socket).clone()),
                result: &mut recv_result,
            };
            host_receive.await.unwrap()
        };

        assert_eq!(received, 1);
        assert_eq!(recv_result.meta[0].len, 11);
        assert_eq!(&recv_result.bufs[0][..11], b"hello world");

        // This test proves that the packet travels a specific path and is delayed at each hop
        let expected_timings = [
            (Duration::from_millis(0), "client"),
            (Duration::from_millis(10), "router2"),
            (Duration::from_millis(20), "router1"),
            (Duration::from_millis(30), "server"),
        ];

        let stepper = network.tracer.stepper();
        let hops = stepper.get_packet_hops(packet_id);

        assert_eq!(hops.len(), expected_timings.len());
        for ((duration, node), (expected_duration, expected_node)) in
            hops.into_iter().zip(expected_timings)
        {
            assert_eq!(&*node, expected_node);
            assert_eq!(duration, expected_duration, "{node:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_packet_is_delayed_by_buffering() {
        let bandwidths_and_delays = [
            (BANDWIDTH_100_MBPS, Duration::from_millis(0)),
            (BANDWIDTH_8_KBPS, Duration::from_secs_f64(1.2)),
        ];
        for (bandwidth, expected_delay) in bandwidths_and_delays {
            // Sanity check
            let network = default_network().bandwidth_bps(bandwidth).call();
            let server_socket = Arc::new(network.host(SERVER_ADDR.as_ip_addr()));
            let client_socket = Arc::new(network.host(CLIENT_ADDR.as_ip_addr()));
            network
                .assert_connectivity_between_hosts(client_socket.addr.ip(), server_socket.addr.ip())
                .await
                .unwrap();

            // Actual test
            let network = default_network().bandwidth_bps(bandwidth).call();
            let server_socket = Arc::new(network.host(SERVER_ADDR.as_ip_addr()));
            let client_socket = Arc::new(network.host(CLIENT_ADDR.as_ip_addr()));

            let mut packet_ids = Vec::new();
            for _ in 0..4 {
                let data = network.in_transit_data(
                    (*client_socket).clone(),
                    OwnedTransmit {
                        destination: network.host_handle((*server_socket).clone()).addr(),
                        ecn: None,
                        contents: vec![42; 1200],
                        segment_size: None,
                    },
                );

                packet_ids.push(data.id);
                network.forward(Node::Host((*client_socket).clone()), data.clone());
            }

            let mut received = 0;
            while received < 4 {
                let mut recv_result = BufsAndMeta::new();
                received += {
                    let host_receive = HostReceive {
                        host_handle: network.host_handle((*server_socket).clone()),
                        result: &mut recv_result,
                    };

                    host_receive.await.unwrap()
                };

                assert!(received >= 1);
                assert_eq!(recv_result.meta[0].len, 1200);
            }

            assert_eq!(received, 4);

            let stepper = network.tracer.stepper();

            let mut arrival_times = Vec::new();
            for packet_id in packet_ids {
                let packet_arrived = stepper.get_packet_arrived_at(packet_id, &server_socket.id);
                arrival_times.push(packet_arrived.unwrap());
            }

            for x in arrival_times.windows(2) {
                let delay = *x.last().unwrap() - *x.first().unwrap();
                assert_eq!(delay, expected_delay);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_packet_is_buffered_when_link_down() {
        // Let one of the links be down for 10 seconds
        let network = default_network()
            .events(vec![
                NetworkEvent {
                    relative_time: Duration::from_secs(0),
                    payload: NetworkEventPayload {
                        link_id: "router2-router1".into(),
                        status: Some(UpdateLinkStatus::Down),
                        bandwidth_bps: None,
                        delay: None,
                        extra_delay: None,
                        extra_delay_ratio: None,
                        packet_duplication_ratio: None,
                        packet_loss_ratio: None,
                        congestion_event_ratio: None,
                    },
                },
                NetworkEvent {
                    relative_time: Duration::from_secs(10),
                    payload: NetworkEventPayload {
                        link_id: "router2-router1".into(),
                        status: Some(UpdateLinkStatus::Up),
                        bandwidth_bps: None,
                        delay: None,
                        extra_delay: None,
                        extra_delay_ratio: None,
                        packet_duplication_ratio: None,
                        packet_loss_ratio: None,
                        congestion_event_ratio: None,
                    },
                },
            ])
            .call();

        let server_socket = Arc::new(network.host(SERVER_ADDR.as_ip_addr()));
        let client_socket = Arc::new(network.host(CLIENT_ADDR.as_ip_addr()));

        let data = network.in_transit_data(
            (*client_socket).clone(),
            OwnedTransmit {
                destination: network.host_handle((*server_socket).clone()).host.addr,
                ecn: None,
                contents: vec![42; 1200],
                segment_size: None,
            },
        );
        let packet_id = data.id;

        network.forward(Node::Host((*client_socket).clone()), data.clone());
        let mut recv_result = BufsAndMeta::new();
        let received = {
            let host_receive = HostReceive {
                host_handle: network.host_handle((*server_socket).clone()),
                result: &mut recv_result,
            };

            host_receive.await.unwrap()
        };

        assert_eq!(received, 1);
        assert_eq!(recv_result.meta[0].len, 1200);

        let stepper = network.tracer.stepper();
        let hops = stepper.get_packet_hops(packet_id);
        assert_eq!(hops.len(), 4);

        // This test proves that the packet travels a specific path and is delayed at each hop
        let expected_timings = [
            (Duration::from_millis(0), "client"),
            (Duration::from_millis(10), "router2"),
            (Duration::from_millis(10_010), "router1"),
            (Duration::from_millis(10_020), "server"),
        ];

        assert_eq!(hops.len(), expected_timings.len());
        for ((duration, node), (expected_duration, expected_node)) in
            hops.into_iter().zip(expected_timings)
        {
            assert_eq!(&*node, expected_node);
            assert_eq!(duration, expected_duration, "{node:?}");
        }
    }

    // Utility future for testing a Host's `poll_recv`
    struct HostReceive<'a> {
        host_handle: HostHandle,
        result: &'a mut BufsAndMeta,
    }

    struct BufsAndMeta {
        bufs: Vec<Vec<u8>>,
        meta: Vec<RecvMeta>,
    }

    impl BufsAndMeta {
        fn new() -> Self {
            Self {
                bufs: vec![vec![0u8; 1500]; 4],
                meta: vec![RecvMeta::default(); 4],
            }
        }
    }

    impl Future for HostReceive<'_> {
        type Output = io::Result<usize>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = &mut *self;

            let host_handle = &mut this.host_handle;
            let bufs = &mut this.result.bufs;
            let meta = &mut this.result.meta;

            let mut bufs: Vec<_> = bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
            host_handle.poll_recv(cx, &mut bufs, meta)
        }
    }
}
