use anyhow::{anyhow, Context};
use in_memory_network::{InMemoryNetwork, PcapExporter};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::rustls::RootCertStore;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to initialize tokio");

    rt.block_on(run())?;
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    // Certificates
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    // Network
    let pcap_exporter = Arc::new(PcapExporter::new());
    let simulated_link_delay = Duration::from_secs(0);
    let simulated_link_capacity = usize::MAX;
    let network = Arc::new(InMemoryNetwork::initialize(
        simulated_link_delay,
        simulated_link_capacity,
        pcap_exporter.clone(),
    ));

    // Let a server listen in the background
    let server = server_endpoint(cert.clone(), key.into(), network.clone())?;
    let server_task = tokio::spawn(server_listen(server));

    // Make repeated requests
    let client = client_endpoint(cert, network)?;
    let connection = client
        .connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            "localhost",
        )?
        .await?;

    let mut received = Vec::new();
    for b in 42..45 {
        let (mut tx, mut rx) = connection.open_bi().await?;
        tx.write_all(&[b]).await?;

        let mut buf = [0];
        rx.read_exact(&mut buf).await?;

        received.push(buf[0]);
    }

    connection.close(VarInt::from_u32(0), b"done");

    drop(connection);
    drop(client);

    server_task
        .await
        .context("server task crashed")?
        .context("server task errored")?;

    println!("Done! Received: {received:?}");

    pcap_exporter.save("capture.pcap".as_ref());

    Ok(())
}

async fn server_listen(endpoint: Endpoint) -> anyhow::Result<()> {
    let conn = endpoint
        .accept()
        .await
        .ok_or(anyhow!("failed to accept incoming connection"))?
        .await?;

    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        // Read a single byte
        let mut buf = [0];
        rx.read_exact(&mut buf).await?;

        // Echo it back
        tx.write(&buf).await?;
    }

    Ok(())
}

fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    network: Arc<InMemoryNetwork>,
) -> anyhow::Result<Endpoint> {
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
    server_config.transport = Arc::new(transport_config());
    Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        Arc::new(network.server_socket()),
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create server endpoint")
}

fn client_endpoint(
    server_cert: CertificateDer<'_>,
    network: Arc<InMemoryNetwork>,
) -> anyhow::Result<Endpoint> {
    let mut endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        Arc::new(network.client_socket()),
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create client endpoint")?;

    endpoint.set_default_client_config(client_config(server_cert)?);

    Ok(endpoint)
}

fn client_config(server_cert: CertificateDer<'_>) -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(server_cert)?;

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

    let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    client_config.transport_config(Arc::new(transport_config()));

    Ok(client_config)
}

fn transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.mtu_discovery_config(None);
    // config.initial_rtt(Duration::from_secs(5));

    config
}
