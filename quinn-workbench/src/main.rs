mod no_cc;

use crate::no_cc::NoCCConfig;
use anyhow::{anyhow, Context};
use clap::Parser;
use in_memory_network::{InMemoryNetwork, PcapExporter, SERVER_ADDR};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::rustls::RootCertStore;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};
use quinn_proto::AckFrequencyConfig;
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Parser, Debug)]
struct Opt {
    /// Sets many transport config parameters to very large values (such as ::MAX) to handle
    /// deep space usage, where delays and disruptions can be in order of minutes, hours, days
    #[arg(long)]
    dtn: bool,

    /// The amount of times the http request should be repeated
    #[arg(long, default_value_t = 10)]
    repeat: u32,

    /// The delay on outgoing packets, in seconds
    #[arg(long, default_value_t = 5)]
    delay: u64,

    /// The bandwidth of the simulated link, in bytes
    #[arg(long, default_value_t = usize::MAX)]
    bandwidth: usize,

    /// The ratio of packet loss (e.g. 0.1 = 10% packet loss)
    #[arg(long, default_value_t = 0.05)]
    loss: f64,
}

fn main() -> anyhow::Result<()> {
    std::env::set_var("SSLKEYLOGFILE", "keylog.key");
    let opt = Opt::parse();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("failed to initialize tokio");

    rt.block_on(run(&opt))?;
    Ok(())
}

async fn run(options: &Opt) -> anyhow::Result<()> {
    // Certificates
    let server_name = "server-name";
    let cert = rcgen::generate_simple_self_signed(vec![server_name.into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    // Network
    let pcap_exporter = Arc::new(PcapExporter::new());
    let simulated_link_delay = Duration::from_secs(options.delay);
    let simulated_link_capacity = options.bandwidth;
    let packet_loss_ratio = options.loss;
    let network = Arc::new(InMemoryNetwork::initialize(
        simulated_link_delay,
        simulated_link_capacity,
        packet_loss_ratio,
        pcap_exporter.clone(),
    ));

    // Let a server listen in the background
    let server = server_endpoint(cert.clone(), key.into(), network.clone(), options)?;
    let server_task = tokio::spawn(server_listen(server));

    // Make repeated requests
    let client = client_endpoint(cert, network, options)?;
    let start = Instant::now();
    println!("0.00s CONNECT");
    let connection = client.connect(SERVER_ADDR, server_name)?.await?;

    let request_number = options.repeat;
    let request = "GET /index.html";
    for _ in 0..request_number {
        println!("{:.02}s {request}", start.elapsed().as_secs_f64());

        let (mut tx, mut rx) = connection.open_bi().await?;
        tx.write_all(request.as_bytes()).await?;
        tx.finish()?;

        rx.read_to_end(usize::MAX).await?;
    }

    println!(
        "Done! Sent {request_number} requests in {:.02}s. Waiting for connection close...",
        start.elapsed().as_secs_f64()
    );

    connection.close(VarInt::from_u32(0), &[]);

    drop(connection);
    drop(client);

    server_task
        .await
        .context("server task crashed")?
        .context("server task errored")?;

    println!(
        "Time from start to connection closed: {:.02}s",
        start.elapsed().as_secs_f64()
    );

    pcap_exporter.save("capture.pcap".as_ref());

    Ok(())
}

async fn server_listen(endpoint: Endpoint) -> anyhow::Result<()> {
    let conn = endpoint
        .accept()
        .await
        .ok_or(anyhow!("failed to accept incoming connection"))?
        .await?;

    let response = "<html>
      <h1>Hello from Internet in Deep Space</h1>
      <p>This message was sent over HTTP/QUIC/UDP/IP with a long delay</p>
    </html>";

    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        // Read the request
        let request = rx.read_to_end(usize::MAX).await?;
        assert_eq!(request, b"GET /index.html");

        // Respond
        tx.write(response.as_bytes()).await?;
        tx.finish()?;
    }

    Ok(())
}

fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    network: Arc<InMemoryNetwork>,
    options: &Opt,
) -> anyhow::Result<Endpoint> {
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
    server_config.transport = Arc::new(transport_config(options));
    Endpoint::new_with_abstract_socket_and_rng_seed(
        EndpointConfig::default(),
        Some(server_config),
        Arc::new(network.server_socket()),
        quinn::default_runtime().unwrap(),
        [0; 32],
    )
    .context("failed to create server endpoint")
}

fn client_endpoint(
    server_cert: CertificateDer<'_>,
    network: Arc<InMemoryNetwork>,
    options: &Opt,
) -> anyhow::Result<Endpoint> {
    let mut endpoint = Endpoint::new_with_abstract_socket_and_rng_seed(
        EndpointConfig::default(),
        None,
        Arc::new(network.client_socket()),
        quinn::default_runtime().unwrap(),
        [0; 32],
    )
    .context("failed to create client endpoint")?;

    endpoint.set_default_client_config(client_config(server_cert, options)?);

    Ok(endpoint)
}

fn client_config(server_cert: CertificateDer<'_>, options: &Opt) -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(server_cert)?;

    let default_provider = rustls::crypto::ring::default_provider();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
        ..default_provider
    };

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    client_config.transport_config(Arc::new(transport_config(options)));

    Ok(client_config)
}

fn transport_config(options: &Opt) -> TransportConfig {
    let mut config = TransportConfig::default();
    config.mtu_discovery_config(None);

    if options.dtn {
        // DTN stuff
        config.max_idle_timeout(Some(VarInt::MAX.into()));
        config.receive_window(VarInt::MAX);
        config.datagram_send_buffer_size(usize::MAX);
        config.send_window(u64::MAX);
        config.datagram_receive_buffer_size(Some(usize::MAX));
        config.stream_receive_window(VarInt::MAX);
        config.congestion_controller_factory(Arc::new(NoCCConfig::default()));
        let mut ack_frequency_config = AckFrequencyConfig::default();
        ack_frequency_config.max_ack_delay(Some(Duration::MAX));
        config.ack_frequency_config(Some(ack_frequency_config));
        config.packet_threshold(u32::MAX);
        config.initial_rtt(Duration::from_secs(100000));
    }
    config
}
