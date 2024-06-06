mod no_cc;
mod no_cid;

use crate::no_cc::NoCCConfig;
use crate::no_cid::NoConnectionIdGenerator;
use anyhow::{anyhow, Context};
use clap::Parser;
use fastrand::Rng;
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

#[derive(Parser, Debug, Clone)]
struct Opt {
    /// Sets many transport config parameters to very large values (such as ::MAX) to handle
    /// deep space usage, where delays and disruptions can be in order of minutes, hours, days
    #[arg(long)]
    dtn: bool,

    /// The amount of times the http request should be repeated
    #[arg(long, default_value_t = 10)]
    repeat: u32,

    /// The delay on outgoing packets, in milliseconds
    #[arg(long, default_value_t = 5000)]
    delay: u64,

    /// The bandwidth of the simulated link, in bytes
    #[arg(long, default_value_t = usize::MAX)]
    bandwidth: usize,

    /// The ratio of packet loss (e.g. 0.1 = 10% packet loss)
    #[arg(long, default_value_t = 0.05)]
    loss: f64,

    /// Initial RTT in ms
    #[arg(long, default_value_t = 100000000)]
    initial_rtt: u64,

    /// Packet Threshold
    #[arg(long, default_value_t = u32::MAX)]
    packet_threshold: u32,

    /// Buffer size
    #[arg(long, default_value_t = usize::MAX)]
    buffer_size: usize,

    /// MTU Discovery
    #[arg(long, default_value_t = false)]
    mtu_discovery: bool,

    /// Almost no congestion control
    #[arg(long, default_value_t = true)]
    no_cc: bool,

    /// Maximum Idle Timeout
    #[arg(long, default_value_t = 1000000000)]
    maximum_idle_timeout: u64,

    /// Send Window Size
    #[arg(long, default_value_t = u64::MAX)]
    send_window_size: u64,

    /// Quinn's random seed, which you can control to generate deterministic results
    #[arg(long, default_value_t = 0)]
    quinn_rng_seed: u64,

    /// The random seed used for packet loss, which you can control to generate deterministic
    /// results
    #[arg(long, default_value_t = 42)]
    packet_loss_rng_seed: u64,

    /// Ignore any provided random seeds and try many of them in succession, attempting to find a
    /// combination that causes the application to hang
    #[arg(long)]
    find_hangs: bool,
}

fn main() -> anyhow::Result<()> {
    std::env::set_var("SSLKEYLOGFILE", "keylog.key");
    let opt = Opt::parse();

    if opt.find_hangs {
        find_hangs(opt)
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("failed to initialize tokio");

        let pcap_exporter = Arc::new(PcapExporter::new());
        let result = rt.block_on(run(&opt, pcap_exporter.clone()));

        // Always save export, regardless of success / failure
        pcap_exporter.save("capture.pcap".as_ref());

        result
    }
}

fn find_hangs(opt: Opt) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut rng = Rng::new();
    loop {
        let mut opt = opt.clone();
        opt.quinn_rng_seed = rng.u64(..);
        opt.packet_loss_rng_seed = rng.u64(..);

        println!("---\n---New run\n---");
        let pcap_exporter = Arc::new(PcapExporter::new());

        let pcap_exporter_clone = pcap_exporter.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .expect("failed to initialize tokio");

            rt.block_on(run(&opt, pcap_exporter))
        });

        std::thread::sleep(Duration::from_millis(200));
        if !thread.is_finished() {
            std::thread::sleep(Duration::from_millis(1500));
            if !thread.is_finished() {
                panic!("Got stuck");
                // break Ok(());
                // continue;
            }
        }

        if thread.join().unwrap().is_err() {
            pcap_exporter_clone.save("capture.pcap".as_ref());
            break Ok(());
        }

        if start.elapsed() > Duration::from_secs(60) {
            println!("No hangs found after 60 seconds");
            break Ok(());
        }
    }
}

async fn run(options: &Opt, pcap_exporter: Arc<PcapExporter>) -> anyhow::Result<()> {
    println!(
        "Quinn seed: {}; packet loss seed: {}",
        options.quinn_rng_seed, options.packet_loss_rng_seed
    );

    let mut quinn_rng = Rng::with_seed(options.quinn_rng_seed);
    let mut packet_loss_rng = Rng::with_seed(options.packet_loss_rng_seed);

    // Certificates
    let server_name = "server-name";
    let cert = rcgen::generate_simple_self_signed(vec![server_name.into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    // Network
    let simulated_link_delay = Duration::from_millis(options.delay);
    let simulated_link_capacity = options.bandwidth;
    let packet_loss_ratio = options.loss;
    let network = Arc::new(InMemoryNetwork::initialize(
        simulated_link_delay,
        simulated_link_capacity,
        packet_loss_ratio,
        pcap_exporter.clone(),
    ));

    // Let a server listen in the background
    let server = server_endpoint(
        cert.clone(),
        key.into(),
        network.clone(),
        options,
        &mut quinn_rng,
        &mut packet_loss_rng,
    )?;
    let server_task = tokio::spawn(server_listen(server));

    // Make repeated requests
    let client = client_endpoint(cert, network, options, &mut quinn_rng, &mut packet_loss_rng)?;
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
    quinn_rng: &mut Rng,
    packet_loss_rng: &mut Rng,
) -> anyhow::Result<Endpoint> {
    let mut seed = [0; 32];
    quinn_rng.fill(&mut seed);

    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
    server_config.transport = Arc::new(transport_config(options));
    Endpoint::new_with_abstract_socket_and_rng_seed(
        endpoint_config(),
        Some(server_config),
        Arc::new(network.server_socket(packet_loss_rng)),
        quinn::default_runtime().unwrap(),
        seed,
    )
    .context("failed to create server endpoint")
}

fn client_endpoint(
    server_cert: CertificateDer<'_>,
    network: Arc<InMemoryNetwork>,
    options: &Opt,
    quinn_rng: &mut Rng,
    packet_loss_rng: &mut Rng,
) -> anyhow::Result<Endpoint> {
    let mut seed = [0; 32];
    quinn_rng.fill(&mut seed);

    let mut endpoint = Endpoint::new_with_abstract_socket_and_rng_seed(
        endpoint_config(),
        None,
        Arc::new(network.client_socket(packet_loss_rng)),
        quinn::default_runtime().unwrap(),
        seed,
    )
    .context("failed to create client endpoint")?;

    endpoint.set_default_client_config(client_config(server_cert, options)?);

    Ok(endpoint)
}

fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.cid_generator(|| Box::new(NoConnectionIdGenerator));
    config
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

    if options.dtn {
        // DTN stuff
        if !options.mtu_discovery { config.mtu_discovery_config(None); }
        config.max_idle_timeout(Some(
            Duration::from_millis(options.maximum_idle_timeout)
                .try_into()
                .unwrap(),
        ));
        config.receive_window(VarInt::MAX);
        config.datagram_send_buffer_size(options.buffer_size);
        config.send_window(options.send_window_size);
        config.datagram_receive_buffer_size(Some(options.buffer_size));
        config.stream_receive_window(VarInt::MAX);
        if options.no_cc {
            config.congestion_controller_factory(Arc::new(NoCCConfig::default()));
        }
        let mut ack_frequency_config = AckFrequencyConfig::default();
        ack_frequency_config.max_ack_delay(Some(Duration::MAX));
        config.ack_frequency_config(Some(ack_frequency_config));
        config.packet_threshold(options.packet_threshold);
        config.initial_rtt(Duration::from_millis(options.initial_rtt));
    }
    config
}
