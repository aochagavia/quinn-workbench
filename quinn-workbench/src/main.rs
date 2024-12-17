mod config;
mod quinn_extensions;

use crate::config::SimulationConfig;
use anyhow::{anyhow, Context};
use clap::Parser;
use config::cli::CliOpt;
use config::quinn::QuinnJsonConfig;
use fastrand::Rng;
use in_memory_network::network::node::HostHandle;
use in_memory_network::network::InMemoryNetwork;
use in_memory_network::pcap_exporter::PcapExporter;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use quinn::rustls::RootCertStore;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};
use quinn_extensions::ecn_cc::EcnCcFactory;
use quinn_extensions::no_cc::NoCCConfig;
use quinn_extensions::no_cid::NoConnectionIdGenerator;
use quinn_proto::congestion::NewRenoConfig;
use quinn_proto::AckFrequencyConfig;
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_ansi(false)
        .without_time()
        .init();

    std::env::set_var("SSLKEYLOGFILE", "keylog.key");
    let opt = CliOpt::parse();
    let simulation_config = load_simulation_config(&opt)?;

    if opt.find_hangs {
        find_hangs(opt)
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("failed to initialize tokio");

        let start = Instant::now();
        let pcap_exporter = Arc::new(PcapExporter::new());
        let result = rt.block_on(run(&opt, simulation_config, pcap_exporter.clone()));

        // Always save export, regardless of success / failure
        pcap_exporter.save("capture.pcap".as_ref());

        if result.is_err() {
            eprintln!("Error after {:.2}s", start.elapsed().as_secs_f64());
        }

        result
    }
}

fn load_simulation_config(cli: &CliOpt) -> anyhow::Result<SimulationConfig> {
    let quinn = load_json(&cli.quinn_config)?;
    let network_graph = load_json(&cli.network_graph)?;
    let network_events = load_json(&cli.network_events)?;

    Ok(SimulationConfig {
        quinn,
        network_graph,
        network_events,
    })
}

fn load_json<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let file =
        File::open(path).with_context(|| format!("unable to open file at `{}`", path.display()))?;
    let parsed = serde_json::from_reader(file)
        .with_context(|| format!("error parsing JSON from `{}`", path.display()))?;
    Ok(parsed)
}

fn find_hangs(opt: CliOpt) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut rng = Rng::new();
    loop {
        let mut opt = opt.clone();
        opt.quinn_rng_seed = rng.u64(..);
        opt.simulated_network_rng_seed = rng.u64(..);
        let simulation_config = load_simulation_config(&opt)?;

        println!("---\n---New run\n---");
        let pcap_exporter = Arc::new(PcapExporter::new());

        let pcap_exporter_clone = pcap_exporter.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .expect("failed to initialize tokio");

            rt.block_on(run(&opt, simulation_config, pcap_exporter))
        });

        std::thread::sleep(Duration::from_millis(200));
        if !thread.is_finished() {
            std::thread::sleep(Duration::from_millis(1500));
            if !thread.is_finished() {
                panic!("Got stuck");
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

async fn run(
    options: &CliOpt,
    config: SimulationConfig,
    pcap_exporter: Arc<PcapExporter>,
) -> anyhow::Result<()> {
    println!("--- Params ---");
    let (quinn_rng_seed, simulated_network_rng_seed) = if options.non_deterministic {
        let mut rng = Rng::new();
        (rng.u64(..), rng.u64(..))
    } else {
        (options.quinn_rng_seed, options.simulated_network_rng_seed)
    };
    println!("* Quinn seed: {}", quinn_rng_seed);
    println!("* Network seed: {}", simulated_network_rng_seed);
    println!("* Quinn config path: {}", options.quinn_config.display());
    println!("* Network graph path: {}", options.network_graph.display());
    println!(
        "* Network events path: {}",
        options.network_events.display()
    );

    let start = Instant::now();

    // Network check
    let network_check_pcap_exporter = Arc::new(PcapExporter::new());
    let network = InMemoryNetwork::initialize(
        config.network_graph.clone().into(),
        config
            .network_events
            .clone()
            .into_iter()
            .map(|e| e.into())
            .collect(),
        network_check_pcap_exporter,
        Rng::with_seed(simulated_network_rng_seed),
        start,
    )?;

    println!("--- Network ---");
    println!("* Running connectivity check...");
    let (arrived1, arrived2) = network.assert_connectivity_between_hosts().await?;
    println!(
        "* Connectivity check passed (packets arrived after {} ms and {} ms)",
        (arrived1 - start).as_millis(),
        (arrived2 - start).as_millis()
    );

    drop(network);

    let start = Instant::now();

    // Network
    let network = InMemoryNetwork::initialize(
        config.network_graph.into(),
        config
            .network_events
            .into_iter()
            .map(|e| e.into())
            .collect(),
        pcap_exporter.clone(),
        Rng::with_seed(simulated_network_rng_seed),
        start,
    )?;

    // Set up server certificate
    let server_name = "server-name";
    let cert = rcgen::generate_simple_self_signed(vec![server_name.into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    // Let a server listen in the background
    let mut quinn_rng = Rng::with_seed(quinn_rng_seed);
    let server_host = network.host_a();
    let server_addr = server_host.addr();
    let server = server_endpoint(
        cert.clone(),
        key.into(),
        server_host,
        &config.quinn,
        &mut quinn_rng,
    )?;
    let server_task = tokio::spawn(server_listen(server, options.response_size));

    // Make repeated requests
    println!("--- Requests ---");
    let client = client_endpoint(cert, network.host_b(), &config.quinn, &mut quinn_rng)?;
    println!("{:.2}s CONNECT", start.elapsed().as_secs_f64());
    let connection = client
        .connect(server_addr, server_name)
        .context("failed to start connecting to server")?
        .await
        .context("client failed to connect to server")?;

    let request_number = options.repeat;
    let request = "GET /index.html";
    for _ in 0..request_number {
        println!("{:.2}s {request}", start.elapsed().as_secs_f64());

        let (mut tx, mut rx) = connection.open_bi().await?;
        tx.write_all(request.as_bytes()).await?;
        tx.finish()?;

        rx.read_to_end(usize::MAX).await?;
    }

    println!(
        "{:.2}s Done sending {request_number} requests",
        start.elapsed().as_secs_f64()
    );

    connection.close(VarInt::from_u32(0), &[]);

    drop(connection);
    drop(client);

    server_task
        .await
        .context("server task crashed")?
        .context("server task errored")?;

    let total_time_sec = start.elapsed().as_secs_f64();
    println!("{:.2}s Connection closed", total_time_sec);

    // let rtt_sec = simulated_link_delay.as_secs_f64() * 2.0;
    println!("--- Stats ---");
    println!(
        "* Time from start to connection closed: {:.2}s",
        total_time_sec,
    );

    let stats = network.stats();
    for (name, stats) in [("Client", stats.peer_b), ("Server", stats.peer_a)] {
        println!(
            "* {name} packets successfully sent: {} ({} bytes)",
            stats.sent.packets, stats.sent.bytes,
        );
        println!(
            "  * From the above packets, {} were duplicates ({} bytes)",
            stats.duplicates.packets, stats.duplicates.bytes
        );
        println!(
            "  * From the above packets, {} were received out of order by the peer ({} bytes)",
            stats.out_of_order.packets, stats.out_of_order.bytes
        );
        println!(
            "  * From the above packets, {} were marked with the CE ECN codepoint",
            stats.congestion_experienced
        );
        println!(
            "* {name} packets dropped: {} ({} bytes)",
            stats.dropped.packets, stats.dropped.bytes
        );
    }

    Ok(())
}

async fn server_listen(endpoint: Endpoint, response_payload_size: usize) -> anyhow::Result<()> {
    let conn = endpoint
        .accept()
        .await
        .ok_or(anyhow!("failed to accept incoming connection"))?
        .await?;

    let response: Vec<_> = "Lorem ipsum "
        .bytes()
        .cycle()
        .take(response_payload_size)
        .collect();

    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        // Read the request
        let request = rx.read_to_end(usize::MAX).await?;
        assert_eq!(request, b"GET /index.html");

        // Respond
        tx.write_all(&response).await?;
        tx.finish()?;
    }

    Ok(())
}

fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    server_host: HostHandle,
    quinn_config: &QuinnJsonConfig,
    quinn_rng: &mut Rng,
) -> anyhow::Result<Endpoint> {
    let mut seed = [0; 32];
    quinn_rng.fill(&mut seed);

    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
    server_config.transport = Arc::new(transport_config(quinn_config));
    Endpoint::new_with_abstract_socket(
        endpoint_config(seed),
        Some(server_config),
        Arc::new(server_host),
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create server endpoint")
}

fn client_endpoint(
    server_cert: CertificateDer<'_>,
    client_host: HostHandle,
    quinn_config: &QuinnJsonConfig,
    quinn_rng: &mut Rng,
) -> anyhow::Result<Endpoint> {
    let mut seed = [0; 32];
    quinn_rng.fill(&mut seed);

    let mut endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config(seed),
        None,
        Arc::new(client_host),
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create client endpoint")?;

    endpoint.set_default_client_config(client_config(server_cert, quinn_config)?);

    Ok(endpoint)
}

fn endpoint_config(rng_seed: [u8; 32]) -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.rng_seed(Some(rng_seed));
    config.cid_generator(|| Box::new(NoConnectionIdGenerator));
    config
}

fn client_config(
    server_cert: CertificateDer<'_>,
    quinn_config: &QuinnJsonConfig,
) -> anyhow::Result<ClientConfig> {
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

    let mut client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    client_config.transport_config(Arc::new(transport_config(quinn_config)));

    Ok(client_config)
}

fn transport_config(quinn_config: &QuinnJsonConfig) -> TransportConfig {
    let mut config = TransportConfig::default();

    if !quinn_config.mtu_discovery {
        config.mtu_discovery_config(None);
    }

    config.max_idle_timeout(Some(
        Duration::from_millis(quinn_config.maximum_idle_timeout_ms)
            .try_into()
            .unwrap(),
    ));

    if quinn_config.maximize_send_and_receive_windows {
        config.receive_window(VarInt::MAX);
        config.stream_receive_window(VarInt::MAX);
        config.send_window(u64::MAX);
    }

    config.packet_threshold(quinn_config.packet_threshold);

    if let Some(congestion_window) = quinn_config.fixed_congestion_window {
        assert!(!quinn_config.use_ecn_based_reno);

        config.congestion_controller_factory(Arc::new(NoCCConfig {
            initial_window: congestion_window,
        }));
    } else {
        config.congestion_controller_factory(Arc::new(EcnCcFactory::new(NewRenoConfig::default())));
    }

    let mut ack_frequency_config = AckFrequencyConfig::default();
    ack_frequency_config
        .ack_eliciting_threshold(VarInt::from_u32(quinn_config.ack_eliciting_threshold));
    ack_frequency_config.max_ack_delay(Some(Duration::from_millis(quinn_config.max_ack_delay_ms)));

    // The docs say the recommended value for this is `packet_threshold - 1`
    ack_frequency_config.reordering_threshold(VarInt::from_u32(quinn_config.packet_threshold - 1));
    config.ack_frequency_config(Some(ack_frequency_config));

    config.initial_rtt(Duration::from_millis(quinn_config.initial_rtt_ms));

    config
}
