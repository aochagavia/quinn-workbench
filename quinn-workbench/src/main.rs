mod config;
mod quinn_extensions;

use anyhow::{anyhow, Context};
use clap::Parser;
use config::cli::CliOpt;
use config::json::{JsonConfig, QuinnJsonConfig};
use fastrand::Rng;
use in_memory_network::{InMemoryNetwork, NetworkConfig, PcapExporter, SERVER_ADDR};
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
    let json_config = load_json_config(&opt.config)?;

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
        let result = rt.block_on(run(&opt, json_config, pcap_exporter.clone()));

        // Always save export, regardless of success / failure
        pcap_exporter.save("capture.pcap".as_ref());

        if result.is_err() {
            eprintln!("Error after {:.2}s", start.elapsed().as_secs_f64());
        }

        result
    }
}

fn load_json_config(path: &Path) -> anyhow::Result<JsonConfig> {
    let file = File::open(path).context("unable to open config JSON file for loading")?;
    let parsed = serde_json::from_reader(file).context("error parsing JSON config")?;
    Ok(parsed)
}

fn find_hangs(opt: CliOpt) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut rng = Rng::new();
    loop {
        let mut opt = opt.clone();
        opt.quinn_rng_seed = rng.u64(..);
        opt.simulated_network_rng_seed = rng.u64(..);
        let json_config = load_json_config(&opt.config)?;

        println!("---\n---New run\n---");
        let pcap_exporter = Arc::new(PcapExporter::new());

        let pcap_exporter_clone = pcap_exporter.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .expect("failed to initialize tokio");

            rt.block_on(run(&opt, json_config, pcap_exporter))
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
    config: JsonConfig,
    pcap_exporter: Arc<PcapExporter>,
) -> anyhow::Result<()> {
    let network_config = config.network;
    let quinn_config = config.quinn.as_ref();

    let simulated_link_delay = Duration::from_millis(network_config.delay_ms);
    let extra_link_delay = Duration::from_millis(network_config.extra_delay_ms);

    println!("--- Params ---");
    let (quinn_rng_seed, simulated_network_rng_seed) = if options.non_deterministic {
        let mut rng = Rng::new();
        (rng.u64(..), rng.u64(..))
    } else {
        (options.quinn_rng_seed, options.simulated_network_rng_seed)
    };
    println!("* Quinn seed: {}", quinn_rng_seed);
    println!("* Network seed: {}", simulated_network_rng_seed);
    println!("* Transport config path: {}", options.config.display());
    println!(
        "* Delay: {:.2}s ({:.2}s RTT)",
        simulated_link_delay.as_secs_f64(),
        simulated_link_delay.as_secs_f64() * 2.0
    );
    println!(
        "* Extra delay ({:.2}% chance): {:.2}s",
        network_config.extra_delay_ratio * 100.0,
        extra_link_delay.as_secs_f64(),
    );
    println!(
        "* Packet loss ratio: {:.2}%",
        network_config.packet_loss_ratio * 100.0
    );
    println!(
        "* Packet duplication ratio: {:.2}%",
        network_config.packet_duplication_ratio * 100.0
    );
    println!(
        "* ECN ratio: {:.2}%",
        network_config.congestion_event_ratio * 100.0
    );

    let mut quinn_rng = Rng::with_seed(quinn_rng_seed);
    let start = Instant::now();

    // Certificates
    let server_name = "server-name";
    let cert = rcgen::generate_simple_self_signed(vec![server_name.into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    // Network
    let network = Arc::new(InMemoryNetwork::initialize(
        NetworkConfig {
            congestion_event_ratio: network_config.congestion_event_ratio,
            packet_loss_ratio: network_config.packet_loss_ratio,
            packet_duplication_ratio: network_config.packet_duplication_ratio,
            link_capacity: network_config.bandwidth,
            link_delay: simulated_link_delay,
            link_extra_delay: extra_link_delay,
            link_extra_delay_ratio: network_config.extra_delay_ratio,
        },
        pcap_exporter.clone(),
        Rng::with_seed(simulated_network_rng_seed),
        start,
    ));

    // Let a server listen in the background
    let server = server_endpoint(
        cert.clone(),
        key.into(),
        network.clone(),
        quinn_config,
        &mut quinn_rng,
    )?;
    let server_task = tokio::spawn(server_listen(server, options.response_size));

    // Make repeated requests
    println!("--- Requests ---");
    let client = client_endpoint(cert, network.clone(), quinn_config, &mut quinn_rng)?;
    println!("0.00s CONNECT");
    let connection = client.connect(SERVER_ADDR, server_name)?.await?;

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

    let rtt_sec = simulated_link_delay.as_secs_f64() * 2.0;
    println!("--- Stats ---");
    println!(
        "* Time from start to connection closed: {:.2}s ({:.2} RTT)",
        total_time_sec,
        total_time_sec / rtt_sec,
    );

    let stats = network.stats();
    for (name, stats) in [("Client", stats.client), ("Server", stats.server)] {
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
    network: Arc<InMemoryNetwork>,
    quinn_config: Option<&QuinnJsonConfig>,
    quinn_rng: &mut Rng,
) -> anyhow::Result<Endpoint> {
    let mut seed = [0; 32];
    quinn_rng.fill(&mut seed);

    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
    server_config.transport = Arc::new(transport_config(quinn_config));
    Endpoint::new_with_abstract_socket(
        endpoint_config(seed),
        Some(server_config),
        Arc::new(network.server_socket()),
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create server endpoint")
}

fn client_endpoint(
    server_cert: CertificateDer<'_>,
    network: Arc<InMemoryNetwork>,
    quinn_config: Option<&QuinnJsonConfig>,
    quinn_rng: &mut Rng,
) -> anyhow::Result<Endpoint> {
    let mut seed = [0; 32];
    quinn_rng.fill(&mut seed);

    let mut endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config(seed),
        None,
        Arc::new(network.client_socket()),
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
    quinn_config: Option<&QuinnJsonConfig>,
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

fn transport_config(quinn_config: Option<&QuinnJsonConfig>) -> TransportConfig {
    let mut config = TransportConfig::default();

    if let Some(quinn_config) = quinn_config {
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
            config.congestion_controller_factory(Arc::new(EcnCcFactory::new(
                NewRenoConfig::default(),
            )));
        }

        let mut ack_frequency_config = AckFrequencyConfig::default();
        ack_frequency_config
            .ack_eliciting_threshold(VarInt::from_u32(quinn_config.ack_eliciting_threshold));
        ack_frequency_config
            .max_ack_delay(Some(Duration::from_millis(quinn_config.max_ack_delay_ms)));

        // The docs say the recommended value for this is `packet_threshold - 1`
        ack_frequency_config
            .reordering_threshold(VarInt::from_u32(quinn_config.packet_threshold - 1));
        config.ack_frequency_config(Some(ack_frequency_config));

        config.initial_rtt(Duration::from_millis(quinn_config.initial_rtt_ms));
    }

    config
}
