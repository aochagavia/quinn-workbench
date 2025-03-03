mod client;
mod config;
mod quinn_extensions;
mod server;
mod simulation;

use crate::config::SimulationConfig;
use crate::simulation::Simulation;
use anyhow::Context;
use clap::Parser;
use config::cli::CliOpt;
use config::quinn::QuinnJsonConfig;
use in_memory_network::pcap_exporter::PcapExporter;
use quinn::{EndpointConfig, TransportConfig, VarInt};
use quinn_extensions::ecn_cc::EcnCcFactory;
use quinn_extensions::no_cc::NoCCConfig;
use quinn_proto::AckFrequencyConfig;
use quinn_proto::congestion::NewRenoConfig;
use serde::de::DeserializeOwned;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::Subscriber;

fn main() -> anyhow::Result<()> {
    Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_ansi(false)
        .without_time()
        .init();

    // Safety: we are fully single-threaded
    unsafe { std::env::set_var("SSLKEYLOGFILE", "keylog.key") };
    let opt = CliOpt::parse();
    let simulation_config = load_simulation_config(&opt)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("failed to initialize tokio");

    let pcap_file =
        File::create("capture.pcap").context("failed to open capture.pcap for writing")?;
    let pcap_exporter = Arc::new(PcapExporter::new(pcap_file));
    let result = rt.block_on(run_and_report_stats(
        &opt,
        simulation_config,
        pcap_exporter.clone(),
    ));

    // Ensure the pcap export is written to disk
    pcap_exporter.flush()?;
    result
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

async fn run_and_report_stats(
    options: &CliOpt,
    config: SimulationConfig,
    pcap_exporter: Arc<PcapExporter>,
) -> anyhow::Result<()> {
    let mut simulation = Simulation::new();
    let result = simulation.run(options, config, pcap_exporter.clone()).await;

    let Some((tracer, network)) = simulation.tracer_and_network else {
        eprintln!("Error...");
        return result;
    };

    println!("--- Replay log ---");
    let replay_log_path = "replay-log.json";
    let json_steps = serde_json::to_vec_pretty(&tracer.stepper().steps()).unwrap();
    fs::write(replay_log_path, json_steps).context("failed to store replay log")?;
    println!("* Replay log available at {replay_log_path}");

    println!("--- Stats ---");
    let verified_simulation = tracer
        .verifier()
        .context("failed to create simulation verifier")?
        .verify()
        .context("failed to verify simulation")?;
    let server_host = network.host(options.server_ip_address);
    let client_host = network.host(options.client_ip_address);
    for node in ["client", "server"] {
        let name = match node {
            "server" => &network.host(server_host.addr.ip()).id,
            "client" => &network.host(client_host.addr.ip()).id,
            _ => unreachable!(),
        };
        let stats = &verified_simulation.stats_by_node[name];

        println!("* {name} ({node})");

        println!(
            "  * Sent packets: {} ({} bytes)",
            stats.sent.packets, stats.sent.bytes,
        );
        println!(
            "    | {} packets duplicated in transit ({} bytes)",
            stats.duplicates.packets, stats.duplicates.bytes
        );
        println!(
            "    | {} packets marked with the CE ECN codepoint in transit ({} bytes)",
            stats.congestion_experienced.packets, stats.congestion_experienced.bytes
        );
        println!(
            "    | {} packets dropped in transit ({} bytes)",
            stats.dropped_injected.packets + stats.dropped_buffer_full.packets,
            stats.dropped_injected.bytes + stats.dropped_buffer_full.bytes
        );
        println!(
            "  * Received packets: {} ({} bytes)",
            stats.received.packets, stats.received.bytes
        );
        println!(
            "    | {} packets received out of order ({} bytes)",
            stats.received_out_of_order.packets, stats.received_out_of_order.bytes
        );
    }

    println!("--- Max buffer usage per node ---");
    let mut buffer_usage: Vec<_> = verified_simulation.stats_by_node.iter().collect();
    buffer_usage.sort_unstable_by(|t1, t2| {
        t1.1.max_buffer_usage
            .cmp(&t2.1.max_buffer_usage)
            .then(t2.0.cmp(t1.0))
    });
    for (node_id, stats) in buffer_usage.into_iter().rev() {
        println!(
            "* {node_id}: {} bytes ({} packets dropped due to buffer being full)",
            stats.max_buffer_usage, stats.dropped_buffer_full.packets
        );
    }

    if result.is_err() {
        eprintln!("Error...");
    }

    result
}

fn endpoint_config(rng_seed: [u8; 32]) -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.rng_seed(Some(rng_seed));

    config
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
