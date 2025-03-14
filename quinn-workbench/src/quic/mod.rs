use crate::config::NetworkConfig;
use crate::config::cli::{CliOpt, QuicOpt};
use crate::config::quinn::QuinnJsonConfig;
use crate::quic::simulation::QuicSimulation;
use crate::quinn_extensions::ecn_cc::EcnCcFactory;
use crate::quinn_extensions::no_cc::NoCCConfig;
use anyhow::Context;
use in_memory_network::pcap_exporter::PcapExporter;
use quinn_proto::congestion::NewRenoConfig;
use quinn_proto::{AckFrequencyConfig, EndpointConfig, TransportConfig, VarInt};
use std::fs;
use std::sync::Arc;
use std::time::Duration;

mod client;
mod server;
pub mod simulation;

pub async fn run_and_report_stats(
    options: &CliOpt,
    quic_options: &QuicOpt,
    network_config: NetworkConfig,
    quinn_config: QuinnJsonConfig,
    pcap_exporter: Arc<PcapExporter>,
) -> anyhow::Result<()> {
    let mut simulation = QuicSimulation::new();
    let result = simulation
        .run(
            options,
            quic_options,
            network_config,
            quinn_config,
            pcap_exporter.clone(),
        )
        .await;

    let Some((tracer, network)) = simulation.tracer_and_network else {
        eprintln!("Error...");
        return result;
    };

    println!("--- Replay log ---");
    let replay_log_path = "replay-log.json";
    let json_steps = serde_json::to_vec_pretty(&tracer.stepper().steps()).unwrap();
    fs::write(replay_log_path, json_steps).context("failed to store replay log")?;
    println!("* Replay log available at {replay_log_path}");

    println!("--- Node stats ---");
    let verified_simulation = tracer
        .verifier()
        .context("failed to create simulation verifier")?
        .verify()
        .context("failed to verify simulation")?;
    let server_node = network.host(options.server_ip_address);
    let client_node = network.host(options.client_ip_address);
    for node in ["client", "server"] {
        let name = match node {
            "server" => server_node.id().clone(),
            "client" => client_node.id().clone(),
            _ => unreachable!(),
        };
        let stats = &verified_simulation.stats_by_node[&name];

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

    if !verified_simulation.stats_by_link.is_empty() {
        println!("--- Link stats ---");
    }
    let mut link_stats: Vec<_> = verified_simulation.stats_by_link.iter().collect();
    link_stats.sort_unstable_by_key(|(id, _)| *id);
    for (link_id, stats) in link_stats {
        println!(
            "* {link_id}: {} packets lost in transit ({} bytes)",
            stats.dropped_in_transit.packets, stats.dropped_in_transit.bytes
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
