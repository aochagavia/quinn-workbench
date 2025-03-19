use crate::config::NetworkConfig;
use crate::config::cli::{CliOpt, ThroughputOpt};
use anyhow::Context as _;
use fastrand::Rng;
use futures::{FutureExt, select_biased};
use in_memory_network::async_rt;
use in_memory_network::async_rt::cancellation::CancellationToken;
use in_memory_network::async_rt::instant::Instant;
use in_memory_network::network::InMemoryNetwork;
use in_memory_network::network::event::NetworkEvents;
use in_memory_network::network::spec::NetworkSpec;
use in_memory_network::pcap_exporter::PcapExporter;
use in_memory_network::quinn_interop::BufsAndMeta;
use in_memory_network::tracing::tracer::SimulationStepTracer;
use quinn::AsyncUdpSocket;
use quinn::udp::Transmit;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, fs};

pub async fn run(
    cli_opt: &CliOpt,
    ping_opt: &ThroughputOpt,
    network_config: NetworkConfig,
) -> anyhow::Result<()> {
    let simulation_start = Instant::now();

    // Network
    let network_check_pcap_exporter = Arc::new(PcapExporter::new(std::io::empty()));
    let network_spec: NetworkSpec = network_config.network_graph.into();
    let network_events = NetworkEvents::new(
        network_config
            .network_events
            .clone()
            .into_iter()
            .map(|e| e.into())
            .collect(),
        &network_spec.links,
    );
    let tracer = Arc::new(SimulationStepTracer::new(
        network_check_pcap_exporter,
        network_spec.clone(),
    ));
    let network = InMemoryNetwork::initialize(
        network_spec.clone(),
        network_events,
        tracer.clone(),
        Rng::with_seed(cli_opt.network_rng_seed),
        simulation_start,
    )?;

    println!("--- Network ---");
    println!("* Initial link statuses (derived from events):");
    for link_spec in &network_spec.links {
        let status = network.get_link_status(&link_spec.id);
        println!("  * {}: {}", link_spec.id, status);
    }

    println!("--- Throughput test ---");
    let duration = Duration::from_millis(ping_opt.duration_ms);

    let server_ip = cli_opt.server_ip_address;
    let server_node = network.host(server_ip);
    let server_socket = Arc::pin(network.udp_socket_for_node(server_node.clone()));

    let client_ip = cli_opt.client_ip_address;
    let client_node = network.host(client_ip);
    let client_socket = Arc::pin(network.udp_socket_for_node(client_node.clone()));

    let (cancellation_token, cancellation_signal) = CancellationToken::new();

    // Destination
    let cancellation_token_cp = cancellation_token.clone();
    let server_task = async_rt::spawn(async move {
        let mut arrived_packets: Vec<(Duration, usize)> = Vec::new();
        let mut bufs_and_meta = BufsAndMeta::new(1200, 20);

        loop {
            let packets = select_biased! {
                packets = server_socket.receive(&mut bufs_and_meta).fuse() => packets.unwrap(),
                _ = cancellation_token_cp.cancelled().fuse() => { break },
            };

            // Receive next transmits
            for packet in packets {
                assert_eq!(packet.source_addr.ip(), client_ip);
                arrived_packets.push((simulation_start.elapsed(), packet.payload.len()));
            }
        }

        arrived_packets
    });

    // Sender
    let max_link_bps = network_spec
        .links
        .iter()
        .map(|l| l.bandwidth_bps)
        .max()
        .unwrap();
    let send_bps = ping_opt.send_bps.unwrap_or(2 * max_link_bps);
    let send_bytes_per_second = send_bps / 8;
    let send_interval_ms = 50;
    let send_bytes_per_interval = send_bytes_per_second / (1000 / send_interval_ms);

    println!("Sending at {send_bps} bps");

    let client_socket_cp = client_socket.clone();
    async_rt::spawn(async move {
        let max_bytes_per_send = 1200;
        let payload = vec![0; max_bytes_per_send];
        loop {
            if cancellation_token.is_cancelled() {
                break;
            }

            // Each iteration is a new send interval
            let mut bytes_left = send_bytes_per_interval as usize;
            while bytes_left > 0 {
                let next_packet_size_bytes = cmp::min(max_bytes_per_send, bytes_left);
                bytes_left -= next_packet_size_bytes;

                // Send packet
                client_socket_cp
                    .try_send(&Transmit {
                        destination: SocketAddr::new(server_ip, 8080),
                        ecn: None,
                        contents: &payload[..next_packet_size_bytes],
                        segment_size: None,
                        src_ip: None,
                    })
                    .unwrap();
            }

            // Sleep before sending the next packet
            async_rt::sleep(Duration::from_millis(send_interval_ms)).await;
        }
    });

    // Wait till done
    async_rt::sleep(duration).await;
    println!("{:.2}s Done", simulation_start.elapsed().as_secs_f64());

    println!("--- Replay log ---");
    let replay_log_path = "replay-log.json";
    let json_steps = serde_json::to_vec_pretty(&tracer.stepper().steps()).unwrap();
    fs::write(replay_log_path, json_steps).context("failed to store replay log")?;
    println!("* Replay log available at {replay_log_path}");

    println!("--- Throughput ---");
    cancellation_signal.cancel();
    let packets = server_task.await.unwrap();

    let mut window: VecDeque<(Duration, usize)> = VecDeque::new();
    let mut bytes_in_window = 0;
    let window_duration = Duration::from_millis(100);

    for (arrival_time, bytes) in packets {
        // Remove throughput that's no longer in the window
        while window
            .front()
            .is_some_and(|first| first.0 + window_duration < arrival_time)
        {
            let (_, bytes) = window.pop_front().unwrap();
            bytes_in_window -= bytes;
        }

        // Add this packet to the window
        window.push_back((arrival_time, bytes));
        bytes_in_window += bytes;

        // Smoothed throughput
        println!(
            "{:06.3}s - {} bps",
            arrival_time.as_secs_f64(),
            bytes_in_window * 8 * 10
        );
    }

    println!("--- Node stats ---");
    let verified_simulation = tracer
        .verifier()
        .context("failed to create simulation verifier")?
        .verify()
        .context("failed to verify simulation")?;
    let server_node = network.host(cli_opt.server_ip_address);
    let client_node = network.host(cli_opt.client_ip_address);
    for node in ["client", "server"] {
        let name = match node {
            "server" => server_node.id().clone(),
            "client" => client_node.id().clone(),
            _ => unreachable!(),
        };
        let stats = &verified_simulation.stats.stats_by_node[&name];

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
    let mut buffer_usage: Vec<_> = verified_simulation.stats.stats_by_node.iter().collect();
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

    if !verified_simulation.stats.stats_by_link.is_empty() {
        println!("--- Link stats ---");
    }
    let mut link_stats: Vec<_> = verified_simulation.stats.stats_by_link.iter().collect();
    link_stats.sort_unstable_by_key(|(id, _)| *id);
    for (link_id, stats) in link_stats {
        println!(
            "* {link_id}: {} packets lost in transit ({} bytes)",
            stats.dropped_in_transit.packets, stats.dropped_in_transit.bytes
        );
    }

    const DISPLAY_MAX_ERRORS: usize = 10;
    if !verified_simulation.non_fatal_errors.is_empty() {
        print!("--- Errors ");
        if verified_simulation.non_fatal_errors.len() > DISPLAY_MAX_ERRORS {
            print!(
                "(showing {DISPLAY_MAX_ERRORS} of {})",
                verified_simulation.non_fatal_errors.len()
            );
        }

        println!(" ---");
    }
    for error in verified_simulation
        .non_fatal_errors
        .into_iter()
        .take(DISPLAY_MAX_ERRORS)
    {
        println!("* {error}");
    }

    Ok(())
}
