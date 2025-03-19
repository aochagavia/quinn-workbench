use in_memory_network::network::InMemoryNetwork;
use in_memory_network::network::node::Node;
use in_memory_network::tracing::simulation_verifier::VerifiedSimulation;

pub fn print_max_buffer_usage_per_node(verified_simulation: &VerifiedSimulation) {
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
}

pub fn print_link_stats(verified_simulation: &VerifiedSimulation, network: &InMemoryNetwork) {
    if !verified_simulation.stats.stats_by_link.is_empty() {
        println!("--- Link stats ---");
    }
    let mut link_stats: Vec<_> = verified_simulation.stats.stats_by_link.iter().collect();
    link_stats.sort_unstable_by_key(|(id, _)| *id);
    for (link_id, stats) in link_stats {
        println!("* {link_id}:");
        println!(
            "|-> Lost in transit {} packets ({} bytes)",
            stats.dropped_in_transit.packets, stats.dropped_in_transit.bytes
        );

        let bandwidth_bps = network.get_link_bandwidth_bps(link_id);
        let usage_ratio = stats.max_used_bandwidth_bps as f64 / bandwidth_bps as f64 * 100.0;
        println!(
            "|-> Max used bandwidth (bps): {} ({usage_ratio:.2}% of the link's bandwidth)",
            stats.max_used_bandwidth_bps
        );
    }
}

pub fn print_node_stats(
    verified_simulation: &VerifiedSimulation,
    server_node: &Node,
    client_node: &Node,
) {
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
}
