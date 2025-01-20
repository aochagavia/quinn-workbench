use crate::config::cli::CliOpt;
use crate::config::SimulationConfig;
use crate::{client, server};
use anyhow::{bail, Context};
use fastrand::Rng;
use in_memory_network::network::event::NetworkEvents;
use in_memory_network::network::spec::NetworkSpec;
use in_memory_network::network::InMemoryNetwork;
use in_memory_network::pcap_exporter::PcapExporter;
use in_memory_network::tracing::tracer::SimulationStepTracer;
use parking_lot::Mutex;
use quinn_proto::VarInt;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;

#[derive(Default)]
pub struct Simulation {
    pub tracer_and_network: Option<(Arc<SimulationStepTracer>, Arc<InMemoryNetwork>)>,
}

impl Simulation {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(
        &mut self,
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
        let network_check_pcap_exporter = Arc::new(PcapExporter::new(std::io::empty()));
        let network_spec: NetworkSpec = config.network_graph.into();
        let network_events = NetworkEvents::new(
            config
                .network_events
                .clone()
                .into_iter()
                .map(|e| e.into())
                .collect(),
        );
        let network = InMemoryNetwork::initialize(
            network_spec.clone(),
            network_events,
            Arc::new(SimulationStepTracer::new(
                network_check_pcap_exporter,
                network_spec.clone(),
            )),
            Rng::with_seed(simulated_network_rng_seed),
            start,
        )?;

        println!("--- Network ---");
        println!("* Initial link statuses (derived from events):");
        for link_spec in &network_spec.links {
            let status = network.get_link_status(&link_spec.id);
            println!("  * {}: {}", link_spec.id, status);
        }
        println!("* Running connectivity check...");
        let (arrived1, arrived2) = network
            .assert_connectivity_between_hosts(options.server_ip_address, options.client_ip_address)
            .await?;
        println!(
            "* Connectivity check passed (packets arrived after {} ms and {} ms)",
            arrived1.as_millis(),
            arrived2.as_millis()
        );

        drop(network);

        let start = Instant::now();

        // Network
        let tracer = Arc::new(SimulationStepTracer::new(
            pcap_exporter,
            network_spec.clone(),
        ));
        let network = InMemoryNetwork::initialize(
            network_spec,
            NetworkEvents::new(
                config
                    .network_events
                    .into_iter()
                    .map(|e| e.into())
                    .collect(),
            ),
            tracer.clone(),
            Rng::with_seed(simulated_network_rng_seed),
            start,
        )?;
        self.tracer_and_network = Some((tracer.clone(), network.clone()));

        // Set up server certificate
        let server_name = "server-name";
        let cert = rcgen::generate_simple_self_signed(vec![server_name.into()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert = CertificateDer::from(cert.cert);

        // Let a server listen in the background
        let mut quinn_rng = Rng::with_seed(quinn_rng_seed);
        let server_host = network.host(options.server_ip_address);
        let server_addr = server_host.addr;
        let server = server::server_endpoint(
            cert.clone(),
            key.into(),
            network.host_handle(server_host.clone()),
            &config.quinn,
            &mut quinn_rng,
        )?;
        let mut server_handled_connections =
            server::server_listen(server.clone(), options.response_size);

        // Create the client endpoint
        let client_host = network.host(options.client_ip_address);
        let client = client::client_endpoint(
            cert,
            network.host_handle(client_host.clone()),
            &config.quinn,
            &mut quinn_rng,
        )?;

        let max_connections = b'Z' - b'A';
        if options.concurrent_connections > max_connections {
            bail!("The maximum number of concurrent connections is {max_connections}, but {} were configured", options.concurrent_connections);
        }

        // Make requests, potentially using concurrent connections
        println!("--- Requests ---");
        let connections_semaphore =
            Arc::new(Semaphore::new(options.concurrent_connections as usize));
        let mut connection_tasks = Vec::new();
        let requests_left = Arc::new(Mutex::new(options.requests));
        for i in 0..options.concurrent_connections {
            let client = client.clone();
            let server_name = server_name.to_string();
            let requests_left = requests_left.clone();
            let connection_name = (i + b'A') as char;
            let connections_semaphore = connections_semaphore.clone();
            let concurrent_streams = options.concurrent_streams_per_connection;
            connection_tasks.push(tokio::spawn(async move {
                let _permit = connections_semaphore.acquire().await.unwrap();
                client::run_connection(
                    client,
                    server_name,
                    server_addr,
                    connection_name.to_string(),
                    requests_left,
                    concurrent_streams,
                    start,
                )
                .await
            }));

            // Wait 1 ms before starting the next connection
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        drop(client);

        // Wait for all connections to finish
        let total_connections = connection_tasks.len();
        for task in connection_tasks {
            task.await
                .context("client connection task crashed")?
                .context("client connection errored")?;
        }

        let total_time_sec = start.elapsed().as_secs_f64();
        println!("{:.2}s All connections closed", total_time_sec);

        // Cleanly shut down the server
        let mut handled_connections = 0;
        while let Some(conn_task_handle) = server_handled_connections.recv().await {
            conn_task_handle
                .await
                .context("server connection task crashed")?
                .context("server connection task errored")?;

            handled_connections += 1;
            if handled_connections >= total_connections {
                break;
            }
        }
        server.close(VarInt::from_u32(0), b"server shut down");

        Ok(())
    }
}
