use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
pub struct CliOpt {
    /// The IP address of the node used as a client
    #[arg(long)]
    pub client_ip_address: IpAddr,

    /// The IP address of the node used as a server
    #[arg(long)]
    pub server_ip_address: IpAddr,

    /// The number of requests that should be made
    #[arg(long, default_value_t = 10)]
    pub requests: u32,

    /// The number of concurrent connections used when making the requests
    #[arg(long, default_value_t = 1)]
    pub concurrent_connections: u8,

    /// The number of concurrent streams per connection used when making the requests
    #[arg(long, default_value_t = 1)]
    pub concurrent_streams_per_connection: u32,

    /// The size of each response, in bytes
    #[arg(long, default_value_t = 1024)]
    pub response_size: usize,

    /// Whether the run should be non-deterministic, i.e. using a non-constant seed for the random
    /// number generators
    #[arg(long)]
    pub non_deterministic: bool,

    /// Quinn's random seed, which you can control to generate deterministic results (Quinn uses
    /// randomness internally)
    #[arg(long, default_value_t = 0)]
    pub quinn_rng_seed: u64,

    /// The random seed used for the simulated network (governing packet loss, duplication and
    /// reordering)
    #[arg(long, default_value_t = 42)]
    pub simulated_network_rng_seed: u64,

    /// Ignore any provided random seeds and try many of them in succession, attempting to find a
    /// combination that causes the application to hang.
    ///
    /// This is mostly useful for debugging, so you should probably ignore it.
    #[arg(long)]
    pub find_hangs: bool,

    /// Path to the JSON file containing the desired quinn config
    #[arg(long)]
    pub quinn_config: PathBuf,

    /// Path to the JSON file containing the network graph
    #[arg(long)]
    pub network_graph: PathBuf,

    /// Path to the JSON file containing the network events
    #[arg(long)]
    pub network_events: PathBuf,
}
