mod config;
mod quic;
mod quinn_extensions;
mod udp;
mod util;

use crate::config::NetworkConfig;
use crate::config::cli::Command;
use crate::udp::{ping, throughput};
use anyhow::Context;
use clap::Parser;
use config::cli::CliOpt;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::path::Path;
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
    let network_config = load_network_config(&opt)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("failed to initialize tokio");

    match &opt.command {
        Command::Quic(quic_opt) => {
            let quinn = load_json(&quic_opt.quinn_config)?;
            let result = rt.block_on(quic::run_and_report_stats(
                &opt,
                quic_opt,
                network_config,
                quinn,
            ));

            result
        }
        Command::Ping(ping_opt) => rt.block_on(ping::run(&opt, ping_opt, network_config)),
        Command::Throughput(throughput_opt) => {
            rt.block_on(throughput::run(&opt, throughput_opt, network_config))
        }
    }
}

fn load_network_config(cli: &CliOpt) -> anyhow::Result<NetworkConfig> {
    let network_graph = load_json(&cli.network_graph)?;
    let network_events = load_json(&cli.network_events)?;

    Ok(NetworkConfig {
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
