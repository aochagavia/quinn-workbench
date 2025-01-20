use crate::config::quinn::QuinnJsonConfig;
use anyhow::Context;
use fastrand::Rng;
use in_memory_network::network::node::HostHandle;
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;

// A server that concurrently handles connections and their streams. Each stream is expected to make
// a "request" in the form `GET /index.html`.
pub fn server_listen(
    endpoint: Endpoint,
    response_payload_size: usize,
) -> UnboundedReceiver<JoinHandle<anyhow::Result<()>>> {
    let (connection_result_tx, connection_result_rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        let response: Vec<_> = "Lorem ipsum "
            .bytes()
            .cycle()
            .take(response_payload_size)
            .collect();
        let response = Arc::new(response);

        while let Some(incoming) = endpoint.accept().await {
            let response = response.clone();
            let task = tokio::spawn(async move {
                let conn = incoming.await?;

                let mut stream_tasks = Vec::new();
                while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
                    let response = response.clone();
                    let stream_task = tokio::spawn(async move {
                        // Read the request
                        let request = rx.read_to_end(usize::MAX).await?;
                        assert_eq!(request, b"GET /index.html");

                        // Respond
                        tx.write_all(&response).await?;
                        tx.finish()?;
                        tx.stopped().await?;

                        Result::<_, anyhow::Error>::Ok(())
                    });

                    stream_tasks.push(stream_task);
                }

                for task in stream_tasks {
                    task.await
                        .context("server stream task crashed")?
                        .context("server stream task errored")?;
                }

                Result::<_, anyhow::Error>::Ok(())
            });

            // Notify observers that we are done handling the connection
            connection_result_tx.send(task).unwrap();
        }
    });

    connection_result_rx
}

pub fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    server_host: HostHandle,
    quinn_config: &QuinnJsonConfig,
    quinn_rng: &mut Rng,
) -> anyhow::Result<Endpoint> {
    let mut seed = [0; 32];
    quinn_rng.fill(&mut seed);

    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
    server_config.transport = Arc::new(crate::transport_config(quinn_config));
    Endpoint::new_with_abstract_socket(
        crate::endpoint_config(seed),
        Some(server_config),
        Arc::new(server_host),
        quinn::default_runtime().unwrap(),
    )
    .context("failed to create server endpoint")
}
