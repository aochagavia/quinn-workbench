use crate::network::inbound_queue::InboundQueue;
use crate::network::quinn_interop::InMemoryUdpPoller;
use crate::network::InMemoryNetwork;
use crate::stats_tracker::NetworkStatsTracker;
use crate::{InTransitData, NetworkConfig, OwnedTransmit};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::fmt::{Debug, Formatter};
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::time::Instant;

pub struct InMemorySocketHandle {
    pub network: Arc<InMemoryNetwork>,
    pub addr: SocketAddr,
}

impl Debug for InMemorySocketHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "in memory socket ({})", self.addr)
    }
}

impl AsyncUdpSocket for InMemorySocketHandle {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(InMemoryUdpPoller)
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        // We don't have code to handle GSO, so let's ensure transmits are always a single UDP
        // packet
        assert!(transmit.segment_size.is_none());

        self.network.send(
            Instant::now(),
            self.addr,
            OwnedTransmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents.to_vec(),
                segment_size: transmit.segment_size,
            },
        );

        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let socket = self.network.socket(self.addr);
        let mut inbound = socket.inbound.lock().unwrap();

        let max_transmits = meta.len();
        let mut received = 0;

        let out = meta.iter_mut().zip(bufs);
        for (in_transit, (meta, buf)) in inbound.receive(max_transmits).zip(out) {
            received += 1;
            let transmit = in_transit.transmit;

            // Meta
            meta.addr = in_transit.source_addr;
            meta.ecn = transmit.ecn;
            meta.dst_ip = Some(transmit.destination.ip());
            meta.len = transmit.contents.len();
            meta.stride = transmit.segment_size.unwrap_or(meta.len);

            // Buffer
            buf[..transmit.contents.len()].copy_from_slice(&transmit.contents);
        }

        if received == 0 {
            if inbound.is_empty() {
                // Store the waker so we can be notified of new transmits
                let mut waker = socket.waker.lock().unwrap();
                if waker.is_none() {
                    *waker = Some(cx.waker().clone())
                }
            } else {
                // Wake up next time we can read
                let next_read = inbound.time_of_next_receive();
                let waker = cx.waker().clone();
                tokio::task::spawn(async move {
                    tokio::time::sleep_until(next_read).await;
                    waker.wake();
                });
            }

            Poll::Pending
        } else {
            Poll::Ready(Ok(received))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

#[derive(Clone)]
pub struct InMemorySocket {
    pub(in crate::network) addr: SocketAddr,
    pub(in crate::network) name: Arc<str>,
    pub(in crate::network) inbound: Arc<Mutex<InboundQueue>>,
    pub(in crate::network) waker: Arc<Mutex<Option<Waker>>>,
}

impl InMemorySocket {
    pub(crate) fn new(
        addr: SocketAddr,
        name: Arc<str>,
        config: &NetworkConfig,
        stats_tracker: NetworkStatsTracker,
        start: Instant,
    ) -> InMemorySocket {
        InMemorySocket {
            addr,
            name,
            inbound: Arc::new(Mutex::new(InboundQueue::new(
                config.link_delay,
                config.link_capacity,
                stats_tracker,
                start,
            ))),
            waker: Arc::new(Mutex::new(None)),
        }
    }

    pub fn has_enough_capacity(&self, data: &InTransitData, duplicate: bool) -> bool {
        self.inbound
            .lock()
            .unwrap()
            .has_enough_capacity(data, duplicate)
    }

    pub fn enqueue_send(&self, data: InTransitData, metadata_index: usize, extra_delay: Duration) {
        self.inbound
            .lock()
            .unwrap()
            .send(data, metadata_index, extra_delay);
    }
}
