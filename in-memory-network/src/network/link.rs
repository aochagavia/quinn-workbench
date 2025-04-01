use crate::InTransitData;
use crate::network::event::UpdateLinkStatus;
use crate::network::inbound_queue::{InboundQueue, NextPacketDelivery};
use crate::network::node::Node;
use crate::network::spec::NetworkLinkSpec;
use crate::tracing::tracer::SimulationStepTracer;
use futures_util::future::Shared;
use futures_util::{FutureExt, select_biased};
use parking_lot::Mutex;
use std::mem;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub struct NetworkLink {
    pub id: Arc<str>,
    pub target: IpAddr,
    tracer: Arc<SimulationStepTracer>,
    in_transit: Arc<Mutex<InboundQueue>>,
    pacer: Mutex<PacketPacer>,
    sleep_until_ready_to_send_semaphore: Arc<Semaphore>,
    status: LinkStatus,
    last_down: Option<Instant>,
    delay: Duration,
    pub(crate) bandwidth_bps: usize,
    pub(crate) notify_packet_sent: Arc<Notify>,
    pub(crate) congestion_event_ratio: f64,
    pub(crate) extra_delay: Duration,
    pub(crate) extra_delay_ratio: f64,
}

pub(crate) enum LinkStatus {
    Up,
    Down {
        up_tx: tokio::sync::oneshot::Sender<()>,
        up_rx: Shared<tokio::sync::oneshot::Receiver<()>>,
    },
}

impl LinkStatus {
    pub(crate) fn new_down() -> Self {
        let (up_tx, up_rx) = tokio::sync::oneshot::channel();
        LinkStatus::Down {
            up_tx,
            up_rx: up_rx.shared(),
        }
    }

    fn is_down(&self) -> bool {
        match self {
            LinkStatus::Up => false,
            LinkStatus::Down { .. } => true,
        }
    }

    fn notifier_for_link_up(&self) -> Option<Shared<tokio::sync::oneshot::Receiver<()>>> {
        match self {
            LinkStatus::Up => None,
            LinkStatus::Down { up_rx, .. } => Some(up_rx.clone()),
        }
    }
}

impl NetworkLink {
    pub(crate) fn new(l: NetworkLinkSpec, tracer: Arc<SimulationStepTracer>) -> Self {
        Self {
            id: l.id,
            status: LinkStatus::Up,
            last_down: None,
            tracer,
            target: l.target,
            in_transit: Arc::new(Mutex::new(InboundQueue::new())),
            pacer: Mutex::new(PacketPacer::new(l.bandwidth_bps)),
            sleep_until_ready_to_send_semaphore: Arc::new(Semaphore::new(1)),
            delay: l.delay,
            bandwidth_bps: l.bandwidth_bps as usize,
            notify_packet_sent: Arc::new(Notify::new()),
            congestion_event_ratio: l.congestion_event_ratio,
            extra_delay: l.extra_delay,
            extra_delay_ratio: l.extra_delay_ratio,
        }
    }

    pub(crate) fn was_down_after(&self, instant: Instant) -> bool {
        matches!(self.last_down, Some(down) if down > instant)
    }

    pub(crate) fn status_str(&self) -> &'static str {
        match self.status {
            LinkStatus::Up => "UP",
            LinkStatus::Down { .. } => "DOWN",
        }
    }

    pub(crate) fn update_status(&mut self, update: UpdateLinkStatus) {
        let status = mem::replace(&mut self.status, LinkStatus::Up);
        match (status, update) {
            (status @ LinkStatus::Down { .. }, UpdateLinkStatus::Down)
            | (status @ LinkStatus::Up, UpdateLinkStatus::Up) => {
                // No update, restore original status
                self.status = status;
            }

            (LinkStatus::Up, UpdateLinkStatus::Down) => {
                // Set status to down
                self.status = LinkStatus::new_down();
                self.last_down = Some(Instant::now());

                // Nothing else to do here, because:
                // 1. already sent packets will be dropped by the forwarding code if they are still in flight
                // 2. packets in the router's outbound buffer will stay there until the link is back up
                // 3. attempting to send new packets will cause them to land in the buffer (if there's space)
            }

            (LinkStatus::Down { up_tx, .. }, UpdateLinkStatus::Up) => {
                // Set status to up and notify anyone waiting that the link is back up
                self.status = LinkStatus::Up;
                up_tx.send(()).ok();
            }
        }
    }

    pub(crate) fn send(&mut self, current_node: &Node, data: InTransitData, extra_delay: Duration) {
        // Sanity checks
        assert!(self.pacer.lock().can_send(Instant::now()));
        assert!(matches!(self.status, LinkStatus::Up));

        // Record
        self.tracer
            .track_packet_in_transit(current_node, self, &data);

        // Send
        self.pacer
            .lock()
            .track_send(Instant::now(), data.transmit.packet_size());
        self.in_transit.lock().send(data, self.delay + extra_delay);
    }

    pub(crate) fn sleep_until_ready_to_send(
        this: Arc<Mutex<Self>>,
        cancellation_token: CancellationToken,
    ) -> tokio::sync::oneshot::Receiver<Arc<Mutex<Self>>> {
        assert!(
            !this.lock().has_bandwidth_available(),
            "we should only wait when no bandwidth is available"
        );

        let (tx, rx) = tokio::sync::oneshot::channel();
        let semaphore = this.lock().sleep_until_ready_to_send_semaphore.clone();
        tokio::spawn(async move {
            // Only one task at a time may continue after this line (they will wait in order,
            // because the semaphore is fair)
            let _permit = semaphore.acquire().await.unwrap();

            let duration_until_enough_bandwidth = this
                .lock()
                .pacer
                .lock()
                .duration_until_can_send(Instant::now());

            // Sleep until enough bandwidth or until cancelled, whichever comes first
            select_biased! {
                _ = cancellation_token.cancelled().fuse() => {}
                _ = tokio::time::sleep(duration_until_enough_bandwidth).fuse() => {}
            }

            // Concurrency: keep the one-liner to shorten the lock on `this`
            let notifier_for_link_up = this.lock().status.notifier_for_link_up();
            if let Some(notifier_for_link_up) = notifier_for_link_up {
                // The link is currently down, so we need to wait for it to be back up
                notifier_for_link_up.await.ok();
            }

            let notify_packet_sent = this.lock().notify_packet_sent.clone();

            // Let observers know that the link is ready to send
            tx.send(this).ok();

            // Only end the task after the packet has been sent. Otherwise, packets that are waiting
            // will think they can be sent too because "there is available bandwidth".
            notify_packet_sent.notified().await
        });

        rx
    }

    pub(crate) fn has_bandwidth_available(&mut self) -> bool {
        let packets_are_waiting_for_bandwidth =
            self.sleep_until_ready_to_send_semaphore.available_permits() == 0;
        if packets_are_waiting_for_bandwidth || self.status.is_down() {
            return false;
        }

        self.pacer.lock().can_send(Instant::now())
    }

    pub(crate) fn next_delivered_packets(&mut self, max_transmits: usize) -> NextPacketDelivery {
        NextPacketDelivery::new(self.in_transit.clone(), max_transmits)
    }
}

// Ensures that only a single packet at a time is being sent
struct PacketPacer {
    bandwidth_bps: f64,
    last_send: Option<SendingPacket>,
}

#[derive(Clone)]
struct SendingPacket {
    send_done: Instant,
}

impl PacketPacer {
    fn new(bandwidth_bps: u64) -> Self {
        Self {
            bandwidth_bps: bandwidth_bps as f64,
            last_send: None,
        }
    }

    fn can_send(&mut self, now: Instant) -> bool {
        let Some(packet) = self.last_send.clone() else {
            // No packet has been sent yet
            return true;
        };

        packet.send_done <= now
    }

    fn duration_until_can_send(&self, now: Instant) -> Duration {
        match &self.last_send {
            None => Duration::default(),
            Some(p) => p.send_done.saturating_duration_since(now),
        }
    }

    fn track_send(&mut self, now: Instant, packet_size_bytes: usize) {
        let packet_size_bits = packet_size_bytes.saturating_mul(8);
        let send_duration_ms = packet_size_bits as f64 / self.bandwidth_bps * 1_000.0;

        self.last_send = Some(SendingPacket {
            send_done: now + Duration::from_millis(send_duration_ms.ceil() as u64),
        });
    }
}
