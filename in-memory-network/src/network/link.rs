use crate::async_rt::JoinHandle;
use crate::async_rt::cancellation::CancellationToken;
use crate::async_rt::instant::Instant;
use crate::async_rt::notify::Notify;
use crate::network::event::UpdateLinkStatus;
use crate::network::inbound_queue::{InboundQueue, NextPacketDelivery};
use crate::network::node::Node;
use crate::network::spec::NetworkLinkSpec;
use crate::tracing::tracer::SimulationStepTracer;
use crate::transmit::{IPV4_OVERHEAD, UDP_OVERHEAD};
use crate::{InTransitData, async_rt};
use futures::future::Shared;
use futures::{FutureExt, select_biased};
use parking_lot::Mutex;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, mem};

pub struct NetworkLink {
    pub id: Arc<str>,
    pub target: IpAddr,
    tracer: Arc<SimulationStepTracer>,
    in_transit: Arc<Mutex<InboundQueue>>,
    rate_calculator: DataRateCalculator,
    packets_waiting_for_bandwidth_task: Option<JoinHandle<()>>,
    status: LinkStatus,
    last_down: Option<Instant>,
    delay: Duration,
    pub(crate) notify_packet_sent: Arc<Notify>,
    pub(crate) congestion_event_ratio: f64,
    pub(crate) extra_delay: Duration,
    pub(crate) extra_delay_ratio: f64,
}

pub(crate) enum LinkStatus {
    Up,
    Down {
        up_tx: futures::channel::oneshot::Sender<()>,
        up_rx: Shared<futures::channel::oneshot::Receiver<()>>,
    },
}

impl LinkStatus {
    pub(crate) fn new_down() -> Self {
        let (up_tx, up_rx) = futures::channel::oneshot::channel();
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

    fn notifier_for_link_up(&self) -> Option<Shared<futures::channel::oneshot::Receiver<()>>> {
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
            rate_calculator: DataRateCalculator::new(l.bandwidth_bps),
            packets_waiting_for_bandwidth_task: None,
            delay: l.delay,
            notify_packet_sent: Arc::new(Notify::new()),
            congestion_event_ratio: l.congestion_event_ratio,
            extra_delay: l.extra_delay,
            extra_delay_ratio: l.extra_delay_ratio,
        }
    }

    pub fn was_down_after(&self, instant: Instant) -> bool {
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
        assert!(
            self.rate_calculator
                .has_bandwidth_available(Instant::now(), data.transmit.packet_size())
        );
        assert!(matches!(self.status, LinkStatus::Up));

        // Record
        self.tracer.track_sent_in_pcap(&data, current_node);
        self.tracer
            .track_packet_in_transit(current_node, self, &data);

        // Send
        self.rate_calculator.track_send(data.transmit.packet_size());
        self.in_transit.lock().send(data, self.delay + extra_delay);
    }

    pub(crate) fn sleep_until_ready_to_send(
        this: Arc<Mutex<Self>>,
        data: &InTransitData,
        cancellation_token: CancellationToken,
    ) -> futures::channel::oneshot::Receiver<Arc<Mutex<Self>>> {
        assert!(
            !this.lock().has_bandwidth_available(data),
            "we should only wait when no bandwidth is available"
        );

        let (tx, rx) = futures::channel::oneshot::channel();
        let existing_task = this.lock().packets_waiting_for_bandwidth_task.take();
        let this_cp = this.clone();
        let data_len = data.transmit.packet_size();
        let new_task = async_rt::spawn(async move {
            if let Some(task) = existing_task {
                // Wait for the previous packets in the queue to be done
                let result = task.await;
                if let Err(e) = result {
                    println!("ERROR: `sleep_until_ready_to_send` task crashed. Message: {e}")
                }
            }

            let duration_until_enough_bandwidth = this
                .lock()
                .rate_calculator
                .duration_until_enough_bandwidth(data_len);

            // Sleep until enough bandwidth or until cancelled, whichever comes first
            select_biased! {
                _ = cancellation_token.cancelled().fuse() => {}
                _ = async_rt::sleep(duration_until_enough_bandwidth).fuse() => {}
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

        this_cp.lock().packets_waiting_for_bandwidth_task = Some(new_task);
        rx
    }

    pub(crate) fn has_bandwidth_available(&mut self, data: &InTransitData) -> bool {
        let at_least_one_packet_waiting_for_bandwidth =
            self.packets_waiting_for_bandwidth_task.is_some();
        if at_least_one_packet_waiting_for_bandwidth || self.status.is_down() {
            return false;
        }

        self.rate_calculator
            .has_bandwidth_available(Instant::now(), data.transmit.packet_size())
    }

    pub(crate) fn next_delivered_packets(&mut self, max_transmits: usize) -> NextPacketDelivery {
        NextPacketDelivery::new(self.in_transit.clone(), max_transmits)
    }
}

/// Keeps track of the available bandwidth for sending data
pub(crate) struct DataRateCalculator {
    last_increase: Instant,
    bandwidth_bps: f64,
    available_bandwidth_bits: usize,
    max_available_bandwidth_bits: usize,
}

impl DataRateCalculator {
    fn new(bandwidth_bps: u64) -> Self {
        // We use 100ms as the maximum period in which you can "accumulate" bandwidth, unless the
        // link's bandwidth is so small that more time is necessary to reach the QUIC MTU
        let max_available_bandwidth_bits = cmp::max(
            (bandwidth_bps / 10) as usize,
            1200 * 8 + (UDP_OVERHEAD + IPV4_OVERHEAD) * 8,
        );

        Self {
            last_increase: Instant::now(),
            bandwidth_bps: bandwidth_bps as f64,
            available_bandwidth_bits: max_available_bandwidth_bits,
            max_available_bandwidth_bits,
        }
    }

    pub(crate) fn duration_until_enough_bandwidth(&self, size_bytes: usize) -> Duration {
        let missing_bits = size_bytes
            .saturating_mul(8)
            .saturating_sub(self.available_bandwidth_bits);
        let seconds_until_enough_bandwidth = missing_bits as f64 / self.bandwidth_bps;
        Duration::from_secs_f64(seconds_until_enough_bandwidth)
    }

    fn has_bandwidth_available(&mut self, now: Instant, payload_size_bytes: usize) -> bool {
        let payload_size_bits = payload_size_bytes.saturating_mul(8);
        if payload_size_bits > self.max_available_bandwidth_bits {
            println!(
                "WARN: packet will never be sent because its size exceeds the maximum available bandwidth"
            );
        }

        let seconds_since_last_increase = (now - self.last_increase).as_secs_f64();

        // println!("seconds since last increase: {seconds_since_last_increase:.6}");

        let available_bits_since_last_increase = (self.bandwidth_bps * seconds_since_last_increase)
            .ceil()
            .clamp(0.0, usize::MAX as f64)
            as usize;

        // println!("available since last increase: {available_bits_since_last_increase}");

        // Cap the available bandwidth (otherwise it will build up to infinity)
        self.available_bandwidth_bits = self
            .available_bandwidth_bits
            .saturating_add(available_bits_since_last_increase)
            .clamp(0, self.max_available_bandwidth_bits);

        self.last_increase = now;

        payload_size_bits <= self.available_bandwidth_bits
    }

    fn track_send(&mut self, payload_size_bytes: usize) {
        assert!(self.has_bandwidth_available(Instant::now(), payload_size_bytes));
        self.available_bandwidth_bits -= payload_size_bytes.saturating_mul(8);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[macros::async_test_priv]
    async fn test_drc_send_until_not_enough_bandwidth() {
        let mut drc = DataRateCalculator::new(10_000_000);

        // The max available bandwidth is tracked per 100ms, so it's 1/10th of the original one
        assert_eq!(drc.available_bandwidth_bits, 1_000_000);

        // Send in one go until not enough bandwidth available
        for _ in 0..104 {
            drc.track_send(1200);
        }
        assert_eq!(drc.available_bandwidth_bits, 1600);
        assert!(!drc.has_bandwidth_available(Instant::now(), 1200));
    }

    #[macros::async_test_priv]
    async fn test_drc_bandwidth_regen() {
        let mut drc = DataRateCalculator::new(10_000_000);

        // Send until not enough bandwidth available
        for _ in 0..104 {
            drc.track_send(1200);
        }
        assert_eq!(drc.available_bandwidth_bits, 1600);
        assert!(!drc.has_bandwidth_available(Instant::now(), 1200));

        // Bandwidth regen happens at the expected rate for "big" intervals
        async_rt::sleep(Duration::from_millis(10)).await;
        assert!(drc.has_bandwidth_available(Instant::now(), 1200));
        assert_eq!(drc.available_bandwidth_bits, 1600 + 100_000);
    }

    #[macros::async_test_priv]
    async fn test_drc_bandwidth_regen_sub_millisecond() {
        let mut drc = DataRateCalculator::new(10_000_000);
        drc.available_bandwidth_bits = 0;

        async_rt::sleep(Duration::from_millis(1)).await;
        drc.has_bandwidth_available(Instant::now(), 1200);
        assert_eq!(drc.available_bandwidth_bits, 10_000);

        // 1 ms = 1000 µs = 1000000 ns
        async_rt::sleep(Duration::from_micros(2001)).await;
        drc.has_bandwidth_available(Instant::now(), 1200);
        assert_eq!(drc.available_bandwidth_bits, 30_010);
    }
}
