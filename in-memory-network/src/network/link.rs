use crate::network::event::UpdateLinkStatus;
use crate::network::inbound_queue::InboundQueue;
use crate::network::node::Node;
use crate::network::spec::NetworkLinkSpec;
use crate::tracing::tracer::SimulationStepTracer;
use crate::InTransitData;
use futures_util::future::Shared;
use futures_util::FutureExt;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, mem};
use tokio::time::Instant;

pub struct NetworkLink {
    pub id: Arc<str>,
    pub target: IpAddr,
    tracer: Arc<SimulationStepTracer>,
    queue: InboundQueue,
    rate_calculator: DataRateCalculator,
    packets_waiting_for_bandwidth: VecDeque<(InTransitData, tokio::sync::oneshot::Sender<()>)>,
    status: LinkStatus,
    delay: Duration,
    pub(crate) congestion_event_ratio: f64,
    pub(crate) packet_loss_ratio: f64,
    pub(crate) packet_duplication_ratio: f64,
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
    pub(crate) fn new(
        l: NetworkLinkSpec,
        tracer: Arc<SimulationStepTracer>,
        status: LinkStatus,
    ) -> Self {
        Self {
            id: l.id,
            status,
            tracer,
            target: l.target,
            queue: InboundQueue::new(),
            rate_calculator: DataRateCalculator::new(l.bandwidth_bps),
            packets_waiting_for_bandwidth: VecDeque::new(),
            delay: l.delay,
            congestion_event_ratio: l.congestion_event_ratio,
            packet_loss_ratio: l.packet_loss_ratio,
            packet_duplication_ratio: l.packet_duplication_ratio,
            extra_delay: l.extra_delay,
            extra_delay_ratio: l.extra_delay_ratio,
        }
    }

    pub fn is_up(&self) -> bool {
        !self.status.is_down()
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

                // Nothing else to do here, because:
                // 1. already sent packets will continue traveling to their destination
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
        // Sanity check
        assert!(self
            .rate_calculator
            .has_bandwidth_available(Instant::now(), data.transmit.contents.len()));
        assert!(matches!(self.status, LinkStatus::Up));

        // Record
        self.tracer.track_sent_in_pcap(&data, current_node);
        self.tracer
            .track_packet_in_transit(current_node, self, &data);

        // Send
        self.rate_calculator
            .track_send(data.transmit.contents.len());
        self.queue.send(data, self.delay + extra_delay);
    }

    pub(crate) fn send_when_bandwidth_available(
        this: Arc<Mutex<Self>>,
        node: Node,
        data: InTransitData,
        extra_delay: Duration,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let link = this.clone();
        let mut link = link.lock();
        link.packets_waiting_for_bandwidth.push_back((data, tx));

        // We only spawn a task when going from 0 to 1 packet, since the existing task will
        // handle any packets we add afterwards
        if link.packets_waiting_for_bandwidth.len() == 1 {
            tokio::spawn(async move {
                loop {
                    // Concurrency: shorten the lock on `this`
                    let duration_until_enough_bandwidth = {
                        let link = this.lock();
                        link.packets_waiting_for_bandwidth.front().map(|(data, _)| {
                            link.rate_calculator
                                .duration_until_enough_bandwidth(data.transmit.contents.len())
                        })
                    };

                    let Some(duration_until_enough_bandwidth) = duration_until_enough_bandwidth
                    else {
                        // No data waiting for bandwidth, we are done
                        return;
                    };

                    tokio::time::sleep(duration_until_enough_bandwidth).await;

                    // Concurrency: keep the one-liner to shorten the lock on `this`
                    let notifier_for_link_up = this.lock().status.notifier_for_link_up();
                    if let Some(notifier_for_link_up) = notifier_for_link_up {
                        // The link is currently down, so we need to wait for it to be back up
                        notifier_for_link_up.await.ok();
                    }

                    // Concurrency: only lock after all awaits
                    let mut link = this.lock();
                    let (data, sent_tx) = link.packets_waiting_for_bandwidth.pop_front().unwrap();

                    // Send
                    link.send(&node, data, extra_delay);

                    // Notify that the data has been sent
                    sent_tx.send(()).ok();
                }
            });
        }

        rx
    }

    pub(crate) fn has_bandwidth_available(&mut self, data: &InTransitData) -> bool {
        let at_least_one_packet_waiting_for_bandwidth =
            !self.packets_waiting_for_bandwidth.is_empty();
        if at_least_one_packet_waiting_for_bandwidth || self.status.is_down() {
            return false;
        }

        self.rate_calculator
            .has_bandwidth_available(Instant::now(), data.transmit.contents.len())
    }

    pub(crate) fn receive(&mut self, max_transmits: usize) -> Vec<InTransitData> {
        self.queue.receive(max_transmits)
    }

    pub(crate) fn time_of_next_receive(&self) -> Option<Instant> {
        self.queue.time_of_next_receive()
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
        let max_available_bandwidth_bits = cmp::max((bandwidth_bps / 10) as usize, 1200 * 8);

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
            println!("WARN: packet will never be sent because its size exceeds the maximum available bandwidth");
        }

        let seconds_since_last_increase = (now - self.last_increase).as_secs_f64();
        let available_bits_since_last_increase = (self.bandwidth_bps * seconds_since_last_increase)
            .ceil()
            .clamp(0.0, usize::MAX as f64)
            as usize;

        // Cap the available bandwidth (otherwise it will build up in periods of inactivity and
        // tend to infinity)
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
