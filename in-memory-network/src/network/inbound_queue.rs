use crate::stats_tracker::NetworkStatsTracker;
use crate::InTransitData;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Waker;
use std::time::Duration;
use tokio::time::Instant;

/// Keeps track of the available bandwidth for sending data
struct DataRateCalculator {
    last_increase: Instant,
    bandwidth_bps: f64,
    available_bandwidth_bits: usize,
    maximum_available_bandwidth_bits: usize,
}

impl DataRateCalculator {
    fn new(bandwidth_bps: u64) -> Self {
        // We use 2 seconds as the maximum period in which you can "accumulate" bandwidth. It is not
        // the most realistic (it should probably be shorter, like 100ms), but it enables us to
        // treat packets as the single unit of transportation (instead of implementing logic to
        // partially transmit packets, which sounds complex).
        let maximum_available_bandwidth_bits = bandwidth_bps.saturating_mul(2) as usize;

        Self {
            last_increase: Instant::now(),
            bandwidth_bps: bandwidth_bps as f64,
            available_bandwidth_bits: maximum_available_bandwidth_bits,
            maximum_available_bandwidth_bits,
        }
    }

    fn has_bandwidth_available(&mut self, now: Instant, payload_size_bytes: usize) -> bool {
        if payload_size_bytes.saturating_mul(8) > self.maximum_available_bandwidth_bits {
            println!("WARN: packet will never be sent because its size exceeds the maximum available bandwidth");
        }

        let seconds_since_last_increase = (now - self.last_increase).as_secs_f64();
        let available_bits_since_last_increase = (self.bandwidth_bps * seconds_since_last_increase)
            .round()
            .clamp(0.0, usize::MAX as f64)
            as usize;

        // Cap the available bandwidth (otherwise it will build up in periods of inactivity and
        // tend to infinity)
        self.available_bandwidth_bits = self
            .available_bandwidth_bits
            .saturating_add(available_bits_since_last_increase)
            .clamp(0, self.maximum_available_bandwidth_bits);

        payload_size_bytes.saturating_mul(8) < self.available_bandwidth_bits
    }

    fn track_send(&mut self, payload_size_bytes: usize) {
        assert!(self.has_bandwidth_available(Instant::now(), payload_size_bytes));
        self.available_bandwidth_bits -= payload_size_bytes.saturating_mul(8);
    }
}

pub struct InboundQueue {
    queue: BinaryHeap<PrioritizedInTransitData>,
    link_delay: Duration,
    rate_calculator: DataRateCalculator,
    highest_received_transmit_number: AtomicU64,
    stats_tracker: NetworkStatsTracker,
    start: Instant,
    notify_new_transmit: Option<Waker>,
}

impl InboundQueue {
    pub(crate) fn new(
        link_delay: Duration,
        link_bandwidth_bps: u64,
        stats_tracker: NetworkStatsTracker,
        start: Instant,
    ) -> Self {
        Self {
            queue: BinaryHeap::new(),
            link_delay,
            rate_calculator: DataRateCalculator::new(link_bandwidth_bps),
            highest_received_transmit_number: Default::default(),
            stats_tracker,
            start,
            notify_new_transmit: None,
        }
    }

    pub(crate) fn has_bandwidth_available(
        &mut self,
        data: &InTransitData,
        duplicate: bool,
    ) -> bool {
        let duplicate_multiplier = if duplicate { 2 } else { 1 };
        let total_size = data.transmit.contents.len() * duplicate_multiplier;
        self.rate_calculator
            .has_bandwidth_available(Instant::now(), total_size)
    }

    pub(crate) fn send(
        &mut self,
        data: InTransitData,
        metadata_index: Option<usize>,
        extra_delay: Duration,
    ) {
        self.rate_calculator
            .track_send(data.transmit.contents.len());
        self.queue.push(PrioritizedInTransitData {
            data,
            metadata_index,
            delay: self.link_delay + extra_delay,
        });

        if let Some(waker) = self.notify_new_transmit.take() {
            waker.wake();
        }
    }

    pub(crate) fn register_waker(&mut self, waker: Waker) {
        if let Some(next_read) = self.time_of_next_receive() {
            // Wake up next time we can read
            tokio::task::spawn(async move {
                tokio::time::sleep_until(next_read).await;
                waker.wake();
            });
        } else {
            // The queue is empty. Store the waker so we can be notified of new transmits.
            if self.notify_new_transmit.is_none() {
                self.notify_new_transmit = Some(waker)
            }
        }
    }

    pub(crate) fn receive(&mut self, max_transmits: usize) -> Vec<InTransitData> {
        let now = Instant::now();
        let mut highest_received = self
            .highest_received_transmit_number
            .load(Ordering::Relaxed);
        let mut received = Vec::new();

        for _ in 0..max_transmits {
            if self
                .queue
                .peek()
                .is_some_and(|next| next.arrival_time() <= now)
            {
                let data = self.queue.pop().unwrap();

                // Keep track of out-of-order packets if there's metadata about the packet
                if let Some(metadata_index) = data.metadata_index {
                    if data.data.number < highest_received {
                        let pcap_number = self.stats_tracker.track_out_of_order(metadata_index);
                        println!(
                            "{:.2}s WARN Received reordered packet (#{pcap_number}) after it was delayed for extra {:.2}s",
                            self.start.elapsed().as_secs_f64(),
                            (data.delay - self.link_delay).as_secs_f64(),
                        );
                    }
                }

                highest_received = highest_received.max(data.data.number);
                received.push(data.data);
            } else {
                break;
            }
        }

        self.highest_received_transmit_number
            .store(highest_received, Ordering::Relaxed);

        received
    }

    pub(crate) fn time_of_next_receive(&self) -> Option<Instant> {
        self.queue.peek().map(|x| x.arrival_time())
    }
}

// In transit data, sorted by arrival time
struct PrioritizedInTransitData {
    data: InTransitData,
    metadata_index: Option<usize>,
    delay: Duration,
}

impl PrioritizedInTransitData {
    fn arrival_time(&self) -> Instant {
        self.data.last_sent + self.delay
    }
}

impl Eq for PrioritizedInTransitData {}

impl PartialEq<Self> for PrioritizedInTransitData {
    fn eq(&self, other: &Self) -> bool {
        self.arrival_time() == other.arrival_time() && self.data.number == other.data.number
    }
}

impl PartialOrd<Self> for PrioritizedInTransitData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedInTransitData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Note: the order is reversed, so the "max" in transit data will be the next one to be sent
        other
            .arrival_time()
            .cmp(&self.arrival_time())
            .then(other.data.number.cmp(&self.data.number))
    }
}
