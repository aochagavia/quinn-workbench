use crate::stats_tracker::NetworkStatsTracker;
use crate::{InTransitData, PrioritizedInTransitData};
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;

pub struct InboundQueue {
    queue: BinaryHeap<PrioritizedInTransitData>,
    bytes_in_transit: usize,
    link_delay: Duration,
    link_capacity: usize,
    highest_received_transmit_number: AtomicU64,
    stats_tracker: NetworkStatsTracker,
    start: Instant,
}

impl InboundQueue {
    pub(crate) fn new(
        link_delay: Duration,
        link_capacity: u64,
        stats_tracker: NetworkStatsTracker,
        start: Instant,
    ) -> Self {
        Self {
            queue: BinaryHeap::new(),
            bytes_in_transit: 0,
            link_delay,
            link_capacity: link_capacity as usize,
            highest_received_transmit_number: Default::default(),
            stats_tracker,
            start,
        }
    }

    pub(crate) fn has_enough_capacity(&self, data: &InTransitData, duplicate: bool) -> bool {
        let duplicate_multiplier = if duplicate { 2 } else { 1 };
        self.bytes_in_transit + data.transmit.contents.len() * duplicate_multiplier
            <= self.link_capacity
    }

    pub(crate) fn send(
        &mut self,
        data: InTransitData,
        metadata_index: usize,
        extra_delay: Duration,
    ) {
        assert!(self.has_enough_capacity(&data, false));
        self.bytes_in_transit += data.transmit.contents.len();
        self.queue.push(PrioritizedInTransitData {
            data,
            metadata_index,
            delay: self.link_delay + extra_delay,
        });
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(crate) fn receive(&mut self, max_transmits: usize) -> impl Iterator<Item = InTransitData> {
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

                // Keep track of out-of-order packets
                if data.data.number < highest_received {
                    let pcap_number = self.stats_tracker.track_out_of_order(data.metadata_index);
                    println!(
                        "{:.2}s WARN Received reordered packet (#{pcap_number}) after it was delayed for extra {:.2}s",
                        self.start.elapsed().as_secs_f64(),
                        (data.delay - self.link_delay).as_secs_f64(),
                    );
                }
                highest_received = highest_received.max(data.data.number);

                // Keep track of bytes in transit
                self.bytes_in_transit -= data.data.transmit.contents.len();

                received.push(data.data);
            } else {
                break;
            }
        }

        self.highest_received_transmit_number
            .store(highest_received, Ordering::Relaxed);

        received.into_iter()
    }

    pub(crate) fn time_of_next_receive(&self) -> Instant {
        self.queue.peek().unwrap().arrival_time()
    }
}