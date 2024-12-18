use crate::InTransitData;
use std::collections::BinaryHeap;
use std::task::Waker;
use std::time::Duration;
use tokio::time::Instant;

pub struct InboundQueue {
    queue: BinaryHeap<PrioritizedInTransitData>,
    notify_new_transmit: Option<Waker>,
}

impl InboundQueue {
    pub(crate) fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            notify_new_transmit: None,
        }
    }

    pub(crate) fn send(&mut self, data: InTransitData, delay: Duration) {
        self.queue.push(PrioritizedInTransitData {
            data,
            sent: Instant::now(),
            delay,
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
        let mut received = Vec::new();

        for _ in 0..max_transmits {
            if self
                .queue
                .peek()
                .is_some_and(|next| next.arrival_time() <= now)
            {
                let data = self.queue.pop().unwrap();
                received.push(data.data);
            } else {
                break;
            }
        }

        received
    }

    pub(crate) fn time_of_next_receive(&self) -> Option<Instant> {
        self.queue.peek().map(|x| x.arrival_time())
    }
}

// In transit data, sorted by arrival time
struct PrioritizedInTransitData {
    data: InTransitData,
    sent: Instant,
    delay: Duration,
}

impl PrioritizedInTransitData {
    fn arrival_time(&self) -> Instant {
        self.sent + self.delay
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
