use quinn_proto::RttEstimator;
use quinn_proto::congestion::{Controller, ControllerFactory};
use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

pub struct EcnCc(Box<dyn Controller>);

impl Controller for EcnCc {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.0.on_sent(now, bytes, last_packet_number)
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.0.on_ack(now, sent, bytes, app_limited, rtt)
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.0
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // We ignore congestion events triggered by packet loss, forwarding only those triggered by ECN
        if lost_bytes == 0 {
            self.0
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.0.on_mtu_update(new_mtu)
    }

    fn window(&self) -> u64 {
        self.0.window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(EcnCc(self.0.clone_box()))
    }

    fn initial_window(&self) -> u64 {
        self.0.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self as Box<dyn Any>
    }
}

pub struct EcnCcFactory(Arc<dyn ControllerFactory + Send + Sync + 'static>);

impl EcnCcFactory {
    pub fn new(factory: impl ControllerFactory + Send + Sync + 'static) -> Self {
        Self(Arc::new(factory))
    }
}

impl ControllerFactory for EcnCcFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        self.0.clone().build(now, current_mtu)
    }
}
