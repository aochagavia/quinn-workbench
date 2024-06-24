use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

/// No congestion control
#[derive(Clone)]
pub struct NoCC {
    config: Arc<NoCCConfig>,
    /// Maximum number of bytes in flight that may be sent.
    window: u64,
}

impl NoCC {
    pub fn new(config: Arc<NoCCConfig>, _now: Instant, _current_mtu: u16) -> Self {
        Self {
            window: config.initial_window,
            config,
        }
    }
}

impl Controller for NoCC {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
    ) {
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `NoCC` congestion controller
#[derive(Debug, Clone)]
pub struct NoCCConfig {
    pub initial_window: u64,
}

impl Default for NoCCConfig {
    fn default() -> Self {
        Self {
            // set to the largest possible value (aka almost infinite)
            initial_window: u64::MAX,
        }
    }
}

impl ControllerFactory for NoCCConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NoCC::new(self, now, current_mtu))
    }
}
