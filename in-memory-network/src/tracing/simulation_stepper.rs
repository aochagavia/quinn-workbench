use crate::tracing::simulation_step::{SimulationStep, SimulationStepKind};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct SimulationStepper {
    steps: Vec<SimulationStep>,
}

impl SimulationStepper {
    pub fn record(&mut self, step: SimulationStep) {
        self.steps.push(step);
    }

    pub fn steps(self) -> Vec<SimulationStep> {
        self.steps
    }

    pub fn get_packet_hops(&self, id: Uuid) -> Vec<(Duration, Arc<str>)> {
        let mut hops = Vec::new();
        for step in &self.steps {
            match &step.kind {
                SimulationStepKind::PacketInNode(s) if s.packet_id == id => {
                    hops.push((step.relative_time, s.node_id.clone()));
                }
                _ => {}
            }
        }

        hops
    }

    pub fn get_packet_path(&self, id: Uuid) -> Vec<Arc<str>> {
        self.get_packet_hops(id)
            .into_iter()
            .map(|(_, node_id)| node_id)
            .collect()
    }

    pub fn get_packet_arrived_at(&self, packet_id: Uuid, node_id: &str) -> Option<Duration> {
        self.steps
            .iter()
            .filter_map(|s| match &s.kind {
                SimulationStepKind::PacketInNode(kind)
                    if kind.packet_id == packet_id && kind.node_id.as_ref() == node_id =>
                {
                    Some(s.relative_time)
                }
                _ => None,
            })
            .next()
    }
}
