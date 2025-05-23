use crate::InTransitData;
use crate::async_rt::time::Instant;
use crate::network::event::NetworkEventPayload;
use crate::network::link::NetworkLink;
use crate::network::node::Node;
use crate::network::spec::NetworkSpec;
use crate::tracing::simulation_step::{
    GenericPacketEvent, PacketDropped, PacketHasExtraDelay, PacketInTransit, PacketLostInTransit,
    SimulationStep, SimulationStepKind,
};
use crate::tracing::simulation_stepper::SimulationStepper;
use crate::tracing::simulation_verifier::SimulationVerifier;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

pub struct SimulationStepTracer {
    simulation_start: Instant,
    recorded_steps: Mutex<SimulationStepper>,
    network_spec: NetworkSpec,
    already_warned_dropped_from_buffer: Mutex<HashSet<Arc<str>>>,
}

impl SimulationStepTracer {
    pub fn new(spec: NetworkSpec) -> Self {
        Self {
            simulation_start: Instant::now(),
            recorded_steps: Default::default(),
            network_spec: spec,
            already_warned_dropped_from_buffer: Mutex::default(),
        }
    }

    pub fn is_fresh(&self) -> bool {
        self.simulation_start.elapsed().is_zero()
    }

    pub fn stepper(&self) -> SimulationStepper {
        self.recorded_steps.lock().clone()
    }

    pub fn verifier(&self) -> anyhow::Result<SimulationVerifier> {
        let steps = self.recorded_steps.lock().clone().steps();
        SimulationVerifier::new(steps, &self.network_spec)
    }

    fn record(&self, kind: SimulationStepKind) {
        self.recorded_steps.lock().record(SimulationStep {
            relative_time: self.simulation_start.elapsed(),
            kind,
        });
    }

    pub fn track_link_event(&self, event: NetworkEventPayload) {
        self.record(SimulationStepKind::NetworkEvent(event));
    }

    pub fn track_packet_in_node(&self, node: &Node, packet: &InTransitData) {
        self.record(SimulationStepKind::PacketInNode(GenericPacketEvent {
            packet_id: packet.id,
            packet_number: packet.number,
            packet_size_bytes: packet.transmit.packet_size(),
            node_id: node.id().clone(),
        }));
    }

    pub fn track_packet_in_transit(&self, node: &Node, link: &NetworkLink, packet: &InTransitData) {
        self.record(SimulationStepKind::PacketInTransit(PacketInTransit {
            packet_id: packet.id,
            node_id: node.id().clone(),
            link_id: link.id.clone(),
        }));
    }

    pub fn track_dropped_randomly(&self, data: &InTransitData, current_node: &Node) {
        self.record(SimulationStepKind::PacketDropped(PacketDropped {
            packet_id: data.id,
            node_id: current_node.id().clone(),
            injected: true,
        }));

        println!(
            "{:.2}s WARN {} packet lost (#{})!",
            self.simulation_start.elapsed().as_secs_f64(),
            data.source_id,
            data.number,
        );
    }

    pub fn track_dropped_from_buffer(&self, data: &InTransitData, current_node: &Node) {
        self.record(SimulationStepKind::PacketDropped(PacketDropped {
            packet_id: data.id,
            node_id: current_node.id().clone(),
            injected: false,
        }));

        let first_dropped = self
            .already_warned_dropped_from_buffer
            .lock()
            .insert(current_node.id.clone());
        if first_dropped {
            println!(
                "{:.2}s WARN packet #{} dropped by node `{}` because its outbound buffer is full! (Note: further warnings for this link will be omitted to avoid cluttering the output)",
                self.simulation_start.elapsed().as_secs_f64(),
                data.number,
                current_node.id(),
            );
        }
    }

    pub fn track_lost_in_transit(&self, data: &InTransitData, link: &NetworkLink) {
        self.record(SimulationStepKind::PacketLostInTransit(
            PacketLostInTransit {
                packet_id: data.id,
                link_id: link.id.clone(),
            },
        ));
    }

    pub fn track_injected_failures(
        &self,
        data: &InTransitData,
        duplicate: bool,
        extra_delay: Duration,
        congestion_experienced: bool,
        current_node: &Node,
    ) {
        if !extra_delay.is_zero() {
            self.record(SimulationStepKind::PacketExtraDelay(PacketHasExtraDelay {
                packet_id: data.id,
                node_id: current_node.id().clone(),
                extra_delay,
            }));
        }

        if duplicate {
            self.record(SimulationStepKind::PacketDuplicated(GenericPacketEvent {
                packet_id: data.id,
                packet_number: data.number,
                packet_size_bytes: data.transmit.packet_size(),
                node_id: current_node.id().clone(),
            }));

            println!(
                "{:.2}s WARN {} sent duplicate packet (#{})!",
                current_node.id(),
                self.simulation_start.elapsed().as_secs_f64(),
                data.number,
            );
        }

        if congestion_experienced {
            self.record(SimulationStepKind::PacketCongestionEvent(
                GenericPacketEvent {
                    packet_id: data.id,
                    packet_number: data.number,
                    packet_size_bytes: data.transmit.packet_size(),
                    node_id: current_node.id().clone(),
                },
            ));

            println!(
                "{:.2}s WARN {} marked packet with CE ECN (#{})!",
                current_node.id(),
                self.simulation_start.elapsed().as_secs_f64(),
                data.number,
            );
        }
    }

    pub fn track_read_by_host(&self, host_id: Arc<str>, data: &InTransitData) {
        self.record(SimulationStepKind::PacketDeliveredToApplication(
            GenericPacketEvent {
                packet_id: data.id,
                packet_number: data.number,
                packet_size_bytes: data.transmit.packet_size(),
                node_id: host_id.clone(),
            },
        ));
    }
}
