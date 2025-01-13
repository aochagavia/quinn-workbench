use crate::network::link::NetworkLink;
use crate::network::node::Node;
use crate::network::spec::{NetworkNodeSpec, NetworkSpec};
use crate::pcap_exporter::PcapExporter;
use crate::tracing::simulation_step::{
    GenericPacketEvent, PacketDropped, PacketHasExtraDelay, PacketInTransit, SimulationStep,
    SimulationStepKind,
};
use crate::tracing::simulation_stepper::SimulationStepper;
use crate::tracing::stats::NetworkStats;
use crate::InTransitData;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

pub struct SimulationStepTracer {
    simulation_start: Instant,
    pcap_exporter: Arc<PcapExporter>,
    recorded_steps: Mutex<Vec<SimulationStep>>,
    nodes: Vec<NetworkNodeSpec>,
    already_warned_dropped_from_buffer: Mutex<HashSet<Arc<str>>>,
}

impl SimulationStepTracer {
    pub fn new(pcap_exporter: Arc<PcapExporter>, spec: NetworkSpec) -> Self {
        Self {
            simulation_start: Instant::now(),
            pcap_exporter,
            recorded_steps: Default::default(),
            nodes: spec.nodes,
            already_warned_dropped_from_buffer: Mutex::default(),
        }
    }

    pub fn steps(&self) -> Vec<SimulationStep> {
        self.recorded_steps.lock().clone()
    }

    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            by_node: self.stepper().simulate(),
        }
    }

    pub fn stepper(&self) -> SimulationStepper {
        let steps = self.recorded_steps.lock().clone();
        SimulationStepper::new(steps, &self.nodes)
    }

    fn record(&self, kind: SimulationStepKind) {
        self.recorded_steps.lock().push(SimulationStep {
            relative_time: self.simulation_start.elapsed(),
            kind,
        });
    }

    pub fn track_packet_in_node(&self, node: &Node, packet: &InTransitData) {
        self.record(SimulationStepKind::PacketInNode(GenericPacketEvent {
            packet_id: packet.id,
            packet_number: packet.number,
            packet_size_bytes: packet.transmit.contents.len(),
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
            data.source.id,
            data.number,
        );
    }

    pub fn track_dropped_from_buffer(
        &self,
        data: &InTransitData,
        current_node: &Node,
        link: &NetworkLink,
    ) {
        self.record(SimulationStepKind::PacketDropped(PacketDropped {
            packet_id: data.id,
            node_id: current_node.id().clone(),
            injected: false,
        }));

        let first_dropped = self
            .already_warned_dropped_from_buffer
            .lock()
            .insert(link.id.clone());
        if first_dropped {
            println!(
                "{:.2}s WARN packet #{} dropped by node `{}` because the link `{}` was saturated and node buffer was full! (Note: further warnings for this link will be omitted to avoid cluttering the output)",
                self.simulation_start.elapsed().as_secs_f64(),
                data.number,
                current_node.id(),
                link.id,
            );
        }
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
                packet_size_bytes: data.transmit.contents.len(),
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
                    packet_size_bytes: data.transmit.contents.len(),
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

    pub fn track_read_by_host(&self, host_id: Arc<str>, data: &InTransitData, out_of_order: bool) {
        if out_of_order {
            println!(
                "{:.2}s WARN Received reordered packet (#{})",
                self.simulation_start.elapsed().as_secs_f64(),
                data.number
            );
        }

        self.record(SimulationStepKind::PacketDeliveredToApplication(
            GenericPacketEvent {
                packet_id: data.id,
                packet_number: data.number,
                packet_size_bytes: data.transmit.contents.len(),
                node_id: host_id.clone(),
            },
        ));
    }

    pub fn track_sent_in_pcap(&self, data: &InTransitData, current_node: &Node) {
        // The pcap exporter should only track packets as they get sent from a host
        if let Node::Host(source) = current_node {
            self.pcap_exporter
                .track_packet(data, &source.addr, data.transmit.ecn);
        };
    }
}
