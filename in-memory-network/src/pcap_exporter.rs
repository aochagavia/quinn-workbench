use anyhow::Context;
use parking_lot::Mutex;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::blocks::section_header::SectionHeaderBlock;
use pcap_file::{DataLink, Endianness};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::udp::MutableUdpPacket;
use pnet_packet::{PacketSize, ipv4, udp};
use quinn::udp::Transmit;
use std::fs;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;

pub trait PcapExporterFactory: Send + Sync {
    fn create_pcap_exporter_for_node(&self, node_id: &str) -> anyhow::Result<PcapExporter>;
}

pub struct NoOpPcapExporterFactory;
impl PcapExporterFactory for NoOpPcapExporterFactory {
    fn create_pcap_exporter_for_node(&self, _: &str) -> anyhow::Result<PcapExporter> {
        Ok(PcapExporter::noop())
    }
}

pub struct FileBasedPcapExporterFactory;
impl PcapExporterFactory for FileBasedPcapExporterFactory {
    fn create_pcap_exporter_for_node(&self, node_id: &str) -> anyhow::Result<PcapExporter> {
        let file_name = format!("{node_id}.pcap");
        let pcap_file = fs::File::create(&file_name)
            .with_context(|| format!("failed to open {file_name} for writing"))?;
        Ok(PcapExporter::new(pcap_file))
    }
}

pub struct PcapExporter {
    capture_start: Instant,
    total_tracked_packets: AtomicU64,
    writer: Mutex<PcapNgWriter<BufWriter<Box<dyn Write + Send + Sync + 'static>>>>,
}

impl PcapExporter {
    pub fn new(writer: impl Write + Send + Sync + 'static) -> Self {
        let writer: Box<dyn Write + Send + Sync + 'static> = Box::new(writer);
        let mut writer = PcapNgWriter::with_section_header(
            BufWriter::new(writer),
            SectionHeaderBlock {
                endianness: Endianness::Big,
                major_version: 1,
                minor_version: 0,
                section_length: 0,
                options: vec![],
            },
        )
        .unwrap();

        writer
            .write_pcapng_block(InterfaceDescriptionBlock {
                linktype: DataLink::IPV4,
                snaplen: 65535,
                options: vec![],
            })
            .unwrap();

        Self {
            capture_start: Instant::now(),
            writer: Mutex::new(writer),
            total_tracked_packets: AtomicU64::new(0),
        }
    }

    pub fn noop() -> Self {
        Self::new(std::io::sink())
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        self.writer
            .lock()
            .get_mut()
            .flush()
            .context("failed to flush pcap writer")
    }

    pub fn track_transmit(&self, source_addr: SocketAddr, transmit: &Transmit) {
        let IpAddr::V4(source) = source_addr.ip() else {
            unreachable!()
        };

        let IpAddr::V4(destination) = transmit.destination.ip() else {
            unreachable!()
        };

        let mut buffer = vec![0; 2000];

        // Wrap the data in a UDP packet
        let mut udp_writer = MutableUdpPacket::new(&mut buffer).unwrap();
        let udp_packet_length = 8 + transmit.contents.len() as u16;
        udp_writer.set_source(source_addr.port());
        udp_writer.set_destination(transmit.destination.port());
        udp_writer.set_length(udp_packet_length);
        udp_writer.set_payload(transmit.contents);
        let checksum = udp::ipv4_checksum(&udp_writer.to_immutable(), &source, &destination);
        udp_writer.set_checksum(checksum);
        drop(udp_writer);
        let udp_packet = buffer[0..udp_packet_length as usize].to_vec();

        // Wrap the UDP packet in an IP packet
        let mut ip_writer = MutableIpv4Packet::new(&mut buffer).unwrap();
        let ip_packet_length = 20 + udp_packet_length;
        ip_writer.set_version(4);
        ip_writer.set_header_length(5); // We don't use options
        ip_writer.set_dscp(0); // Copied from a Wireshark dump
        ip_writer.set_identification(0); // We never fragment
        ip_writer.set_flags(0b010); // We never fragment
        ip_writer.set_fragment_offset(0); // We never fragment
        ip_writer.set_ttl(64);
        ip_writer.set_next_level_protocol(IpNextHeaderProtocol::new(17)); // 17 = UDP
        ip_writer.set_source(source);
        ip_writer.set_destination(destination);
        ip_writer.set_payload(&udp_packet);
        ip_writer.set_total_length(ip_packet_length);
        ip_writer.set_ecn(transmit.ecn.map(|codepoint| codepoint as u8).unwrap_or(0));
        let checksum = ipv4::checksum(&ip_writer.to_immutable());
        ip_writer.set_checksum(checksum);
        let ip_packet_length = ip_writer.packet_size();
        drop(ip_writer);

        let ip_packet = buffer[0..ip_packet_length].to_vec();

        self.total_tracked_packets.fetch_add(1, Ordering::Relaxed);

        let mut writer = self.writer.lock();
        writer
            .write_pcapng_block(EnhancedPacketBlock {
                interface_id: 0,
                timestamp: correct_timestamp(self.capture_start.elapsed()),
                original_len: ip_packet.len() as u32,
                data: ip_packet.into(),
                options: Vec::new(),
            })
            .unwrap();
    }
}

fn correct_timestamp(d: Duration) -> Duration {
    // Round to the nearest millisecond
    let millis = (d.as_secs_f64() * 1000.0).round();

    // Return the time, an order of magnitude smaller (there seems to be a bug in the library we are
    // using, which multiplies seconds by 1000)
    Duration::from_secs_f64(millis / 1_000_000.0)
}
