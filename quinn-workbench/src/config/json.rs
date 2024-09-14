use serde::Deserialize;

#[derive(Deserialize)]
pub struct JsonConfig {
    /// Optionally, the configuration for the Quinn endpoints
    pub quinn: Option<QuinnJsonConfig>,
    /// The configuration of the simulated network
    pub network: NetworkJsonConfig,
}

#[derive(Deserialize)]
pub struct QuinnJsonConfig {
    /// The initial RTT of the QUIC connection, in milliseconds (used before an RTT sample is
    /// available).
    ///
    /// For delay-tolerant networking, it is recommended to set this to a value slightly higher than
    /// the real RTT. If the value is too low, there will be needless retransmissions of packets
    /// until the endpoint is able to infer the real RTT.
    pub initial_rtt_ms: u64,
    /// The maximum idle timeout of the QUIC connection, in milliseconds.
    ///
    /// When expecting a continuous exchange of information, a small idle timeout helps to detect
    /// connection loss. In delay-tolerant networking, it is useful to use a very high timeout, to
    /// ensure the connection never gets lost due to unexpected delays.
    pub maximum_idle_timeout_ms: u64,
    /// Maximum reordering in packet numbers before considering a packet lost. Should not be less
    /// than 3, per RFC5681.
    pub packet_threshold: u32,
    /// Whether MTU discovery should be enabled
    pub mtu_discovery: bool,
    /// Whether the send and receive windows should be maximized, allowing an unbounded number of
    /// unacknowledged in-flight packets
    pub maximize_send_and_receive_windows: bool,
    /// The number of ACK-eliciting packets an endpoint may receive without immediately sending an
    /// ACK.
    ///
    /// Setting this threshold to a high value is particularly useful when we expect to receive long
    /// streams of information from the server, without sending anything back from the client.
    pub ack_eliciting_threshold: u32,
    /// The maximum amount of time that an endpoint waits before sending an ACK when the
    /// ACK-eliciting threshold hasn't been reached.
    ///
    /// Setting this to a high value is particularly useful in combination with a high ACK-eliciting
    /// threshold.
    pub max_ack_delay_ms: u64,
    /// If provided, disables congestion control and uses a fixed congestion window instead
    /// (specified in bytes).
    pub fixed_congestion_window: Option<u64>,
}

#[derive(Clone, Deserialize)]
pub struct NetworkJsonConfig {
    /// The one-way delay of the network, in milliseconds
    pub delay_ms: u64,
    /// The one-way extra delay of the network, which will be applied at random according to
    /// `extra_delay_ratio`
    pub extra_delay_ms: u64,
    /// The ratio of packets that will have an extra delay applied, to simulate packet reordering
    /// (the value must be between 0 and 1)
    pub extra_delay_ratio: f64,
    /// The ratio of packets that will be duplicated upon being sent (the value must be between 0
    /// and 1)
    pub packet_duplication_ratio: f64,
    /// The ratio of packets that will be lost (the value must be between 0 and 1)
    pub packet_loss_ratio: f64,
    /// The ratio of packets that will be marked with a CE ECN codepoint (the value must be between 0 and 1)
    pub congestion_event_ratio: f64,
    /// The one-way bandwidth of the network, in bytes
    pub bandwidth: u64,
}
