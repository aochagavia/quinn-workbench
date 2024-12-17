use in_memory_network::network::event::{NetworkEvent, NetworkEventPayload, UpdateLinkStatus};
use in_memory_network::network::route::IpRange;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Deserialize, Clone)]
pub struct NetworkSpecJson {
    nodes: Vec<NetworkNodeJson>,
    links: Vec<NetworkLinkJson>,
}

#[derive(Deserialize, Clone)]
struct NetworkNodeJson {
    id: String,
    #[serde(rename = "type")]
    #[serde(default = "default_network_node_kind")]
    kind: NetworkNodeKindJson,
    interfaces: Vec<NetworkInterfaceJson>,
    routes: Vec<NetworkRouteJson>,
}

fn default_network_node_kind() -> NetworkNodeKindJson {
    NetworkNodeKindJson::Host
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
enum NetworkNodeKindJson {
    Router,
    Host,
}

#[derive(Deserialize, Clone)]
struct NetworkInterfaceJson {
    addresses: Vec<NetworkAddressJson>,
}

#[serde_as]
#[derive(Deserialize, Clone)]
struct NetworkAddressJson {
    #[serde_as(as = "DisplayFromStr")]
    address: IpAddr,
}

#[serde_as]
#[derive(Deserialize, Clone)]
struct NetworkRouteJson {
    #[serde_as(as = "DisplayFromStr")]
    destination: IpRange,
    next: IpAddr,
}

#[serde_as]
#[derive(Deserialize, Clone)]
struct NetworkLinkJson {
    id: String,
    #[serde_as(as = "DisplayFromStr")]
    source: IpAddr,
    #[serde_as(as = "DisplayFromStr")]
    target: IpAddr,
    /// The link's bandwidth, in bytes per second
    bandwidth_bps: u64,
    /// The delay of the link, in milliseconds
    delay_ms: u64,
    /// The extra delay of the link, which will be applied at random according to
    /// `extra_delay_ratio`
    #[serde(default)]
    extra_delay_ms: u64,
    /// The ratio of packets that will have an extra delay applied, to simulate packet reordering
    /// (the value must be between 0 and 1)
    #[serde(default)]
    extra_delay_ratio: f64,
    /// The ratio of packets that will be duplicated upon being sent (the value must be between 0
    /// and 1)
    #[serde(default)]
    packet_duplication_ratio: f64,
    /// The ratio of packets that will be lost (the value must be between 0 and 1)
    #[serde(default)]
    packet_loss_ratio: f64,
    /// The ratio of packets that will be marked with a CE ECN codepoint (the value must be between 0 and 1)
    #[serde(default)]
    congestion_event_ratio: f64,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
enum NetworkLinkStatusJson {
    Up,
    Down,
}

impl From<NetworkSpecJson> for in_memory_network::network::spec::NetworkSpec {
    fn from(json: NetworkSpecJson) -> Self {
        let nodes = json
            .nodes
            .into_iter()
            .map(|n| in_memory_network::network::spec::NetworkNodeSpec {
                id: n.id,
                kind: match n.kind {
                    NetworkNodeKindJson::Router => {
                        in_memory_network::network::spec::NodeKind::Router
                    }
                    NetworkNodeKindJson::Host => in_memory_network::network::spec::NodeKind::Host,
                },
                interfaces: n
                    .interfaces
                    .into_iter()
                    .map(|i| in_memory_network::network::spec::NetworkInterface {
                        addresses: i.addresses.into_iter().map(|a| a.address).collect(),
                    })
                    .collect(),
                routes: n
                    .routes
                    .into_iter()
                    .map(|r| in_memory_network::network::route::Route {
                        destination: r.destination,
                        next: r.next,
                    })
                    .collect(),
            })
            .collect();

        let links = json.links.into_iter().map(|l| l.into()).collect();

        Self { nodes, links }
    }
}

impl From<NetworkLinkJson> for in_memory_network::network::spec::NetworkLinkSpec {
    fn from(l: NetworkLinkJson) -> Self {
        in_memory_network::network::spec::NetworkLinkSpec {
            id: l.id.into_boxed_str().into(),
            source: l.source,
            target: l.target,
            delay: Duration::from_millis(l.delay_ms),
            bandwidth_bps: l.bandwidth_bps,
            congestion_event_ratio: l.congestion_event_ratio,
            packet_loss_ratio: l.packet_loss_ratio,
            packet_duplication_ratio: l.packet_duplication_ratio,
            extra_delay: Duration::from_millis(l.extra_delay_ms),
            extra_delay_ratio: l.extra_delay_ratio,
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct NetworkEventJson {
    relative_time_ms: u64,
    link: NetworkEventPayloadJson,
}

#[derive(Deserialize, Clone)]
struct NetworkEventPayloadJson {
    id: String,
    status: Option<NetworkLinkStatusJson>,
    bandwidth_bps: Option<u64>,
    delay_ms: Option<u64>,
    extra_delay_ms: Option<u64>,
    extra_delay_ratio: Option<f64>,
    packet_duplication_ratio: Option<f64>,
    packet_loss_ratio: Option<f64>,
    congestion_event_ratio: Option<f64>,
}

impl From<NetworkEventJson> for NetworkEvent {
    fn from(json: NetworkEventJson) -> Self {
        NetworkEvent {
            relative_time: Duration::from_millis(json.relative_time_ms),
            payload: NetworkEventPayload {
                id: json.link.id,
                status: json.link.status.map(|s| match s {
                    NetworkLinkStatusJson::Up => UpdateLinkStatus::Up,
                    NetworkLinkStatusJson::Down => UpdateLinkStatus::Down,
                }),
                bandwidth_bps: json.link.bandwidth_bps,
                delay: json.link.delay_ms.map(Duration::from_millis),
                extra_delay: json.link.extra_delay_ms.map(Duration::from_millis),
                extra_delay_ratio: json.link.extra_delay_ratio,
                packet_duplication_ratio: json.link.packet_duplication_ratio,
                packet_loss_ratio: json.link.packet_loss_ratio,
                congestion_event_ratio: json.link.congestion_event_ratio,
            },
        }
    }
}
