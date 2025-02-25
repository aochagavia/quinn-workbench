use crate::network::spec::NetworkLinkSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct NetworkEvents {
    pub(crate) sorted_events: Vec<NetworkEvent>,
    pub(crate) initial_events: Vec<NetworkEventPayload>,
}

impl NetworkEvents {
    pub fn new(mut events: Vec<NetworkEvent>, links: &[NetworkLinkSpec]) -> Self {
        events.sort_by_key(|e| e.relative_time);
        let initial_link_statuses = get_initial_status_for_links_with_events(&events, links);
        Self {
            sorted_events: events,
            initial_events: initial_link_statuses,
        }
    }
}

#[derive(Clone)]
pub struct NetworkEvent {
    pub relative_time: Duration,
    pub payload: NetworkEventPayload,
}

impl NetworkEvent {
    pub fn updated_status(&self) -> Option<UpdateLinkStatus> {
        self.payload.status
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkEventPayload {
    #[serde(with = "crate::util::serde_arc_str")]
    pub link_id: Arc<str>,
    pub status: Option<UpdateLinkStatus>,
    pub bandwidth_bps: Option<u64>,
    pub delay: Option<Duration>,
    pub extra_delay: Option<Duration>,
    pub extra_delay_ratio: Option<f64>,
    pub packet_duplication_ratio: Option<f64>,
    pub packet_loss_ratio: Option<f64>,
    pub congestion_event_ratio: Option<f64>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdateLinkStatus {
    Up,
    Down,
}

fn get_initial_status_for_links_with_events(
    sorted_events: &[NetworkEvent],
    links: &[NetworkLinkSpec],
) -> Vec<NetworkEventPayload> {
    let mut seen_links = HashSet::new();
    let mut initial_events = Vec::new();
    for event in sorted_events {
        if let Some(updated_status) = event.updated_status() {
            let newly_inserted = seen_links.insert(event.payload.link_id.clone());
            if !newly_inserted {
                // We are only interested in events for links we haven't seen yet
                continue;
            }

            let initial_status = match updated_status {
                UpdateLinkStatus::Up => UpdateLinkStatus::Down,
                UpdateLinkStatus::Down => UpdateLinkStatus::Up,
            };

            initial_events.push(NetworkEventPayload {
                link_id: event.payload.link_id.clone(),
                status: Some(initial_status),
                bandwidth_bps: None,
                delay: None,
                extra_delay: None,
                extra_delay_ratio: None,
                packet_duplication_ratio: None,
                packet_loss_ratio: None,
                congestion_event_ratio: None,
            });
        }
    }

    // Links that have no events at all are always up
    for link in links {
        if !seen_links.contains(&link.id) {
            initial_events.push(NetworkEventPayload {
                link_id: link.id.clone(),
                status: Some(UpdateLinkStatus::Up),
                bandwidth_bps: None,
                delay: None,
                extra_delay: None,
                extra_delay_ratio: None,
                packet_duplication_ratio: None,
                packet_loss_ratio: None,
                congestion_event_ratio: None,
            });
        }
    }

    initial_events
}
