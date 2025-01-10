use crate::network::link::LinkStatus;
use std::collections::HashMap;
use std::time::Duration;

pub struct NetworkEvents {
    pub(crate) sorted_events: Vec<NetworkEvent>,
    pub(crate) initial_link_statuses: HashMap<String, LinkStatus>,
}

impl NetworkEvents {
    pub fn new(mut events: Vec<NetworkEvent>) -> Self {
        events.sort_by_key(|e| e.relative_time);
        let initial_link_statuses = get_initial_status_for_links_with_events(&events);
        Self {
            sorted_events: events,
            initial_link_statuses,
        }
    }
}

pub struct NetworkEvent {
    pub relative_time: Duration,
    pub payload: NetworkEventPayload,
}

impl NetworkEvent {
    pub fn updated_status(&self) -> Option<UpdateLinkStatus> {
        self.payload.status
    }
}

pub struct NetworkEventPayload {
    pub link_id: String,
    pub status: Option<UpdateLinkStatus>,
    pub bandwidth_bps: Option<u64>,
    pub delay: Option<Duration>,
    pub extra_delay: Option<Duration>,
    pub extra_delay_ratio: Option<f64>,
    pub packet_duplication_ratio: Option<f64>,
    pub packet_loss_ratio: Option<f64>,
    pub congestion_event_ratio: Option<f64>,
}

#[derive(Debug, Copy, Clone)]
pub enum UpdateLinkStatus {
    Up,
    Down,
}

fn get_initial_status_for_links_with_events(
    sorted_events: &[NetworkEvent],
) -> HashMap<String, LinkStatus> {
    let mut initial_link_statuses = HashMap::new();
    for event in sorted_events {
        if let Some(updated_status) = event.updated_status() {
            if initial_link_statuses.contains_key(&event.payload.link_id) {
                // We are only interested in events for links we haven't seen yet
                continue;
            };

            let initial_status = match updated_status {
                UpdateLinkStatus::Up => LinkStatus::new_down(),
                UpdateLinkStatus::Down => LinkStatus::Up,
            };

            initial_link_statuses.insert(event.payload.link_id.clone(), initial_status);
        }
    }

    initial_link_statuses
}
