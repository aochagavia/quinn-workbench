use quinn_proto::{ConnectionId, ConnectionIdGenerator};
use std::time::Duration;

pub struct NoConnectionIdGenerator;

impl ConnectionIdGenerator for NoConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::new(&[])
    }

    fn cid_len(&self) -> usize {
        0
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}
