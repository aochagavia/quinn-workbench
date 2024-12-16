use parking_lot::Mutex;

pub struct OutboundBuffer {
    available_capacity_bytes: Mutex<usize>,
}

impl OutboundBuffer {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            available_capacity_bytes: Mutex::new(capacity_bytes),
        }
    }

    pub fn reserve(&self, data_size: usize) -> bool {
        let mut available_capacity_bytes = self.available_capacity_bytes.lock();
        if *available_capacity_bytes < data_size {
            // No space available
            false
        } else {
            // Space available
            *available_capacity_bytes -= data_size;
            true
        }
    }

    pub fn release(&self, data_size: usize) {
        *self.available_capacity_bytes.lock() += data_size;
    }
}
