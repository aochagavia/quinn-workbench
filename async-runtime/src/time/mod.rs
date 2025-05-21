use crate::rt::Rt;
pub use crate::time::instant::Instant;
use crate::time::timer::Timer;
use futures::{FutureExt, select_biased};
use std::pin::pin;
use std::time::Duration;

mod instant;
pub mod timer;

#[must_use]
pub fn sleep(duration: Duration) -> Timer {
    Rt::active().sleep(duration)
}

#[must_use]
pub fn sleep_until(instant: Instant) -> Timer {
    Rt::active().sleep_until(instant)
}

pub async fn timeout<T>(duration: Duration, future: impl Future<Output = T>) -> Result<T, ()> {
    let timer = sleep(duration);
    let future = pin!(future);
    select_biased! {
        _ = timer.fuse() => { Err(()) },
        output = future.fuse() => { Ok(output) }
    }
}
